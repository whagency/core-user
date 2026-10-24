package controllers

import (
	"context"
	"errors"
	"fmt"

	"user-service/config"
	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	recaptchaV3 "user-service/services/recaptcha/v3"

	"github.com/whagency/core-common/cache"
	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

// PasswordRecoveryCtrl orchestrates the forgot-password flow backed by OTP challenges.
type PasswordRecoveryCtrl struct {
	users              domain.UserRepository
	contacts           domain.ContactRepository
	credentials        domain.CredentialRepository
	passwordChangeLogs domain.PasswordChangeLogRepository
	twoFaTokens        domain.TwoFactorTokenRepository
	otpCtrl            domain.OTPController
	passwordHelper     domain.PasswordHelper
	sessionCtrl        domain.SessionController
	transactionManager domain.TransactionManager
	recaptchaV3        *recaptchaV3.Service
}

// NewPasswordRecoveryController builds a new PasswordRecoveryCtrl instance.
func NewPasswordRecoveryController(
	users domain.UserRepository,
	contacts domain.ContactRepository,
	credentials domain.CredentialRepository,
	passwordChangeLogs domain.PasswordChangeLogRepository,
	twoFaTokens domain.TwoFactorTokenRepository,
	otpCtrl domain.OTPController,
	passwordHelper domain.PasswordHelper,
	sessionCtrl domain.SessionController,
	tm domain.TransactionManager,
	recaptchaV3 *recaptchaV3.Service,
) (*PasswordRecoveryCtrl, error) {
	return &PasswordRecoveryCtrl{
		users:              users,
		contacts:           contacts,
		credentials:        credentials,
		passwordChangeLogs: passwordChangeLogs,
		twoFaTokens:        twoFaTokens,
		otpCtrl:            otpCtrl,
		passwordHelper:     passwordHelper,
		sessionCtrl:        sessionCtrl,
		transactionManager: tm,
		recaptchaV3:        recaptchaV3,
	}, nil
}

// Request issues a password recovery OTP and schedules the delivery of the challenge token.
func (c PasswordRecoveryCtrl) Request(ctx context.Context, in domain.PasswordResetRequestParams) (domain.PasswordResetRequestResult, error) {
	logger.LogCtx(ctx).Debugf("[PasswordRecoveryCtrl:Request][hasIdentifier:%t]", in.Identifier != "")

	// Validate reCAPTCHA v3 token
	if config.Commons().IsProduction() && !c.recaptchaV3.IsTokenValid(ctx, in.Recaptcha) {
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			svcErrors.RecaptchaValidationError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request][err: recaptcha token is invalid]")),
		)
	}

	primaryContact, err := c.contacts.FindPrimaryByValue(ctx, domain.NormalizeContactValue(in.Identifier))
	if err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			return domain.PasswordResetRequestResult{}, svcErrors.New(
				svcErrors.AccountInvalidCredentialsError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", err)),
			)
		}
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", err)),
		)
	}
	if !primaryContact.IsVerified() {
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			svcErrors.AccountContactUnverifiedError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request][err: contact unverified]")),
		)
	}

	user, errFindUser := c.users.FindByID(ctx, primaryContact.UserID)
	if errFindUser != nil {
		if errors.Is(errFindUser, domain.ErrRecordNotFound) {
			return domain.PasswordResetRequestResult{}, svcErrors.New(
				svcErrors.AccountInvalidCredentialsError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", errFindUser)),
			)
		}
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", errFindUser)),
		)
	}
	if errValidateUserStatus := user.ValidateStatus(); errValidateUserStatus != nil {
		if errValidateUserStatus.Cause != nil {
			errValidateUserStatus.SetCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", errValidateUserStatus.Cause))
		}
		return domain.PasswordResetRequestResult{}, errValidateUserStatus
	}

	// TODO: decide if we want to limit to one active token at a time
	/*hasActiveToken, errActiveToken := c.twoFaTokens.HasActiveForContact(ctx, primaryContact.ID, domain.TwoFactorTokenTypePasswordReset)
	if errActiveToken != nil {
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", errActiveToken)),
		)
	}
	if hasActiveToken {
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			domain.RecordAlreadyExistsError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request][err: pending challenge exists]")),
		)
	}*/

	otpToken, errGenerateOtp := c.otpCtrl.Generate()
	if errGenerateOtp != nil {
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", errGenerateOtp)),
		)
	}

	passwordResetTwoFactorToken := domain.NewPasswordResetToken(
		user.ID,
		primaryContact.ID,
		domain.TwoFactorMethodFromContactType(primaryContact.Type),
		otpToken.Hash,
		otpToken.Salt,
		otpToken.ExpiresAt,
	)
	if err = c.twoFaTokens.Create(ctx, &passwordResetTwoFactorToken); err != nil {
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", err)),
		)
	}

	if err = c.otpCtrl.Send(ctx, domain.OTPMessage{
		Purpose:      passwordResetTwoFactorToken.Type.GetNotificationPurpose(),
		ContactType:  primaryContact.Type.String(),
		ContactValue: primaryContact.Value,
		Code:         otpToken.Code,
	}); err != nil {
		// Password reset can be requested again freely, so failing here is safe and
		// honest: the alternative is telling the user a code is on its way when it
		// is not.
		return domain.PasswordResetRequestResult{}, svcErrors.New(
			appErrors.ExternalServiceError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Request]%w", err)),
		)
	}

	return domain.PasswordResetRequestResult{ContactMethod: primaryContact, TokenUUID: passwordResetTwoFactorToken.UUID, ExpiresAt: otpToken.ExpiresAt}, nil
}

// Confirm validates the OTP challenge and rotates the user's password.
func (c PasswordRecoveryCtrl) Confirm(ctx context.Context, in domain.PasswordResetConfirmParams) error {
	logger.LogCtx(ctx).Debugf(
		"[PasswordRecoveryCtrl:Confirm][hasTokenUUID:%t][hasDeviceFingerprint:%t][hasIP:%t]",
		in.TokenUUID != "",
		in.DeviceFingerprint != "",
		in.IPAddress != "",
	)

	var err error
	ctx = c.transactionManager.Begin(ctx)
	// The session revocation below writes revocation marks the database cannot
	// roll back; the clean map takes them out again if this transaction fails.
	ctx = cache.NewCleanMap(ctx)

	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)

			cache.CleanKeys(ctx)

			if rbErr := c.transactionManager.Rollback(ctx); rbErr != nil {
				logger.LogCtx(ctx).Errorf("[Rollback]%s", rbErr)
			}
		}
	}()

	passwordResetTwoFactorToken, errFindTokenForUpdate := c.twoFaTokens.WithTxFromContext(ctx).FindByUUIDAndTypeForUpdate(ctx, in.TokenUUID, domain.TwoFactorTokenTypePasswordReset)
	if errFindTokenForUpdate != nil {
		switch {
		case errors.Is(errFindTokenForUpdate, domain.ErrRecordNotFound):
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", errFindTokenForUpdate)),
			)
			return err
		case errors.Is(errFindTokenForUpdate, domain.ErrConcurrencyConflict):
			err = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", errFindTokenForUpdate)),
			)
			return err
		default:
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", errFindTokenForUpdate)),
			)
			return err
		}
	}

	if passwordResetTwoFactorToken.IsConsumed() {
		err = svcErrors.New(
			svcErrors.CodeConsumedError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm][err: challenge consumed]")),
		)
		return err
	}

	if passwordResetTwoFactorToken.IsExpired() {
		err = svcErrors.New(
			svcErrors.CodeExpiredError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm][err: challenge expired]")),
		)
		return err
	}

	remainingAttempts := passwordResetTwoFactorToken.AttemptsLeft()
	if remainingAttempts == 0 {
		err = svcErrors.New(
			svcErrors.CodeAttemptsExceededError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm][err: attempts exceeded]")),
		)
		return err
	}

	if !c.otpCtrl.Verify(in.Code, passwordResetTwoFactorToken.CodeSalt, passwordResetTwoFactorToken.CodeHash) {
		if incErr := c.twoFaTokens.WithTxFromContext(ctx).IncrementAttempts(ctx, passwordResetTwoFactorToken.UUID); incErr != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", incErr)),
			)
			return err
		}

		if err = c.transactionManager.Commit(ctx); err != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm][Commit]%w", err)),
			)
			return err
		}

		return svcErrors.New(
			svcErrors.CodeInvalidError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm][err: invalid code]")),
		)
	}

	if err = c.twoFaTokens.WithTxFromContext(ctx).Consume(ctx, passwordResetTwoFactorToken.UUID, true /*incAttempt*/); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", err)),
		)
		return err
	}

	credential, credErr := c.credentials.WithTxFromContext(ctx).FindByUserIDForUpdate(ctx, passwordResetTwoFactorToken.UserID)
	if credErr != nil {
		switch {
		case errors.Is(credErr, domain.ErrRecordNotFound):
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", credErr)),
			)
			return err
		case errors.Is(credErr, domain.ErrConcurrencyConflict):
			err = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", credErr)),
			)
			return err
		default:
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", credErr)),
			)
			return err
		}
	}

	reused, verifyErr := c.passwordHelper.Verify(in.NewPassword, credential.PasswordHash)
	if verifyErr != nil {
		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", verifyErr)),
		)
		return err
	}
	if reused {
		err = svcErrors.New(
			svcErrors.PasswordChangeReuseNotAllowedError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm][err: password reuse detected]")),
		)
		return err
	}

	// Unlike Register and ChangePassword, this hash stays inside the transaction.
	//
	// It could be moved out -- it depends on nothing the transaction reads -- but
	// the ordering here is doing security work: the OTP is checked first, so a
	// wrong code costs an HMAC comparison and nothing else. Hashing earlier would
	// spend ~45ms of bcrypt on every invalid attempt, handing an attacker a CPU
	// amplifier in exchange for shortening a lock that only ever contends with
	// the same user's own request.
	newHash, hashErr := c.passwordHelper.Hash(in.NewPassword)
	if hashErr != nil {
		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", hashErr)),
		)
		return err
	}

	credential.PasswordHash = newHash
	credential.Algorithm = c.passwordHelper.Algorithm()
	if err = c.credentials.WithTxFromContext(ctx).Update(ctx, &credential); err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", err)),
			)
			return err
		}

		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", err)),
		)
		return err
	}

	// A reset is a password change and belongs in the same history. It was missing
	// before, so AuthCtrl.Me reported the date of the previous change and a user
	// who had just reset their password saw a stale one -- which is the very
	// signal people check when they suspect someone else has been in the account.
	logEntry := domain.NewPasswordChangeLog(passwordResetTwoFactorToken.UserID, in.SessionClientDeviceData)
	if errLog := c.passwordChangeLogs.WithTxFromContext(ctx).Create(ctx, &logEntry); errLog != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", errLog)),
		)
		return err
	}

	// Inside the transaction, and its failure aborts the reset.
	//
	// This used to run after the commit with the error logged and dropped, which
	// meant a reset could succeed while the sessions it was meant to end carried
	// on working -- and a password reset is what someone does precisely because
	// they believe another party is holding one. The empty SessionID spares
	// nothing: whoever answered the emailed code has no session of their own yet.
	if erRevoke := c.sessionCtrl.RevokeAllOnPasswordChange(ctx, domain.AuthenticatedSession{
		UserID:                  passwordResetTwoFactorToken.UserID,
		SessionClientDeviceData: in.SessionClientDeviceData,
	}); erRevoke != nil {
		if er, ok := appErrors.AsErrorResponse(erRevoke); ok {
			if er.Cause != nil {
				er.SetCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", er.Cause))
			}
			err = er
			return err
		}

		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", erRevoke)),
		)
		return err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[PasswordRecoveryCtrl:Confirm]%w", err)),
		)
		return err
	}

	return nil
}
