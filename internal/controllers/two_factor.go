package controllers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"user-service/config"
	svcErrors "user-service/internal/domain/errors"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

const (
	_twoFactorChallengeTTL = 10 * time.Minute
	_totpSecretSize        = 20
	_totpStepSeconds       = 30
	_totpDigitsCount       = 6
)

var _base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

type TwoFactorCtrl struct {
	tokens             domain.TwoFactorTokenRepository
	settings           domain.TwoFactorSettingsRepository
	users              domain.UserRepository
	contacts           domain.ContactRepository
	otpCtrl            domain.OTPController
	transactionManager domain.TransactionManager
}

func NewTwoFactorController(
	tokens domain.TwoFactorTokenRepository,
	settings domain.TwoFactorSettingsRepository,
	users domain.UserRepository,
	contacts domain.ContactRepository,
	otpCtrl domain.OTPController,
	tm domain.TransactionManager,
) *TwoFactorCtrl {
	return &TwoFactorCtrl{
		tokens:             tokens,
		settings:           settings,
		users:              users,
		contacts:           contacts,
		otpCtrl:            otpCtrl,
		transactionManager: tm,
	}
}

// Activate activates 2FA for a user
func (c TwoFactorCtrl) Activate(ctx context.Context, in domain.TwoFactorActivateParams) (domain.TwoFactorChallengeResult, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:Activate][userID:%d][method:%s]", in.UserID, in.Method.String())

	settings, errSettings := c.settings.FindByUserID(ctx, in.UserID)
	if errSettings != nil && !errors.Is(errSettings, domain.ErrRecordNotFound) {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", errSettings)),
		)

	}

	if settings.UserID != 0 {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			svcErrors.TwoFactorAlreadyEnabledError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate][err: two-factor already enabled]")),
		)
	}

	var contact *domain.ContactMethod
	switch in.Method {
	case domain.TwoFactorMethodEmail, domain.TwoFactorMethodSMS:
		contactType, ok := domain.ContactTypeForTwoFactorMethod(in.Method)
		if !ok {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate][err: unsupported contact mapping]")),
			)
		}

		contactMethod, errFind := c.contacts.FindPrimaryByUserAndType(ctx, in.UserID, contactType)
		if errFind != nil {
			if errors.Is(errFind, domain.ErrRecordNotFound) {
				return domain.TwoFactorChallengeResult{}, svcErrors.New(
					appErrors.RecordNotFoundError,
					appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", errFind)),
				)
			}
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", errFind)),
			)
		}
		if !contactMethod.IsVerified() {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				svcErrors.AccountContactUnverifiedError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate][err: contact unverified]")),
			)
		}

		contact = &contactMethod
	case domain.TwoFactorMethodGoogle:
		// Nothing to validate here, will be generated below
	default:
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate][err: unsupported method]")),
		)
	}

	// The invalidate and the create below are one change: without a transaction a
	// failure between them leaves the user with no active token at all, the old
	// one already dead and the new one never written.
	//
	// The transaction closes before the OTP is sent — holding one open across a
	// network call is its own problem — so a failed send leaves a committed token.
	// That is fine here: the next Activate invalidates it, so the path self-cleans.
	var txErr error
	txCtx := c.transactionManager.Begin(ctx)
	committed := false
	defer func() {
		if committed {
			return
		}
		if errRollback := c.transactionManager.Rollback(txCtx); errRollback != nil {
			logger.LogCtx(txCtx).Errorf("[TwoFactorCtrl:Activate][Rollback]%s", errRollback)
		}
	}()

	// Invalidate any existing active setup tokens for the user
	if txErr = c.tokens.WithTxFromContext(txCtx).InvalidateActiveByUserAndType(txCtx, in.UserID, domain.TwoFactorTokenTypeTwoFactorSetup); txErr != nil {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", txErr)),
		)
	}

	var twoFactorToken domain.TwoFactorToken
	result := domain.TwoFactorChallengeResult{
		Method:        in.Method,
		ContactMethod: contact,
	}
	var otpCode string

	switch in.Method {
	case domain.TwoFactorMethodGoogle:
		secret, errGen := generateTOTPSecret()
		if errGen != nil {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", errGen)),
			)
		}

		twoFactorToken = domain.NewTwoFactorSetupToken(in.UserID, in.Method, nil, secret, "", "", time.Now().UTC().Add(_twoFactorChallengeTTL))
		result.Secret = secret
	case domain.TwoFactorMethodEmail, domain.TwoFactorMethodSMS:
		if contact == nil {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate][err: contact is nil]")),
			)
		}

		otpToken, errGen := c.otpCtrl.Generate()
		if errGen != nil {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", errGen)),
			)
		}

		twoFactorToken = domain.NewTwoFactorSetupToken(in.UserID, in.Method, &contact.ID, "", otpToken.Hash, otpToken.Salt, otpToken.ExpiresAt)
		otpCode = otpToken.Code
	}

	if txErr = c.tokens.WithTxFromContext(txCtx).Create(txCtx, &twoFactorToken); txErr != nil {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", txErr)),
		)
	}

	if txErr = c.transactionManager.Commit(txCtx); txErr != nil {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate][Commit]%w", txErr)),
		)
	}
	committed = true

	result.TokenUUID = twoFactorToken.UUID
	result.ExpiresAt = twoFactorToken.ExpiresAt

	if contact != nil && otpCode != "" {
		if errSend := c.otpCtrl.Send(ctx, domain.OTPMessage{
			Purpose:      twoFactorToken.Type.GetNotificationPurpose(),
			ContactType:  contact.Type.String(),
			ContactValue: contact.Value,
			Code:         otpCode,
		}); errSend != nil {
			// Surface the failure instead of logging it. The caller can re-issue the
			// challenge — Activate is re-callable until 2FA is actually enabled — so
			// reporting "sent" when nothing was sent only strands the user watching
			// an inbox.
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.ExternalServiceError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Activate]%w", errSend)),
			)
		}
	}

	return result, nil
}

// Deactivate deactivates 2FA for a user
func (c TwoFactorCtrl) Deactivate(ctx context.Context, in domain.TwoFactorDeactivateParams) (domain.TwoFactorChallengeResult, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:Deactivate][userID:%d]", in.UserID)

	result, err := c.issueChallenge(ctx, domain.TwoFactorIssueChallengeParams{
		UserID: in.UserID,
		Type:   domain.TwoFactorTokenTypeTwoFactorDisable,
	})
	if err != nil {
		if err.Cause != nil {
			err.SetCause(fmt.Errorf("[TwoFactorCtrl:Deactivate]%w", err.Cause))
		}
		return domain.TwoFactorChallengeResult{}, err
	}

	return result, nil
}

// IssueChallenge issues a 2FA challenge
func (c TwoFactorCtrl) IssueChallenge(ctx context.Context, in domain.TwoFactorIssueChallengeParams) (domain.TwoFactorChallengeResult, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:IssueChallenge][userID:%d][type:%s]", in.UserID, in.Type.String())

	result, err := c.issueChallenge(ctx, in)
	if err != nil {
		return domain.TwoFactorChallengeResult{}, err
	}

	return result, nil
}

// ResendChallenge resends a 2FA challenge
func (c TwoFactorCtrl) ResendChallenge(ctx context.Context, in domain.TwoFactorChallengeResendParams) (domain.TwoFactorChallengeResult, error) {
	logger.LogCtx(ctx).Debugf(
		"[TwoFactorCtrl:ResendChallenge][userID:%d][type:%s][hasTokenUUID:%t]",
		in.UserID,
		in.Type.String(),
		in.TokenUUID != "",
	)

	var err error
	ctx = c.transactionManager.Begin(ctx)
	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)
			if rbErr := c.transactionManager.Rollback(ctx); rbErr != nil {
				logger.LogCtx(ctx).Errorf("[Rollback]%s", rbErr)
			}
		}
	}()

	twoFactorToken, errFind := c.tokens.WithTxFromContext(ctx).FindByUUIDAndTypeForUpdate(ctx, in.TokenUUID, in.Type)
	if errFind != nil {
		switch {
		case errors.Is(errFind, domain.ErrRecordNotFound):
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errFind)),
			)
		case errors.Is(errFind, domain.ErrConcurrencyConflict):
			err = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errFind)),
			)
		default:
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errFind)),
			)
		}
		return domain.TwoFactorChallengeResult{}, err
	}

	if twoFactorToken.Type.IsTwoFactorAction() && twoFactorToken.UserID != in.UserID {
		err = svcErrors.New(
			appErrors.AccessForbiddenError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge][err: token user mismatch]")),
		)
		return domain.TwoFactorChallengeResult{}, err
	}

	refreshInterval := config.Commons().OTPRefreshInterval
	if !twoFactorToken.IsRefreshable(refreshInterval) {
		err = svcErrors.New(
			svcErrors.CodeResendRateLimitedError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge][err: token is not refreshable]")),
			appErrors.WithData(appErrors.ErrorData{"retryAfter": twoFactorToken.RetryAfter(refreshInterval).Format(time.RFC3339)}),
		)
		return domain.TwoFactorChallengeResult{}, err
	}

	var contact *domain.ContactMethod
	var otpCode string

	switch twoFactorToken.Method {
	case domain.TwoFactorMethodEmail, domain.TwoFactorMethodSMS:
		if twoFactorToken.ContactID == nil {
			err = svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge][err: contact_id is nil for method %s]", twoFactorToken.Method.String())),
			)
			return domain.TwoFactorChallengeResult{}, err
		}

		contactMethod, errFindContact := c.contacts.WithTxFromContext(ctx).FindByID(ctx, *twoFactorToken.ContactID)
		if errFindContact != nil {
			switch {
			case errors.Is(errFindContact, domain.ErrRecordNotFound):
				err = svcErrors.New(
					appErrors.RecordNotFoundError,
					appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errFindContact)),
				)
			default:
				err = svcErrors.New(
					appErrors.DatabaseError,
					appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errFindContact)),
				)
			}
			return domain.TwoFactorChallengeResult{}, err
		}

		otpToken, errGen := c.otpCtrl.Generate()
		if errGen != nil {
			err = svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errGen)),
			)
			return domain.TwoFactorChallengeResult{}, err
		}

		twoFactorToken.CodeHash = otpToken.Hash
		twoFactorToken.CodeSalt = otpToken.Salt
		twoFactorToken.ExpiresAt = otpToken.ExpiresAt
		twoFactorToken.Status = domain.TwoFactorTokenStatusActive
		twoFactorToken.Attempts = 0
		twoFactorToken.ConsumedAt = nil
		twoFactorToken.DispatchedAt = time.Now().UTC()

		if errRefresh := c.tokens.WithTxFromContext(ctx).Refresh(ctx, &twoFactorToken); errRefresh != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errRefresh)),
			)
			return domain.TwoFactorChallengeResult{}, err
		}

		contact = &contactMethod
		otpCode = otpToken.Code
	default:
		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge][err: unsupported method %s]", twoFactorToken.Method.String())),
		)
		return domain.TwoFactorChallengeResult{}, err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge][Commit]%w", err)),
		)
		return domain.TwoFactorChallengeResult{}, err
	}

	if contact != nil && otpCode != "" {
		if errSend := c.otpCtrl.Send(ctx, domain.OTPMessage{
			Purpose:      twoFactorToken.Type.GetNotificationPurpose(),
			ContactType:  contact.Type.String(),
			ContactValue: contact.Value,
			Code:         otpCode,
		}); errSend != nil {
			// The caller already holds the token UUID and is explicitly asking for a
			// resend, so failing loudly costs nothing and lets them try again.
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.ExternalServiceError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:ResendChallenge]%w", errSend)),
			)
		}
	}

	return domain.TwoFactorChallengeResult{
		TokenUUID:     twoFactorToken.UUID,
		ExpiresAt:     twoFactorToken.ExpiresAt,
		Method:        twoFactorToken.Method,
		ContactMethod: contact,
	}, nil
}

// VerifyChallenge verifies a 2FA challenge
func (c TwoFactorCtrl) VerifyChallenge(ctx context.Context, in domain.TwoFactorChallengeVerifyParams) (domain.TwoFactorToken, *appErrors.ErrorResponse) {
	logger.LogCtx(ctx).Debugf(
		"[TwoFactorCtrl:VerifyChallenge][type:%s][hasTokenUUID:%t]",
		in.Type.String(),
		in.TokenUUID != "",
	)

	twoFactorToken, _, err := c.verifyChallenge(ctx, in)
	if err != nil {
		if err.Cause != nil {
			err.SetCause(fmt.Errorf("[TwoFactorCtrl:VerifyChallenge]%w", err.Cause))
		}
		return domain.TwoFactorToken{}, err
	}

	return twoFactorToken, nil
}

// verifyChallenge verifies a 2FA challenge without logging context
func (c TwoFactorCtrl) verifyChallenge(ctx context.Context, in domain.TwoFactorChallengeVerifyParams) (domain.TwoFactorToken, int64, *appErrors.ErrorResponse) {
	logger.LogCtx(ctx).Debugf(
		"[TwoFactorCtrl:verifyChallenge][type:%s][hasTokenUUID:%t]",
		in.Type.String(),
		in.TokenUUID != "",
	)

	twoFactorToken, errFind := c.tokens.WithTxFromContext(ctx).FindByUUIDAndTypeForUpdate(ctx, in.TokenUUID, in.Type)
	if errFind != nil {
		switch {
		case errors.Is(errFind, domain.ErrRecordNotFound):
			return domain.TwoFactorToken{}, 0, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[verifyChallenge]%w", errFind)),
			)
		case errors.Is(errFind, domain.ErrConcurrencyConflict):
			return domain.TwoFactorToken{}, 0, svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[verifyChallenge]%w", errFind)),
			)
		default:
			return domain.TwoFactorToken{}, 0, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[verifyChallenge]%w", errFind)),
			)
		}
	}

	if in.UserID != nil && twoFactorToken.UserID != *in.UserID {
		return domain.TwoFactorToken{}, 0, svcErrors.New(
			appErrors.AccessForbiddenError,
			appErrors.WithCause(fmt.Errorf("[verifyChallenge][err: token user mismatch]")),
		)
	}

	if twoFactorToken.IsConsumed() {
		return domain.TwoFactorToken{}, 0, svcErrors.New(
			svcErrors.CodeConsumedError,
			appErrors.WithCause(fmt.Errorf("[verifyChallenge][err: token consumed]")),
		)
	}

	if twoFactorToken.IsExpired() {
		return domain.TwoFactorToken{}, 0, svcErrors.New(
			svcErrors.CodeExpiredError,
			appErrors.WithCause(fmt.Errorf("[verifyChallenge][err: token expired]")),
		)
	}

	if twoFactorToken.AttemptsLeft() == 0 {
		return domain.TwoFactorToken{}, 0, svcErrors.New(
			svcErrors.CodeAttemptsExceededError,
			appErrors.WithCause(fmt.Errorf("[verifyChallenge][err: attempts exceeded]")),
		)
	}

	acceptedCounter, valid, erVerify := c.verifyTokenCode(ctx, twoFactorToken, in.Code)
	if erVerify != nil {
		return domain.TwoFactorToken{}, 0, erVerify
	}
	if !valid {
		if incErr := c.tokens.WithTxFromContext(ctx).IncrementAttempts(ctx, twoFactorToken.UUID); incErr != nil {
			return domain.TwoFactorToken{}, 0, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[verifyChallenge]%w", incErr)),
			)
		}

		return domain.TwoFactorToken{}, 0, svcErrors.New(
			svcErrors.CodeInvalidError,
			appErrors.WithCause(fmt.Errorf("[verifyChallenge][err: invalid code]")),
		)
	}

	if err := c.tokens.WithTxFromContext(ctx).Consume(ctx, twoFactorToken.UUID, true); err != nil {
		// A zero-row consume means the token was used between the read above and
		// here. That is a business outcome, not a database failure, and the caller
		// must see the same error it would get from the IsConsumed check.
		if errors.Is(err, domain.ErrTokenAlreadyConsumed) {
			return domain.TwoFactorToken{}, 0, svcErrors.New(
				svcErrors.CodeConsumedError,
				appErrors.WithCause(fmt.Errorf("[verifyChallenge]%w", err)),
			)
		}

		return domain.TwoFactorToken{}, 0, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[verifyChallenge]%w", err)),
		)
	}

	return twoFactorToken, acceptedCounter, nil
}

// Confirm confirms a 2FA challenge activation or deactivation
func (c TwoFactorCtrl) Confirm(ctx context.Context, in domain.TwoFactorConfirmParams) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:Confirm][userID: %d]", in.UserID)

	var err error
	ctx = c.transactionManager.Begin(ctx)
	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:Confirm][Rollback]%s", err)
			if rbErr := c.transactionManager.Rollback(ctx); rbErr != nil {
				logger.LogCtx(ctx).Errorf("[TwoFactorCtrl:Confirm][Rollback]%s", rbErr)
			}
		}
	}()

	tokenType := domain.TwoFactorTokenTypeTwoFactorSetup
	if in.Action == domain.TwoFactorActionDeactivate {
		tokenType = domain.TwoFactorTokenTypeTwoFactorDisable
	}

	twoFactorToken, acceptedCounter, errVerify := c.verifyChallenge(ctx, domain.TwoFactorChallengeVerifyParams{
		UserID:    &in.UserID,
		Type:      tokenType,
		TokenUUID: in.TokenUUID,
		Code:      in.Code,
	})
	if errVerify != nil {
		if errVerify.Cause != nil {
			errVerify.SetCause(fmt.Errorf("[TwoFactorCtrl:Confirm]%w", errVerify.Cause))
		}
		if errVerify.Code == svcErrors.CodeInvalidError {
			if err = c.transactionManager.Commit(ctx); err != nil {
				err = svcErrors.New(
					appErrors.DatabaseError,
					appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Confirm][Commit]%w", err)),
				)
				return err
			}
			return errVerify
		}

		err = errVerify
		return err
	}

	switch twoFactorToken.Type {
	case domain.TwoFactorTokenTypeTwoFactorSetup:
		settings := domain.TwoFactorSettings{
			UserID: twoFactorToken.UserID,
			Method: twoFactorToken.Method,
		}
		if settings.Method == domain.TwoFactorMethodGoogle {
			settings.Secret = twoFactorToken.Secret
			// Seeded with the step enrollment just accepted, so the code the user
			// typed to enroll cannot be turned round and used to sign in inside the
			// window it stays valid.
			settings.LastTOTPCounter = acceptedCounter
		}
		if twoFactorToken.ContactID != nil {
			settings.ContactID = twoFactorToken.ContactID
		}

		if err = c.settings.WithTxFromContext(ctx).Create(ctx, &settings); err != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Confirm]%w", err)),
			)
			return err
		}
	case domain.TwoFactorTokenTypeTwoFactorDisable:
		if err = c.settings.WithTxFromContext(ctx).Delete(ctx, twoFactorToken.UserID); err != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Confirm]%w", err)),
			)
			return err
		}
	default:
		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Confirm][err: unsupported token type %s]", twoFactorToken.Type.String())),
		)
		return err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:Confirm][Commit]%w", err)),
		)
		return err
	}

	return nil
}

// GetSettings retrieves the 2FA settings for a user
func (c TwoFactorCtrl) GetSettings(ctx context.Context, userID domain.ID) (domain.TwoFactorGetSettingsResult, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:GetSettings][userID: %d]", userID)

	settings, err := c.settings.FindByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			return domain.TwoFactorGetSettingsResult{}, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:GetSettings]%w", err)),
			)
		}
		return domain.TwoFactorGetSettingsResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:GetSettings]%w", err)),
		)
	}

	var contact *domain.ContactMethod
	if settings.Method == domain.TwoFactorMethodEmail || settings.Method == domain.TwoFactorMethodSMS {
		if settings.ContactID == nil {
			return domain.TwoFactorGetSettingsResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:GetSettings][err: contact id is nil for method %s]", settings.Method.String())),
			)
		}

		contactMethod, errFind := c.contacts.FindByID(ctx, *settings.ContactID)
		if errFind != nil {
			if errors.Is(errFind, domain.ErrRecordNotFound) {
				return domain.TwoFactorGetSettingsResult{}, svcErrors.New(
					appErrors.InternalServerError,
					appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:GetSettings]%w", errFind)),
				)
			}
			return domain.TwoFactorGetSettingsResult{}, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[TwoFactorCtrl:GetSettings]%w", errFind)),
			)
		}

		contact = &contactMethod
	}

	return domain.TwoFactorGetSettingsResult{
		Method:    settings.Method,
		Contact:   contact,
		CreatedAt: settings.CreatedAt,
	}, nil
}

// issueChallenge issues a 2FA challenge for the user and returns the challenge details.
func (c TwoFactorCtrl) issueChallenge(ctx context.Context, in domain.TwoFactorIssueChallengeParams) (domain.TwoFactorChallengeResult, *appErrors.ErrorResponse) {
	logger.LogCtx(ctx).Debugf("[TwoFactorCtrl:issueChallenge][userID:%d][type:%s]", in.UserID, in.Type.String())

	if in.Type == domain.TwoFactorTokenTypeTwoFactorSetup {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[issueChallenge][err: invalid token type]")),
		)
	}

	settings, errSettings := c.settings.FindByUserID(ctx, in.UserID)
	if errSettings != nil {
		if errors.Is(errSettings, domain.ErrRecordNotFound) {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", errSettings)),
			)
		}
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", errSettings)),
		)
	}

	var contact *domain.ContactMethod
	switch settings.Method {
	case domain.TwoFactorMethodEmail, domain.TwoFactorMethodSMS:
		if settings.ContactID == nil {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[issueChallenge][err: contact id is nil for method %s]", settings.Method.String())),
			)
		}

		contactMethod, errFind := c.contacts.FindByID(ctx, *settings.ContactID)
		if errFind != nil {
			if errors.Is(errFind, domain.ErrRecordNotFound) {
				return domain.TwoFactorChallengeResult{}, svcErrors.New(
					appErrors.InternalServerError,
					appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", errFind)),
				)
			}
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", errFind)),
			)
		}
		contact = &contactMethod
	case domain.TwoFactorMethodGoogle:
		// Nothing to validate here, will be generated below
	default:
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[issueChallenge][err: unsupported method]")),
		)
	}

	// Same pairing as Activate: the invalidate and the create are one change, and
	// a failure between them would leave the user with no active challenge —
	// the previous one dead and the replacement never written. The transaction
	// closes before the OTP is sent, so no network call happens inside it.
	var txErr error
	txCtx := c.transactionManager.Begin(ctx)
	committed := false
	defer func() {
		if committed {
			return
		}
		if errRollback := c.transactionManager.Rollback(txCtx); errRollback != nil {
			logger.LogCtx(txCtx).Errorf("[issueChallenge][Rollback]%s", errRollback)
		}
	}()

	// Invalidate any existing active challenge tokens for the user
	if txErr = c.tokens.WithTxFromContext(txCtx).InvalidateActiveByUserAndType(txCtx, in.UserID, in.Type); txErr != nil {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", txErr)),
		)
	}

	var twoFactorToken domain.TwoFactorToken
	result := domain.TwoFactorChallengeResult{
		Method:        settings.Method,
		ContactMethod: contact,
	}
	var otpCode string

	switch settings.Method {
	case domain.TwoFactorMethodGoogle:
		twoFactorToken = domain.NewTwoFactorToken(in.UserID, settings.Method, in.Type, nil, settings.Secret, "", "", time.Now().UTC().Add(_twoFactorChallengeTTL))
		if in.Type == domain.TwoFactorTokenTypeTwoFactorSetup {
			result.Secret = settings.Secret
		}
	case domain.TwoFactorMethodEmail, domain.TwoFactorMethodSMS:
		if contact == nil {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[issueChallenge][err: contact is nil]")),
			)
		}

		otpToken, errGen := c.otpCtrl.Generate()
		if errGen != nil {
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", errGen)),
			)
		}

		twoFactorToken = domain.NewTwoFactorToken(in.UserID, settings.Method, in.Type, settings.ContactID, "", otpToken.Hash, otpToken.Salt, otpToken.ExpiresAt)
		otpCode = otpToken.Code
	}

	if txErr = c.tokens.WithTxFromContext(txCtx).Create(txCtx, &twoFactorToken); txErr != nil {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", txErr)),
		)
	}

	if txErr = c.transactionManager.Commit(txCtx); txErr != nil {
		return domain.TwoFactorChallengeResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[issueChallenge][Commit]%w", txErr)),
		)
	}
	committed = true

	result.TokenUUID = twoFactorToken.UUID
	result.ExpiresAt = twoFactorToken.ExpiresAt

	if contact != nil && otpCode != "" {
		if errSend := c.otpCtrl.Send(ctx, domain.OTPMessage{
			Purpose:      twoFactorToken.Type.GetNotificationPurpose(),
			ContactType:  contact.Type.String(),
			ContactValue: contact.Value,
			Code:         otpCode,
		}); errSend != nil {
			// Both callers (Deactivate, IssueChallenge) simply issue a fresh challenge
			// on retry, so nothing is lost by failing here.
			return domain.TwoFactorChallengeResult{}, svcErrors.New(
				appErrors.ExternalServiceError,
				appErrors.WithCause(fmt.Errorf("[issueChallenge]%w", errSend)),
			)
		}
	}

	return result, nil
}

// generateTOTPSecret generates a new base32-encoded TOTP secret.
func generateTOTPSecret() (string, error) {
	buf := make([]byte, _totpSecretSize)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return _base32NoPadding.EncodeToString(buf), nil
}

// verifyTokenCode verifies the provided code and, for TOTP, spends the time step
// it matched.
//
// It returns the accepted step so enrollment can seed it into the settings it is
// about to write; zero for the methods that have none.
func (c TwoFactorCtrl) verifyTokenCode(
	ctx context.Context,
	twoFactorToken domain.TwoFactorToken,
	code string,
) (int64, bool, *appErrors.ErrorResponse) {
	switch twoFactorToken.Method {
	case domain.TwoFactorMethodGoogle:
		if twoFactorToken.Secret == "" {
			return 0, false, nil
		}

		counter, ok := validateTOTPCode(twoFactorToken.Secret, code)
		if !ok {
			return 0, false, nil
		}

		// Enrollment has no settings row yet to record against; Confirm creates one
		// seeded with this step a moment later.
		if twoFactorToken.Type == domain.TwoFactorTokenTypeTwoFactorSetup {
			return counter, true, nil
		}

		// Spending the step is what stops the same six digits being replayed
		// against a different challenge inside the 90 seconds they stay valid.
		advanced, err := c.settings.WithTxFromContext(ctx).AdvanceTOTPCounter(ctx, twoFactorToken.UserID, counter)
		if err != nil {
			return 0, false, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[verifyTokenCode]%w", err)),
			)
		}
		if !advanced {
			// Already spent. Reported as an ordinary wrong code: it costs the
			// caller an attempt and tells them nothing about why.
			return 0, false, nil
		}

		return counter, true, nil
	case domain.TwoFactorMethodEmail, domain.TwoFactorMethodSMS:
		return 0, c.otpCtrl.Verify(code, twoFactorToken.CodeSalt, twoFactorToken.CodeHash), nil
	default:
		return 0, false, nil
	}
}

// validateTOTPCode validates a TOTP code and reports which time step matched.
//
// The step is what the caller records: a code is good once, so the next one has
// to sit strictly above the last one accepted.
func validateTOTPCode(secret, code string) (int64, bool) {
	if len(code) != _totpDigitsCount {
		return 0, false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return 0, false
	}

	key, err := _base32NoPadding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}

	counter := time.Now().UTC().Unix() / _totpStepSeconds
	for _, offset := range []int64{0, -1, 1} {
		current := counter + offset
		if current < 0 {
			continue
		}
		expected := hotpFromKey(key, uint64(current))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return current, true
		}
	}

	return 0, false
}

// hotpFromKey generates an HOTP code from the given key and counter.
func hotpFromKey(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := ((int(sum[offset]) & 0x7f) << 24) |
		(int(sum[offset+1]) << 16) |
		(int(sum[offset+2]) << 8) |
		int(sum[offset+3])

	otp := truncated % 1000000
	return fmt.Sprintf("%0*d", _totpDigitsCount, otp)
}
