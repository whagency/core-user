package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"user-service/config"
	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	recaptchaV3 "user-service/services/recaptcha/v3"

	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

// AuthCtrl orchestrates the authentication use cases.
type AuthCtrl struct {
	users              domain.UserRepository
	contacts           domain.ContactRepository
	profiles           domain.ProfileRepository
	credentials        domain.CredentialRepository
	passwordChangeLogs domain.PasswordChangeLogRepository
	verifications      domain.VerificationRepository
	sessions           domain.SessionRepository
	authLogs           domain.AuthLogRepository
	passwordHelper     domain.PasswordHelper
	twoFactorCtrl      domain.TwoFactorController
	geoCtrl            domain.GeoController
	sessionCtrl        domain.SessionController
	transactionManager domain.TransactionManager
	recaptchaV3        *recaptchaV3.Service
}

// NewAuthController builds a new authentication controller.
func NewAuthController(
	users domain.UserRepository,
	contacts domain.ContactRepository,
	profiles domain.ProfileRepository,
	credentials domain.CredentialRepository,
	passwordChangeLogs domain.PasswordChangeLogRepository,
	verifications domain.VerificationRepository,
	sessions domain.SessionRepository,
	authLogs domain.AuthLogRepository,
	passwordHelper domain.PasswordHelper,
	twoFactorCtrl domain.TwoFactorController,
	geoCtrl domain.GeoController,
	sessionCtrl domain.SessionController,
	transactionManager domain.TransactionManager,
	recaptchaV3 *recaptchaV3.Service,
) *AuthCtrl {
	return &AuthCtrl{
		users:              users,
		contacts:           contacts,
		profiles:           profiles,
		credentials:        credentials,
		passwordChangeLogs: passwordChangeLogs,
		verifications:      verifications,
		sessions:           sessions,
		authLogs:           authLogs,
		passwordHelper:     passwordHelper,
		twoFactorCtrl:      twoFactorCtrl,
		geoCtrl:            geoCtrl,
		sessionCtrl:        sessionCtrl,
		transactionManager: transactionManager,
		recaptchaV3:        recaptchaV3,
	}
}

// Login authenticates a user and issues a new session.
func (c AuthCtrl) Login(ctx context.Context, in domain.LoginParams) (domain.LoginResult, error) {
	logger.LogCtx(ctx).Debugf(
		"[AuthCtrl:Login][hasIdentifier:%t][hasDeviceFingerprint:%t][hasIP:%t]",
		in.Identifier != "",
		in.DeviceFingerprint != "",
		in.IPAddress != "",
	)

	// Validate reCAPTCHA v3 token
	if config.Commons().IsProduction() && !c.recaptchaV3.IsTokenValid(ctx, in.Recaptcha) {
		return domain.LoginResult{}, svcErrors.New(
			svcErrors.RecaptchaValidationError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login][err: recaptcha token is invalid]")),
		)
	}

	// Same normalization the value was stored under; without it a user who
	// capitalizes their address differently than at registration is told the
	// account does not exist.
	contact, errContact := c.contacts.FindByValue(ctx, domain.NormalizeContactValue(in.Identifier))
	if errContact != nil {
		if errors.Is(errContact, domain.ErrRecordNotFound) {
			return domain.LoginResult{}, svcErrors.New(
				svcErrors.AccountInvalidCredentialsError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errContact)),
			)
		}

		return domain.LoginResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errContact)),
		)
	}
	if !contact.IsVerified() {
		return domain.LoginResult{}, svcErrors.New(
			svcErrors.AccountContactUnverifiedError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login][err: contact unverified]")),
		)
	}

	user, errFindUser := c.users.FindByID(ctx, contact.UserID)
	if errFindUser != nil {
		if errors.Is(errFindUser, domain.ErrRecordNotFound) {
			return domain.LoginResult{}, svcErrors.New(
				svcErrors.AccountInvalidCredentialsError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errFindUser)),
			)
		}

		return domain.LoginResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errFindUser)),
		)
	}
	if errValidate := user.ValidateStatus(); errValidate != nil {
		if errValidate.Cause != nil {
			errValidate.SetCause(fmt.Errorf("[AuthCtrl:Login]%w", errValidate.Cause))
		}
		return domain.LoginResult{}, errValidate
	}

	credential, errFindCredential := c.credentials.FindByUserID(ctx, user.ID)
	if errFindCredential != nil {
		if errors.Is(errFindCredential, domain.ErrRecordNotFound) {
			return domain.LoginResult{}, svcErrors.New(
				svcErrors.AccountInvalidCredentialsError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errFindCredential)),
			)
		}

		return domain.LoginResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errFindCredential)),
		)
	}

	if credential.MustRotate {
		return domain.LoginResult{}, svcErrors.New(
			svcErrors.AccountPasswordRequiredRotation,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login][err: password rotation required]")),
		)
	}

	// Checked before the hash comparison, so a locked account costs an attacker a
	// query rather than a bcrypt round.
	if credential.IsLoginLocked(time.Now().UTC()) {
		// Logged rather than written to auth_logs. A sustained attack would put a
		// row here per request, and auth_logs has no retention; the failures that
		// caused the lock are already recorded, which is what an investigation
		// needs.
		logger.LogCtx(ctx).Warnf(
			"[AuthCtrl:Login][msg: sign-in refused, account locked][userID:%d][until:%s]",
			user.ID,
			credential.LoginLockedUntil.Format(time.RFC3339),
		)

		return domain.LoginResult{}, newLoginLockedError(*credential.LoginLockedUntil)
	}

	matched, errVerify := c.passwordHelper.Verify(in.Password, credential.PasswordHash)
	if errVerify != nil {
		return domain.LoginResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errVerify)),
		)
	}
	if !matched {
		return domain.LoginResult{}, c.registerFailedLogin(ctx, user.ID, in.SessionClientDeviceData)
	}

	// Any successful password check clears the streak. Writes only when there is
	// something to clear, so the ordinary sign-in does not touch the row.
	if errClear := c.credentials.ClearLoginFailures(ctx, user.ID); errClear != nil {
		return domain.LoginResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errClear)),
		)
	}

	challenge, errChallenge := c.twoFactorCtrl.IssueChallenge(ctx, domain.TwoFactorIssueChallengeParams{
		UserID: user.ID,
		Type:   domain.TwoFactorTokenTypeTwoFactorAuth,
	})
	if errChallenge == nil {
		return domain.LoginResult{
			UserID:                   user.ID,
			TwoFactorChallengeResult: &challenge,
			Requires2FA:              true,
		}, nil
	}

	er, ok := appErrors.AsErrorResponse(errChallenge)
	if !ok {
		return domain.LoginResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login]%w", errChallenge)),
		)
	}

	if er.Code != appErrors.RecordNotFoundError {
		if er.Cause != nil {
			er.SetCause(fmt.Errorf("[AuthCtrl:Login]%w", er.Cause))
		}
		return domain.LoginResult{}, er
	}

	var err error
	ctx = c.transactionManager.Begin(ctx)
	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)
			if errRollback := c.transactionManager.Rollback(ctx); errRollback != nil {
				logger.LogCtx(ctx).Errorf("[Rollback]%s", errRollback)
			}
		}
	}()

	session, errSession := c.issueSession(
		ctx,
		&domain.SessionIssueParams{
			UserID:                  user.ID,
			SessionClientDeviceData: in.SessionClientDeviceData,
		},
	)
	if errSession != nil {
		if errSession.Cause != nil {
			errSession.SetCause(fmt.Errorf("[AuthCtrl:Login]%w", errSession.Cause))
		}
		err = errSession
		return domain.LoginResult{}, err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Login][Commit]%w", err)),
		)
		return domain.LoginResult{}, err
	}

	return domain.LoginResult{
		UserID:      user.ID,
		Session:     &session,
		Requires2FA: false,
	}, nil
}

// registerFailedLogin counts the failure, records it, and returns what the caller
// should hand back.
//
// The counter and the audit row go in one transaction: a counter that advanced
// without leaving a trace, or a trace without the counter, would each make an
// investigation lie about what happened.
//
// The caller is told "invalid credentials" as before, unless this attempt is the
// one that engaged the lock -- there the retryAfter is worth having, and the
// account's existence has already been given away by the unverified-contact and
// blocked responses above.
func (c AuthCtrl) registerFailedLogin(
	ctx context.Context,
	userID domain.ID,
	deviceData domain.SessionClientDeviceData,
) error {
	policy := domain.LoginLockPolicy{
		MaxFailedAttempts: config.Commons().LoginMaxFailedAttempts,
		LockFor:           config.Commons().LoginLockDuration,
	}

	var err error
	txCtx := c.transactionManager.Begin(ctx)
	committed := false
	defer func() {
		if committed {
			return
		}
		if errRollback := c.transactionManager.Rollback(txCtx); errRollback != nil {
			logger.LogCtx(txCtx).Errorf("[AuthCtrl:registerFailedLogin][Rollback]%s", errRollback)
		}
	}()

	updated, errRegister := c.credentials.WithTxFromContext(txCtx).RegisterFailedLogin(txCtx, userID, policy)
	if errRegister != nil {
		return svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:registerFailedLogin]%w", errRegister)),
		)
	}

	authLog := &domain.AuthLog{
		UserID:                  userID,
		SessionClientDeviceData: deviceData,
		Status:                  domain.AuthLogStatusLoginFailed,
	}
	if errLog := c.authLogs.WithTxFromContext(txCtx).Create(txCtx, authLog); errLog != nil {
		return svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:registerFailedLogin]%w", errLog)),
		)
	}

	if err = c.transactionManager.Commit(txCtx); err != nil {
		return svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:registerFailedLogin][Commit]%w", err)),
		)
	}
	committed = true

	if updated.IsLoginLocked(time.Now().UTC()) {
		logger.LogCtx(ctx).Warnf(
			"[AuthCtrl:registerFailedLogin][msg: account locked after consecutive failures][userID:%d][attempts:%d][until:%s]",
			userID,
			updated.FailedLoginAttempts,
			updated.LoginLockedUntil.Format(time.RFC3339),
		)

		return newLoginLockedError(*updated.LoginLockedUntil)
	}

	return svcErrors.New(
		svcErrors.AccountInvalidCredentialsError,
		appErrors.WithCause(fmt.Errorf("[AuthCtrl:registerFailedLogin][err: invalid credentials]")),
	)
}

// newLoginLockedError reports the lock with the deadline attached, in the shape
// the OTP resend limit already uses.
func newLoginLockedError(until time.Time) *appErrors.ErrorResponse {
	return svcErrors.New(
		svcErrors.AccountLoginAttemptsExceededError,
		appErrors.WithCause(fmt.Errorf("[err: sign-in locked until %s]", until.Format(time.RFC3339))),
		appErrors.WithData(appErrors.ErrorData{"retryAfter": until.Format(time.RFC3339)}),
	)
}

// issueSession creates a new session and logs the authentication event.
func (c AuthCtrl) issueSession(ctx context.Context, sessionIssueParams *domain.SessionIssueParams) (domain.SessionToken, *appErrors.ErrorResponse) {
	logger.LogCtx(ctx).Debugf(
		"[AuthCtrl:issueSession][userID:%d][hasDeviceFingerprint:%t][hasIP:%t]",
		sessionIssueParams.UserID,
		sessionIssueParams.DeviceFingerprint != "",
		sessionIssueParams.IPAddress != "",
	)

	storedAuthLog := &domain.AuthLog{
		UserID:                  sessionIssueParams.UserID,
		SessionClientDeviceData: sessionIssueParams.SessionClientDeviceData,
		Status:                  domain.AuthLogStatusLoginSuccess,
	}

	if dataGeo, errGeo := c.geoCtrl.GetGeoInfo(sessionIssueParams.SessionClientDeviceData.IPAddress); errGeo == nil {
		sessionIssueParams.SessionClientDeviceData.SetGeoInfo(dataGeo)
		storedAuthLog.City = dataGeo.City
		storedAuthLog.CountryName = dataGeo.CountryName
	} else {
		logger.LogCtx(ctx).Errorf("[AuthCtrl:issueSession]%s", errGeo)
	}

	if dataAnonymous, errAnonymous := c.geoCtrl.GetAnonymousInfo(sessionIssueParams.SessionClientDeviceData.IPAddress); errAnonymous == nil {
		sessionIssueParams.SessionClientDeviceData.SetAnonymousInfo(dataAnonymous)
		storedAuthLog.AnonymousInfo = dataAnonymous
	} else {
		logger.LogCtx(ctx).Errorf("[AuthCtrl:issueSession]%s", errAnonymous)
	}

	session, errSession := c.sessionCtrl.Issue(
		ctx,
		sessionIssueParams,
	)
	if errSession != nil {
		if er, ok := appErrors.AsErrorResponse(errSession); ok {
			if er.Cause != nil {
				er.SetCause(fmt.Errorf("[issueSession]%w", er.Cause))
			}
			return domain.SessionToken{}, er
		}

		return domain.SessionToken{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[issueSession]%w", errSession)),
		)
	}

	if err := c.authLogs.WithTxFromContext(ctx).Create(ctx, storedAuthLog); err != nil {
		return domain.SessionToken{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[issueSession]%w", err)),
		)
	}

	return session, nil
}

// Me returns the authenticated user's information.
func (c AuthCtrl) Me(ctx context.Context, userID domain.ID) (domain.MeResult, error) {
	logger.LogCtx(ctx).Debugf("[AuthCtrl:Me][userID: %d]", userID)

	user, errUser := c.users.FindByID(ctx, userID)
	if errUser != nil {
		if errors.Is(errUser, domain.ErrRecordNotFound) {
			err := svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errUser)),
			)
			return domain.MeResult{}, err
		}
		err := svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errUser)),
		)
		return domain.MeResult{}, err
	}

	if user.PrimaryContactID == nil {
		err := svcErrors.New(
			appErrors.RecordNotFoundError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me][err: primary contact missing]")),
		)
		return domain.MeResult{}, err
	}

	contact, errContact := c.contacts.FindByID(ctx, *user.PrimaryContactID)
	if errContact != nil {
		if errors.Is(errContact, domain.ErrRecordNotFound) {
			err := svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errContact)),
			)
			return domain.MeResult{}, err
		}
		err := svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errContact)),
		)
		return domain.MeResult{}, err
	}

	profile, errProfile := c.profiles.FindByUserID(ctx, user.ID)
	if errProfile != nil {
		if errors.Is(errProfile, domain.ErrRecordNotFound) {
			err := svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errProfile)),
			)
			return domain.MeResult{}, err
		}
		err := svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errProfile)),
		)
		return domain.MeResult{}, err
	}

	var lastPasswordChangeAt *time.Time
	if logEntry, errLog := c.passwordChangeLogs.FindLastByUserID(ctx, user.ID); errLog != nil {
		if !errors.Is(errLog, domain.ErrRecordNotFound) {
			err := svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errLog)),
			)
			return domain.MeResult{}, err
		}
	} else {
		lastPasswordChangeAt = &logEntry.CreatedAt
	}

	var lastVerificationRequest *domain.LastUserVerificationRequest
	if verification, errVerification := c.verifications.GetLast(ctx, user.ID); errVerification != nil {
		if !errors.Is(errVerification, domain.ErrRecordNotFound) {
			err := svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[AuthCtrl:Me]%w", errVerification)),
			)
			return domain.MeResult{}, err
		}
	} else {
		lastVerificationRequest = &domain.LastUserVerificationRequest{
			FormUrl:   verification.GetFormUrl(),
			Status:    verification.Status,
			CreatedAt: verification.CreatedAt,
			UpdatedAt: verification.UpdatedAt,
		}
	}

	return domain.MeResult{
		UserNumber:                  user.Number,
		Status:                      user.Status.String(),
		VerificationLevel:           user.VerificationLevel,
		Contact:                     &contact,
		Profile:                     profile,
		LastPasswordChangeAt:        lastPasswordChangeAt,
		LastUserVerificationRequest: lastVerificationRequest,
	}, nil
}

// CompleteLoginChallenge verifies a 2FA challenge and issues a new session.
func (c AuthCtrl) CompleteLoginChallenge(ctx context.Context, in domain.LoginChallengeVerifyParams) (domain.LoginChallengeConfirmResult, error) {
	logger.LogCtx(ctx).Debugf(
		"[AuthCtrl:CompleteLoginChallenge][hasTokenUUID:%t][hasDeviceFingerprint:%t][hasIP:%t]",
		in.TokenUUID != "",
		in.DeviceFingerprint != "",
		in.IPAddress != "",
	)

	var err error
	ctx = c.transactionManager.Begin(ctx)
	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[AuthCtrl:CompleteLoginChallenge][Rollback]%s", err)
			if errRollback := c.transactionManager.Rollback(ctx); errRollback != nil {
				logger.LogCtx(ctx).Errorf("[AuthCtrl:CompleteLoginChallenge][Rollback]%s", errRollback)
			}
		}
	}()

	twoFactorToken, errVerify := c.twoFactorCtrl.VerifyChallenge(ctx, domain.TwoFactorChallengeVerifyParams{
		Type:      domain.TwoFactorTokenTypeTwoFactorAuth,
		TokenUUID: in.TokenUUID,
		Code:      in.Code,
	})
	if errVerify != nil {
		if errVerify.Cause != nil {
			errVerify.SetCause(fmt.Errorf("[AuthCtrl:CompleteLoginChallenge]%w", errVerify.Cause))
		}
		if errVerify.Code == svcErrors.CodeInvalidError {
			if err = c.transactionManager.Commit(ctx); err != nil {
				err = svcErrors.New(
					appErrors.DatabaseError,
					appErrors.WithCause(fmt.Errorf("[AuthCtrl:CompleteLoginChallenge][Commit]%w", err)),
				)
				return domain.LoginChallengeConfirmResult{}, err
			}
			return domain.LoginChallengeConfirmResult{}, errVerify
		}

		err = errVerify
		return domain.LoginChallengeConfirmResult{}, err
	}

	session, errSession := c.issueSession(
		ctx,
		&domain.SessionIssueParams{
			UserID:                  twoFactorToken.UserID,
			SessionClientDeviceData: in.SessionClientDeviceData,
		},
	)
	if errSession != nil {
		if errSession.Cause != nil {
			errSession.SetCause(fmt.Errorf("[AuthCtrl:CompleteLoginChallenge]%w", errSession.Cause))
		}
		err = errSession
		return domain.LoginChallengeConfirmResult{}, err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[AuthCtrl:CompleteLoginChallenge][Commit]%w", err)),
		)
		return domain.LoginChallengeConfirmResult{}, err
	}

	return domain.LoginChallengeConfirmResult{Session: session}, nil
}
