package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"
	svcErrors "user-service/internal/domain/errors"

	"user-service/config"
	"user-service/internal/domain"
	recaptchaV3 "user-service/services/recaptcha/v3"

	"github.com/whagency/core-common/cache"
	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/services/restriction"
)

type UserCtrl struct {
	users              domain.UserRepository
	contacts           domain.ContactRepository
	profiles           domain.ProfileRepository
	credentials        domain.CredentialRepository
	passwordChangeLogs domain.PasswordChangeLogRepository
	twoFaTokens        domain.TwoFactorTokenRepository
	verifications      domain.VerificationRepository
	otpCtrl            domain.OTPController
	outboxRepo         domain.OutboxRepository
	userEventCtrl      domain.UserEventController
	sessionCtrl        domain.SessionController
	geoCtrl            domain.GeoController
	passwordHelper     domain.PasswordHelper
	restriction        domain.RestrictionService
	transactionManager domain.TransactionManager
	recaptchaV3        *recaptchaV3.Service
}

func NewUserController(
	users domain.UserRepository,
	contacts domain.ContactRepository,
	profiles domain.ProfileRepository,
	credentials domain.CredentialRepository,
	passwordChangeLogs domain.PasswordChangeLogRepository,
	twoFaTokens domain.TwoFactorTokenRepository,
	verifications domain.VerificationRepository,
	otpCtrl domain.OTPController,
	outboxRepo domain.OutboxRepository,
	userEventCtrl domain.UserEventController,
	sessionCtrl domain.SessionController,
	geoCtrl domain.GeoController,
	passwordHelper domain.PasswordHelper,
	restriction domain.RestrictionService,
	tm domain.TransactionManager,
	recaptchaV3 *recaptchaV3.Service,
) *UserCtrl {
	return &UserCtrl{
		users:              users,
		contacts:           contacts,
		profiles:           profiles,
		credentials:        credentials,
		passwordChangeLogs: passwordChangeLogs,
		twoFaTokens:        twoFaTokens,
		verifications:      verifications,
		otpCtrl:            otpCtrl,
		outboxRepo:         outboxRepo,
		userEventCtrl:      userEventCtrl,
		sessionCtrl:        sessionCtrl,
		geoCtrl:            geoCtrl,
		passwordHelper:     passwordHelper,
		restriction:        restriction,
		transactionManager: tm,
		recaptchaV3:        recaptchaV3,
	}
}

// Register register a new user
func (c UserCtrl) Register(ctx context.Context, in domain.UserRegisterParams) (domain.UserRegistrationResult, error) {
	logger.LogCtx(ctx).Debugf("[UserCtrl:Register][contactType:%s]", in.Contact.Type.String())

	// Validate reCAPTCHA v3 token
	if config.Commons().IsProduction() && !c.recaptchaV3.IsTokenValid(ctx, in.Recaptcha) {
		return domain.UserRegistrationResult{}, svcErrors.New(
			svcErrors.RecaptchaValidationError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register][err: recaptcha token is invalid]")),
		)
	}

	userCountry, userTimezone, prepErr := c.prepareRegistrationContext(ctx, in.SessionClientDeviceData.IPAddress)
	if prepErr != nil {
		if prepErr.Cause != nil {
			prepErr.SetCause(fmt.Errorf("[UserCtrl:Register]%w", prepErr.Cause))
		}
		return domain.UserRegistrationResult{}, prepErr
	}

	// Normalized before the existence check, so a differently-capitalised address
	// is recognized as the one already registered instead of opening a second
	// account on the same mailbox.
	in.Contact.Value = domain.NormalizeContactValue(in.Contact.Value)

	// Ensure contact is not already registered
	isContactExist, errContactExist := c.contacts.ExistsForTypeAndValue(ctx, in.Contact.Type, in.Contact.Value)
	if errContactExist != nil {
		return domain.UserRegistrationResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", errContactExist)),
		)
	}
	if isContactExist {
		return domain.UserRegistrationResult{}, svcErrors.New(
			svcErrors.UserRegistrationContactAlreadyUsedError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register][err: contact exists]")),
		)
	}

	// Hashed before the transaction opens. bcrypt is deliberately slow -- around
	// 45ms here, more on a server core -- and it depends on nothing the
	// transaction reads, so running it inside would pin a pooled connection for
	// the duration of a pure CPU burn.
	passwordHash, errHash := c.passwordHelper.Hash(in.Password)
	if errHash != nil {
		return domain.UserRegistrationResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", errHash)),
		)
	}

	var err error
	ctx = c.transactionManager.Begin(ctx)

	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[UserCtrl:Register][Rollback]%s", err)
			if errRollback := c.transactionManager.Rollback(ctx); errRollback != nil {
				logger.LogCtx(ctx).Errorf("[UserCtrl:Register][Rollback]%s", errRollback)
			}
		}
	}()

	user := domain.NewUserForRegistration()
	if err = c.users.WithTxFromContext(ctx).Create(ctx, user); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}

	contact := domain.NewContactForUser(user.ID, in.Contact)
	if err = c.contacts.WithTxFromContext(ctx).Create(ctx, contact); err != nil {
		if errors.Is(err, domain.ErrRecordExists) {
			err = svcErrors.New(
				appErrors.RecordAlreadyExistsError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:Register][err: contact exists]")),
			)
			return domain.UserRegistrationResult{}, err
		}

		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}

	profile := domain.NewProfileForUser(user.ID, userCountry, userTimezone)
	if err = c.profiles.WithTxFromContext(ctx).Create(ctx, profile); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}

	if err = c.users.WithTxFromContext(ctx).SetPrimaryContact(ctx, user.ID, contact.ID); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}
	user.SetPrimaryContact(contact.ID)

	credential := domain.NewCredential(user.ID, passwordHash, c.passwordHelper.Algorithm())
	if err = c.credentials.WithTxFromContext(ctx).Create(ctx, &credential); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}

	otpToken, errGenerateOtp := c.otpCtrl.Generate()
	if errGenerateOtp != nil {
		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", errGenerateOtp)),
		)
		return domain.UserRegistrationResult{}, err
	}

	contactVerificationTwoFactorToken := domain.NewContactVerificationToken(user.ID, contact.ID, domain.TwoFactorMethodFromContactType(contact.Type), otpToken.Hash, otpToken.Salt, otpToken.ExpiresAt)
	if err = c.twoFaTokens.WithTxFromContext(ctx).Create(ctx, &contactVerificationTwoFactorToken); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}

	// Commit Transaction
	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Register][Commit]%w", err)),
		)
		return domain.UserRegistrationResult{}, err
	}

	locale := domain.ProfileDefaultLocale
	if profile.Locale != nil {
		locale = *profile.Locale
	}

	codeDelivered := true
	if errSend := c.otpCtrl.Send(ctx, domain.OTPMessage{
		Purpose:      contactVerificationTwoFactorToken.Type.GetNotificationPurpose(),
		ContactType:  contact.Type.String(),
		ContactValue: contact.Value,
		Code:         otpToken.Code,
		Locale:       locale,
	}); errSend != nil {
		// Deliberately logged rather than returned, unlike every other OTP send in
		// this service.
		//
		// The user and their verification token are already committed at this point.
		// Returning an error here would discard the TokenUUID the client needs for
		// the resend endpoint, and re-registering is blocked by the
		// contact-already-used guard above — so the caller would be left with an
		// account they can never verify. Handing back the token and reporting the
		// failure through CodeDelivered is the only path that recovers.
		logger.LogCtx(ctx).Errorf("[UserCtrl:Register][msg: registration committed but OTP delivery failed; client must resend]%s", errSend)

		codeDelivered = false

		// DispatchedAt was stamped when the token was created, before the send was
		// attempted, so the resend cooldown is already running against a dispatch
		// that never happened. Clearing it lets the user resend immediately instead
		// of waiting out a minute for our failure.
		//
		// WithoutCancel because the request context is quite possibly dying — which
		// is one of the ways the send fails in the first place.
		if errClear := c.twoFaTokens.ClearDispatchedAt(
			context.WithoutCancel(ctx), contactVerificationTwoFactorToken.UUID,
		); errClear != nil {
			logger.LogCtx(ctx).Errorf("[UserCtrl:Register][msg: failed to clear dispatch timestamp; resend will be rate limited for one interval]%s", errClear)
		}
	}

	return domain.UserRegistrationResult{
		ContactMethod: *contact,
		TokenUUID:     contactVerificationTwoFactorToken.UUID,
		ExpiresAt:     contactVerificationTwoFactorToken.ExpiresAt,
		CodeDelivered: codeDelivered,
	}, nil
}

// prepareRegistrationContext prepares the country and timezone for registration based on IP
func (c UserCtrl) prepareRegistrationContext(ctx context.Context, ip string) (country string, timezone string, err *appErrors.ErrorResponse) {
	logger.LogCtx(ctx).Debugf("[UserCtrl:prepareRegistrationContext][ip:%s]", ip)

	// defaults
	country = domain.UserDefaultCountry
	timezone = domain.UserDefaultTimezone

	if dataGeo, errGeo := c.geoCtrl.GetGeoInfo(ip); errGeo == nil {
		country = dataGeo.CountryCode
		timezone = dataGeo.TimeZone
	} else {
		logger.LogCtx(ctx).Errorf("[UserCtrl:prepareRegistrationContext]%s", errGeo)
	}

	if !config.Commons().GeoSkipVPNCheck {
		if dataAnonymous, errAnonymous := c.geoCtrl.GetAnonymousInfo(ip); errAnonymous == nil {
			if dataAnonymous.IsAnonymous ||
				dataAnonymous.IsAnonymousVPN ||
				dataAnonymous.IsPublicProxy ||
				dataAnonymous.IsResidentialProxy ||
				dataAnonymous.IsTorExitNode {

				return "", "", svcErrors.New(
					svcErrors.UserRegistrationVPNDetectedError,
					appErrors.WithCause(fmt.Errorf("[prepareRegistrationContext][err: registration from anonymous network not allowed]")),
				)
			}
		} else {
			logger.LogCtx(ctx).Errorf("[UserCtrl:prepareRegistrationContext]%s", errAnonymous)
		}
	}

	isAllow, errRestriction := c.restriction.IsGeoAllow(ctx, country, restriction.GeoFilterOperationTypeRegistration)
	if errRestriction != nil {
		return "", "", svcErrors.New(
			appErrors.ExternalServiceError,
			appErrors.WithCause(fmt.Errorf("[prepareRegistrationContext]%w", errRestriction)),
		)
	}
	if !isAllow {
		return "", "", svcErrors.New(
			svcErrors.UserRegistrationCountryNotAllowedError,
			appErrors.WithCause(fmt.Errorf("[prepareRegistrationContext][err: operation not allowed in country %s]", country)),
		)
	}

	return country, timezone, nil
}

// VerifyContact confirms the OTP provided for a contact method and activates the user when successful.
func (c UserCtrl) VerifyContact(ctx context.Context, in domain.ContactVerifyParams) error {
	logger.LogCtx(ctx).Debugf("[UserCtrl:VerifyContact][hasTokenUUID:%t]", in.TokenUUID != "")

	now := time.Now().UTC()

	var err error
	ctx = c.transactionManager.Begin(ctx)
	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)
			if errRollback := c.transactionManager.Rollback(ctx); errRollback != nil {
				logger.LogCtx(ctx).Errorf("[UserCtrl:VerifyContact][Rollback]%s", errRollback)
			}
		}
	}()

	contactVerificationTwoFactorToken, errFindForUpdate := c.twoFaTokens.WithTxFromContext(ctx).FindByUUIDAndTypeForUpdate(ctx, in.TokenUUID, domain.TwoFactorTokenTypeVerifyContact)
	if errFindForUpdate != nil {
		switch {
		case errors.Is(errFindForUpdate, domain.ErrRecordNotFound):
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", errFindForUpdate)),
			)
			return err
		case errors.Is(errFindForUpdate, domain.ErrConcurrencyConflict):
			err = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", errFindForUpdate)),
			)
			return err
		default:
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", errFindForUpdate)),
			)
			return err
		}
	}

	if contactVerificationTwoFactorToken.IsConsumed() {
		err = svcErrors.New(
			svcErrors.CodeConsumedError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][err: verification already consumed]")),
		)
		return err
	}

	if contactVerificationTwoFactorToken.IsExpired() {
		err = svcErrors.New(
			svcErrors.CodeExpiredError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][err: verification expired]")),
		)
		return err
	}

	remainingAttempts := contactVerificationTwoFactorToken.AttemptsLeft()
	if remainingAttempts == 0 {
		err = svcErrors.New(
			svcErrors.CodeAttemptsExceededError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][err: attempts exceeded]")),
		)
		return err
	}

	if !c.otpCtrl.Verify(in.Code, contactVerificationTwoFactorToken.CodeSalt, contactVerificationTwoFactorToken.CodeHash) {
		if err = c.twoFaTokens.WithTxFromContext(ctx).IncrementAttempts(ctx, contactVerificationTwoFactorToken.UUID); err != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", err)),
			)
			return err
		}

		if err = c.transactionManager.Commit(ctx); err != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][Commit]%w", err)),
			)
			return err
		}

		return svcErrors.New(
			svcErrors.CodeInvalidError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][err: invalid verification code]")),
		)
	}

	if contactVerificationTwoFactorToken.ContactID == nil {
		err = svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][err: contact id is nil]")),
		)
		return err
	}

	if err = c.twoFaTokens.WithTxFromContext(ctx).Consume(ctx, contactVerificationTwoFactorToken.UUID, true /*incAttempt*/); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", err)),
		)
		return err
	}

	if err = c.contacts.WithTxFromContext(ctx).MarkVerified(ctx, *contactVerificationTwoFactorToken.ContactID, now); err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", err)),
			)
			return err
		}

		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", err)),
		)
		return err
	}

	if err = c.users.WithTxFromContext(ctx).ActivateIfPendingByUserID(ctx, contactVerificationTwoFactorToken.UserID); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact]%w", err)),
		)
		return err
	}

	// The lifecycle event is an outbox row written inside this transaction, not a
	// publish after it. It used to be best-effort, so a failed publish left the
	// user activated here while restriction-service never learned they existed and
	// never assigned a tier — with only a log line to show for it.
	if errOutbox := c.outboxRepo.Create(ctx, domain.NewUserCreatedOutboxParams(
		contactVerificationTwoFactorToken.UserID, now,
	)); errOutbox != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][outbox]%w", errOutbox)),
		)
		return err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:VerifyContact][Commit]%w", err)),
		)
		return err
	}

	return nil
}

// UpdateProfile updates profile data of the selected user.
func (c UserCtrl) UpdateProfile(ctx context.Context, in domain.UpdateProfileParams) error {
	logger.LogCtx(ctx).Debugf("[UserCtrl:UpdateProfile][userID:%d]", in.UserID)

	if err := c.profiles.WithTxFromContext(ctx).Update(ctx, in); err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			return svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:UpdateProfile]%w", err)),
			)
		}

		return svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:UpdateProfile]%w", err)),
		)
	}

	return nil
}

// GetProfile get profile data of the selected user.
func (c UserCtrl) GetProfile(ctx context.Context, userID domain.ID) (domain.UserProfile, error) {
	logger.LogCtx(ctx).Debugf("[UserCtrl:GetProfile][userID: %d]", userID)

	user, errUser := c.users.FindByID(ctx, userID)
	if errUser != nil {
		if errors.Is(errUser, domain.ErrRecordNotFound) {
			return domain.UserProfile{}, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:GetProfile]%w", errUser)),
			)
		}

		return domain.UserProfile{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:GetProfile]%w", errUser)),
		)
	}

	profile, errProfile := c.profiles.FindByUserID(ctx, user.ID)
	if errProfile != nil {
		if errors.Is(errProfile, domain.ErrRecordNotFound) {
			return domain.UserProfile{}, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:GetProfile]%w", errProfile)),
			)
		}

		return domain.UserProfile{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:GetProfile]%w", errProfile)),
		)
	}

	userProfile := domain.UserProfile{
		UserID:            user.ID,
		UserNumber:        user.Number,
		VerificationLevel: user.VerificationLevel,
		Status:            user.Status,
		ProfileDetails:    profile,
	}

	lastVerification, errLastVerification := c.verifications.GetLast(ctx, userID)
	if errLastVerification != nil {
		if !errors.Is(errLastVerification, domain.ErrRecordNotFound) {
			return domain.UserProfile{}, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:GetProfile]%w", errLastVerification)),
			)
		}
	} else {
		userProfile.LastUserVerificationRequest = &domain.LastUserVerificationRequest{
			Status:    lastVerification.Status,
			CreatedAt: lastVerification.CreatedAt,
			UpdatedAt: lastVerification.UpdatedAt,
		}
	}

	primaryContact, errPrimaryContact := c.contacts.FindPrimaryByUser(ctx, userID)
	if errPrimaryContact != nil {
		return domain.UserProfile{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:GetProfile]%w", errPrimaryContact)),
		)
	}

	userProfile.PrimaryContact = domain.PrimaryContact{
		Type:   primaryContact.Type,
		Value:  primaryContact.Value,
		Status: primaryContact.Status,
	}

	return userProfile, nil
}

// GetByNumber gets user data of the selected number.
func (c UserCtrl) GetByNumber(ctx context.Context, number int64) (domain.User, error) {
	logger.LogCtx(ctx).Debugf("[UserCtrl:GetByNumber][number: %d]", number)

	user, errUser := c.users.FindByNumber(ctx, number)
	if errUser != nil {
		if errors.Is(errUser, domain.ErrRecordNotFound) {
			return domain.User{}, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:GetByNumber]%w", errUser)),
			)
		}

		return domain.User{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:GetByNumber]%w", errUser)),
		)
	}

	return user, nil
}

// ChangePassword rotates the user's password after verifying the current secret.
func (c UserCtrl) ChangePassword(ctx context.Context, in domain.PasswordChangeParams) error {
	logger.LogCtx(ctx).Debugf("[UserCtrl:ChangePassword][userID: %d]", in.UserID)

	// Everything bcrypt touches happens before the transaction opens -- see
	// prepareRotation.
	credential, newPasswordHash, erPrepare := c.prepareRotation(ctx, in)
	if erPrepare != nil {
		return erPrepare
	}

	var err error
	ctx = c.transactionManager.Begin(ctx)
	// The session revocation below writes to the revocation cache, which the
	// database cannot roll back. The clean map records those keys so a failed
	// transaction takes them out again -- otherwise a rollback would leave the
	// user's other sessions marked revoked in cache while they are still alive
	// in the database.
	ctx = cache.NewCleanMap(ctx)

	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)

			cache.CleanKeys(ctx)

			if errRollback := c.transactionManager.Rollback(ctx); errRollback != nil {
				logger.LogCtx(ctx).Errorf("[UserCtrl:ChangePassword]%s", errRollback)
			}
		}
	}()

	locked, errFindForUpdate := c.credentials.WithTxFromContext(ctx).FindByUserIDForUpdate(ctx, in.UserID)
	if errFindForUpdate != nil {
		switch {
		case errors.Is(errFindForUpdate, domain.ErrRecordNotFound):
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errFindForUpdate)),
			)
			return err
		case errors.Is(errFindForUpdate, domain.ErrConcurrencyConflict):
			err = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errFindForUpdate)),
			)
			return err
		default:
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errFindForUpdate)),
			)
			return err
		}
	}

	// The current password was verified against the hash read a moment ago. If
	// it has moved since, another change committed in between and the password
	// this request proved knowledge of is no longer the account's -- accepting it
	// would let a superseded password set a new one. NOWAIT serializes the two
	// requests but does not order them, so the check has to be here.
	if locked.PasswordHash != credential.PasswordHash {
		err = svcErrors.New(
			appErrors.ConcurrencyConflictError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword][err: credential changed while the password was being verified]")),
		)
		return err
	}

	credential = locked

	// Update the password hash and algorithm
	credential.PasswordHash = newPasswordHash
	credential.Algorithm = c.passwordHelper.Algorithm()

	if err = c.credentials.WithTxFromContext(ctx).Update(ctx, &credential); err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", err)),
			)
			return err
		}

		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", err)),
		)
		return err
	}

	logEntry := domain.NewPasswordChangeLog(in.UserID, in.SessionClientDeviceData)
	if errLog := c.passwordChangeLogs.WithTxFromContext(ctx).Create(ctx, &logEntry); errLog != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errLog)),
		)
		return err
	}

	// Rotating the password ends every other session, inside this transaction so
	// the two cannot disagree. A password change is what a user does after losing
	// control of a device, and leaving the old sessions alive made it a gesture:
	// a stolen refresh token outlived the rotation by up to its full 30-day TTL,
	// renewing itself the whole time.
	if er := c.revokeSessionsOnPasswordChange(ctx, in); er != nil {
		err = er
		return err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword][Commit]%w", err)),
		)
		return err
	}

	return nil
}

// prepareRotation does the expensive half of a password change with no
// transaction open: read the current credential, check the caller knows it and
// is not reusing it, and hash the replacement.
//
// Two verifies and a hash are roughly 135ms of pure CPU at cost 10. Doing that
// inside the transaction meant holding a pooled connection and a FOR UPDATE lock
// on the credential row for the whole time, for work the database has no part
// in. Reading unlocked here is what makes it possible; the re-check under the
// lock in ChangePassword is what makes it safe.
func (c UserCtrl) prepareRotation(
	ctx context.Context,
	in domain.PasswordChangeParams,
) (domain.Credential, string, *appErrors.ErrorResponse) {
	credential, errFind := c.credentials.FindByUserID(ctx, in.UserID)
	if errFind != nil {
		if errors.Is(errFind, domain.ErrRecordNotFound) {
			return domain.Credential{}, "", svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errFind)),
			)
		}

		return domain.Credential{}, "", svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errFind)),
		)
	}

	if er := c.ensurePasswordRotatable(credential, in); er != nil {
		return domain.Credential{}, "", er
	}

	newPasswordHash, errHash := c.passwordHelper.Hash(in.NewPassword)
	if errHash != nil {
		return domain.Credential{}, "", svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errHash)),
		)
	}

	return credential, newPasswordHash, nil
}

// ensurePasswordRotatable checks that the caller knows the current password and
// that the new one is not the same secret again.
func (c UserCtrl) ensurePasswordRotatable(credential domain.Credential, in domain.PasswordChangeParams) *appErrors.ErrorResponse {
	matched, errVerify := c.passwordHelper.Verify(in.CurrentPassword, credential.PasswordHash)
	if errVerify != nil {
		return svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errVerify)),
		)
	}

	if !matched {
		return svcErrors.New(
			svcErrors.PasswordChangeCurrentPasswordInvalidError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword][err: current password mismatch]")),
		)
	}

	reused, errVerifyReused := c.passwordHelper.Verify(in.NewPassword, credential.PasswordHash)
	if errVerifyReused != nil {
		return svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errVerifyReused)),
		)
	}

	if reused {
		return svcErrors.New(
			svcErrors.PasswordChangeReuseNotAllowedError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword][err: password reuse detected]")),
		)
	}

	return nil
}

// revokeSessionsOnPasswordChange ends every session of the user except the one
// performing the change, on the transaction already open in ctx.
func (c UserCtrl) revokeSessionsOnPasswordChange(ctx context.Context, in domain.PasswordChangeParams) *appErrors.ErrorResponse {
	errRevoke := c.sessionCtrl.RevokeAllOnPasswordChange(ctx, domain.AuthenticatedSession{
		UserID:                  in.UserID,
		SessionID:               in.SessionID,
		SessionClientDeviceData: in.SessionClientDeviceData,
	})
	if errRevoke == nil {
		return nil
	}

	if er, ok := appErrors.AsErrorResponse(errRevoke); ok {
		if er.Cause != nil {
			er.SetCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", er.Cause))
		}
		return er
	}

	return svcErrors.New(
		appErrors.InternalServerError,
		appErrors.WithCause(fmt.Errorf("[UserCtrl:ChangePassword]%w", errRevoke)),
	)
}

// Block marks the user blocked and ends every session they hold.
//
// Both in one transaction. They used to be separate statements, and a failure
// in between left the account flagged while its sessions kept working -- the
// status is only consulted at sign-in, so a blocked user carried on using the
// API with the tokens they already had. That is precisely the window this
// endpoint exists to close: account-service calls it when a deposit or a
// withdrawal trips AML.
func (c UserCtrl) Block(ctx context.Context, userID domain.ID) error {
	logger.LogCtx(ctx).Debugf("[UserCtrl:Block][userID: %d]", userID)

	var err error
	ctx = c.transactionManager.Begin(ctx)
	// The revocation marks the sessions in the cache, which the database cannot
	// roll back; the clean map takes those keys out again if this fails.
	ctx = cache.NewCleanMap(ctx)

	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[UserCtrl:Block][Rollback]%s", err)

			cache.CleanKeys(ctx)

			if errRollback := c.transactionManager.Rollback(ctx); errRollback != nil {
				logger.LogCtx(ctx).Errorf("[UserCtrl:Block][Rollback]%s", errRollback)
			}
		}
	}()

	if errStatus := c.users.WithTxFromContext(ctx).UpdateStatus(ctx, userID, domain.UserStatusBlockedSystem); errStatus != nil {
		if errors.Is(errStatus, domain.ErrRecordNotFound) {
			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[UserCtrl:Block]%w", errStatus)),
			)
			return err
		}

		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Block]%w", errStatus)),
		)
		return err
	}

	if erRevoke := c.sessionCtrl.RevokeAllOnBlock(ctx, userID); erRevoke != nil {
		if erRevoke.Cause != nil {
			erRevoke.SetCause(fmt.Errorf("[UserCtrl:Block]%w", erRevoke.Cause))
		}
		err = erRevoke
		return err
	}

	if err = c.transactionManager.Commit(ctx); err != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[UserCtrl:Block][Commit]%w", err)),
		)
		return err
	}

	return nil
}
