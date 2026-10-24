package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"
	svcErrors "user-service/internal/domain/errors"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

type VerificationCtrl struct {
	providers          map[domain.VerificationProvider]domain.VerificationProviderController
	userEventCtrl      domain.UserEventController
	outboxRepo         domain.OutboxRepository
	verifications      domain.VerificationRepository
	users              domain.UserRepository
	transactionManager domain.TransactionManager
	userCtrl           domain.UserController
}

// NewVerificationController creates a new instance of VerificationCtrl.
func NewVerificationController(
	providers map[domain.VerificationProvider]domain.VerificationProviderController,
	userEventCtrl domain.UserEventController,
	outboxRepo domain.OutboxRepository,
	verifications domain.VerificationRepository,
	users domain.UserRepository,
	tm domain.TransactionManager,
	userCtrl domain.UserController,
) *VerificationCtrl {
	return &VerificationCtrl{
		providers:          providers,
		userEventCtrl:      userEventCtrl,
		outboxRepo:         outboxRepo,
		verifications:      verifications,
		users:              users,
		transactionManager: tm,
		userCtrl:           userCtrl,
	}
}

// Init initializes a KYC verification process for a user.
func (c VerificationCtrl) Init(ctx context.Context, in domain.VerificationInitParams) (domain.VerificationInitResult, error) {
	logger.LogCtx(ctx).Debugf(
		"[VerificationCtrl:Init][userID:%d][provider:%s]",
		in.UserID,
		in.Provider.String(),
	)

	// Check if the provider exists
	provider, ok := c.providers[in.Provider]
	if !ok {
		return domain.VerificationInitResult{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Init][err: provider not supported]")),
		)
	}

	user, errFindUser := c.users.FindByID(ctx, in.UserID)
	if errFindUser != nil {
		if errors.Is(errFindUser, domain.ErrRecordNotFound) {
			return domain.VerificationInitResult{}, svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Init]%w", errFindUser)),
			)
		}

		return domain.VerificationInitResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Init]%w", errFindUser)),
		)
	}

	// check if the user already has the maximum verification level
	if user.VerificationLevel.IsMax() {
		return domain.VerificationInitResult{}, svcErrors.New(
			svcErrors.VerificationUserAlreadyVerifiedError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Init][err: user already has the maximum verification level]")),
		)
	}

	// Reserve the row before calling the provider.
	//
	// The old order was: look for an open verification, call the provider, insert.
	// Two requests arriving together both saw none, both paid for an applicant
	// form, and both wrote a row. Writing first means the loser of that race
	// fails at the unique index and is handed the winner's form instead of buying
	// a second one.
	verification, reserved, erReserve := c.reserveVerification(ctx, in, user.VerificationLevel+1)
	if erReserve != nil {
		if erReserve.Cause != nil {
			erReserve.SetCause(fmt.Errorf("[VerificationCtrl:Init]%w", erReserve.Cause))
		}
		return domain.VerificationInitResult{}, erReserve
	}

	// An open verification that already has its form is simply handed back --
	// this is the ordinary "the user asked twice" path.
	if !reserved && verification.ProviderData != nil {
		return domain.VerificationInitResult{ProviderData: verification.ProviderData}, nil
	}

	// Either freshly reserved, or reserved earlier by a call whose provider
	// request failed afterwards. Both want the same thing, and both reuse the
	// external id already on the row, so a retry does not orphan an applicant at
	// the provider.
	requestResult, err := provider.InitRequest(ctx, &verification, verification.VerificationLevel)
	if err != nil {
		return domain.VerificationInitResult{}, svcErrors.New(
			appErrors.ExternalServiceError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Init]%w", err)),
		)
	}

	if errSet := c.verifications.SetProviderData(ctx, verification.ID, requestResult.ProviderData); errSet != nil {
		return domain.VerificationInitResult{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Init]%w", errSet)),
		)
	}

	return domain.VerificationInitResult{
		ProviderData: requestResult.ProviderData,
	}, nil
}

// reserveVerification returns the open verification for this user and provider,
// creating one if there is none.
//
// The bool reports whether this call created it. No transaction: the partial
// unique index on (user_id, provider) for open rows is the serialization point,
// and a duplicate-key error means another request created it first -- so the
// answer is to read what they wrote, not to fail.
func (c VerificationCtrl) reserveVerification(
	ctx context.Context,
	in domain.VerificationInitParams,
	level domain.VerificationLevel,
) (domain.Verification, bool, *appErrors.ErrorResponse) {
	existing, errFind := c.verifications.GetLastPendingByUserIDAndProvider(ctx, in.UserID, in.Provider)
	if errFind != nil && !errors.Is(errFind, domain.ErrRecordNotFound) {
		return domain.Verification{}, false, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[reserveVerification]%w", errFind)),
		)
	}

	if errFind == nil {
		if existing.Status != domain.VerificationStatusNew {
			return domain.Verification{}, false, svcErrors.New(
				svcErrors.VerificationUserHasPendingError,
				appErrors.WithCause(fmt.Errorf("[reserveVerification][err: pending verification already exists]")),
			)
		}

		return existing, false, nil
	}

	verification := domain.NewVerification(in.UserID, in.Provider, level)
	errCreate := c.verifications.Create(ctx, verification)
	if errCreate == nil {
		return *verification, true, nil
	}

	if !errors.Is(errCreate, domain.ErrRecordExists) {
		return domain.Verification{}, false, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[reserveVerification]%w", errCreate)),
		)
	}

	// Lost the race. Whoever won has written the row; read theirs.
	winner, errWinner := c.verifications.GetLastPendingByUserIDAndProvider(ctx, in.UserID, in.Provider)
	if errWinner != nil {
		return domain.Verification{}, false, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[reserveVerification][err: lost the insert race but the winning row is unreadable]%w", errWinner)),
		)
	}
	if winner.Status != domain.VerificationStatusNew {
		return domain.Verification{}, false, svcErrors.New(
			svcErrors.VerificationUserHasPendingError,
			appErrors.WithCause(fmt.Errorf("[reserveVerification][err: pending verification already exists]")),
		)
	}

	return winner, false, nil
}

// Process processes KYC verification data postback from external service
func (c VerificationCtrl) Process(ctx context.Context, data domain.VerificationProcessParams) error {
	logger.LogCtx(ctx).Debugf(
		"[VerificationCtrl:Process][provider:%s][status:%s][hasExternalID:%t]",
		data.Provider.String(),
		data.Status.String(),
		data.ExternalID != "",
	)

	var txErr error
	tx := c.transactionManager.Begin(ctx)
	defer func() {
		if txErr != nil {
			logger.LogCtx(tx).Debugf("[Rollback]%s", txErr)
			if rbErr := c.transactionManager.Rollback(tx); rbErr != nil {
				logger.LogCtx(tx).Errorf("[VerificationCtrl:Process][Rollback]%s", rbErr)
			}
		}
	}()

	verification, errFind := c.verifications.WithTxFromContext(tx).GetByProviderAndExternalIDForUpdate(tx, data.Provider, data.ExternalID)
	if errFind != nil {
		switch {
		case errors.Is(errFind, domain.ErrRecordNotFound):
			txErr = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", errFind)),
			)
			return txErr

		case errors.Is(errFind, domain.ErrConcurrencyConflict):
			txErr = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", errFind)),
			)
			return txErr

		default:
			txErr = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", errFind)),
			)
			return txErr
		}
	}

	if verification.IsComplete() {
		logger.LogCtx(tx).Warnf(
			"[VerificationCtrl:Process][msg: duplicate completed verification ignored][verificationID:%d][provider:%s][hasExternalID:%t]",
			verification.ID,
			data.Provider.String(),
			data.ExternalID != "",
		)

		if txErr = c.transactionManager.Commit(tx); txErr != nil {
			txErr = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process][Commit]%w", txErr)),
			)
			return txErr
		}

		return nil
	}

	// Set the UserID in the profile update data
	data.Profile.UserID = verification.UserID

	if txErr = c.verifications.WithTxFromContext(tx).Update(tx, domain.VerificationUpdateParams{
		VerificationID: verification.ID,
		Status:         data.Status,
	}); txErr != nil {
		txErr = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", txErr)),
		)
		return txErr
	}

	if data.Status == domain.VerificationStatusCompleteYes {
		if txErr = c.users.WithTxFromContext(tx).SetVerificationLevel(tx, verification.UserID, verification.VerificationLevel); txErr != nil {
			if errors.Is(txErr, domain.ErrRecordNotFound) {
				txErr = svcErrors.New(
					appErrors.RecordNotFoundError,
					appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", txErr)),
				)
				return txErr
			}

			txErr = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", txErr)),
			)
			return txErr
		}

		if txErr = c.userCtrl.UpdateProfile(tx, data.Profile); txErr != nil {
			if er, ok := appErrors.AsErrorResponse(txErr); ok {
				if er.Cause != nil {
					er.SetCause(fmt.Errorf("[VerificationCtrl:Process]%w", er.Cause))
				}
				txErr = er
				return txErr
			}

			txErr = svcErrors.New(
				appErrors.InternalServerError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process]%w", txErr)),
			)
			return txErr
		}
	}

	// Only a passed verification changes the user's tier, so only that case emits
	// an event. The row goes inside the transaction: losing this used to mean the
	// user passed KYC while their limits stayed at the unverified tier, visible
	// only in a log line.
	if data.Status == domain.VerificationStatusCompleteYes {
		if errOutbox := c.outboxRepo.Create(tx, domain.NewUserVerifyLevelUpdatedOutboxParams(
			verification.UserID,
			verification.VerificationLevel.Uint8(),
			time.Now().UTC(),
		)); errOutbox != nil {
			txErr = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process][outbox]%w", errOutbox)),
			)
			return txErr
		}
	}

	if txErr = c.transactionManager.Commit(tx); txErr != nil {
		txErr = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[VerificationCtrl:Process][Commit]%w", txErr)),
		)
		return txErr
	}

	return nil
}
