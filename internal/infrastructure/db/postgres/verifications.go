package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"user-service/internal/domain"
	"user-service/tools"

	"github.com/jackc/pgx/v5/pgconn"
	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/db"
	"github.com/whagency/core-common/logger"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type verificationSQL struct {
	ID                uint64         `gorm:"column:id;primaryKey"`
	UserID            uint64         `gorm:"column:user_id"`
	Provider          uint8          `gorm:"column:provider"`
	Status            uint8          `gorm:"column:status"`
	VerificationLevel uint8          `gorm:"column:verification_level"`
	ExternalID        string         `gorm:"column:external_id"`
	ProviderData      datatypes.JSON `gorm:"column:provider_data;type:jsonb"`
	CreatedAt         time.Time      `gorm:"column:created_at"`
	UpdatedAt         *time.Time     `gorm:"column:updated_at"`
}

// TableName specifies the table name for GORM
func (verificationSQL) TableName() string {
	return "verifications"
}

// decode converts verificationSQL to domain.Verification
func (s verificationSQL) decode() domain.Verification {
	return domain.Verification{
		ID:                domain.NewIDFromUint64(s.ID),
		UserID:            domain.NewIDFromUint64(s.UserID),
		Provider:          domain.NewVerificationProvider(s.Provider),
		Status:            domain.NewVerificationStatus(s.Status),
		VerificationLevel: domain.NewVerificationLevel(s.VerificationLevel),
		ExternalID:        s.ExternalID,
		ProviderData:      s.ProviderData,
		CreatedAt:         s.CreatedAt,
		UpdatedAt:         s.UpdatedAt,
	}
}

type VerificationRepo struct {
	db *gorm.DB
}

// NewVerificationRepository creates a new instance of VerificationRepo
func NewVerificationRepository(db *gorm.DB) *VerificationRepo {
	return &VerificationRepo{db: db}
}

// WithTxFromContext returns a new VerificationRepo with the transaction from the context
func (r VerificationRepo) WithTxFromContext(ctx context.Context) domain.VerificationRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new verification into the database
func (r VerificationRepo) Create(ctx context.Context, verification *domain.Verification) error {
	logger.LogCtx(ctx).Debugf(
		"[VerificationRepo:Create][userID:%d][provider:%s][status:%s][level:%s][hasExternalID:%t]",
		verification.UserID,
		verification.Provider.String(),
		verification.Status.String(),
		verification.VerificationLevel.String(),
		verification.ExternalID != "",
	)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeVerificationForCreate(verification)
	if err := r.db.WithContext(ctx).
		Create(row).Error; err != nil {
		// The partial unique index refuses a second open verification for the same
		// user and provider. That is a race being lost, not a failure.
		if isUniqueViolation(err) {
			return fmt.Errorf("[VerificationRepo:Create][err: %w]", domain.ErrRecordExists)
		}
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[VerificationRepo:Create][err: %w]", err)
	}

	verification.ID = domain.NewIDFromUint64(row.ID)
	return nil
}

// GetLastPendingByUserIDAndProvider retrieves the last pending verification for a given user ID
func (r VerificationRepo) GetLastPendingByUserIDAndProvider(ctx context.Context, userID domain.ID, provider domain.VerificationProvider) (domain.Verification, error) {
	logger.LogCtx(ctx).Debugf("[VerificationRepo:GetLastPendingByUserIDAndProvider][userID: %d][provider: %d]", userID, provider)
	defer tools.EndDBRequestTimer(time.Now())

	var row verificationSQL
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ? AND (status = ? OR status = ?)",
			userID.Uint64(),
			provider.Uint8(),
			domain.VerificationStatusNew.Uint8(),
			domain.VerificationStatusPending.Uint8(),
		).
		Order("created_at DESC").
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetLastPendingByUserIDAndProvider][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetLastPendingByUserIDAndProvider][err: %w]", err)
	}

	return row.decode(), nil
}

// GetLast retrieves the last verification for a given user ID
func (r VerificationRepo) GetLast(ctx context.Context, userID domain.ID) (domain.Verification, error) {
	logger.LogCtx(ctx).Debugf("[VerificationRepo:GetLast][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row verificationSQL
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID.Uint64()).
		Order("created_at DESC").
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetLast][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetLast][err: %w]", err)
	}

	return row.decode(), nil
}

// GetByProviderAndExternalIDForUpdate retrieves a verification by provider ID and external verification ID with row-level lock.
func (r VerificationRepo) GetByProviderAndExternalIDForUpdate(ctx context.Context, provider domain.VerificationProvider, externalID string) (domain.Verification, error) {
	logger.LogCtx(ctx).Debugf(
		"[VerificationRepo:GetByProviderAndExternalIDForUpdate][provider:%s][hasExternalID:%t]",
		provider.String(),
		externalID != "",
	)
	defer tools.EndDBRequestTimer(time.Now())

	var row verificationSQL
	if err := r.db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE", Options: "NOWAIT"}).
		Where("provider = ? AND external_id = ?", provider.Uint8(), externalID).
		Take(&row).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetByProviderAndExternalIDForUpdate][err: %w]", domain.ErrRecordNotFound)
		case db.IsRowLockConflict(err):
			return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetByProviderAndExternalIDForUpdate][err: %w]", domain.ErrConcurrencyConflict)
		default:
			tools.TrackMetricDBErrorAdd()
			return domain.Verification{}, fmt.Errorf("[VerificationRepo:GetByProviderAndExternalIDForUpdate][err: %w]", err)
		}
	}

	return row.decode(), nil
}

// Update updates verification with the provided data.
func (r VerificationRepo) Update(ctx context.Context, in domain.VerificationUpdateParams) error {
	logger.LogCtx(ctx).Debugf(
		"[VerificationRepo:Update][verificationID:%d][status:%s]",
		in.VerificationID,
		in.Status.String(),
	)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&verificationSQL{}).
		Where("id = ?", in.VerificationID).
		Updates(map[string]any{
			"status":     in.Status.Uint8(),
			"updated_at": time.Now().UTC(),
		}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[VerificationRepo:Update][err: %w]", err)
	}

	return nil
}

// SetProviderData stores what the provider returned against a reserved row.
//
// The row is written before the provider is called, so that a second request
// arriving at the same moment loses at the unique index rather than paying for a
// second applicant form. This is the other half of that: the reserved row is
// empty until this lands.
func (r VerificationRepo) SetProviderData(ctx context.Context, verificationID domain.ID, providerData any) error {
	logger.LogCtx(ctx).Debugf("[VerificationRepo:SetProviderData][verificationID:%d]", verificationID)
	defer tools.EndDBRequestTimer(time.Now())

	encoded, err := jsoniter.Marshal(providerData)
	if err != nil {
		return fmt.Errorf("[VerificationRepo:SetProviderData][err: %w]", err)
	}

	result := r.db.WithContext(ctx).
		Model(&verificationSQL{}).
		Where("id = ?", verificationID.Uint64()).
		Updates(map[string]any{
			"provider_data": datatypes.JSON(encoded),
			"updated_at":    time.Now().UTC(),
		})
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[VerificationRepo:SetProviderData][err: %w]", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("[VerificationRepo:SetProviderData][err: %w]", domain.ErrRecordNotFound)
	}

	return nil
}

// encodeVerificationForCreate returns a verificationSQL struct for creating a new verification
func encodeVerificationForCreate(in *domain.Verification) *verificationSQL {
	providerDataJSON, _ := in.MarshalProviderDataJSON()
	return &verificationSQL{
		UserID:            in.UserID.Uint64(),
		Provider:          in.Provider.Uint8(),
		Status:            in.Status.Uint8(),
		ExternalID:        in.ExternalID,
		VerificationLevel: in.VerificationLevel.Uint8(),
		ProviderData:      providerDataJSON,
		CreatedAt:         time.Now().UTC(),
	}
}

// _pgUniqueViolation is SQLSTATE 23505. Spelled out rather than pulling in
// pgerrcode for one constant.
const _pgUniqueViolation = "23505"

// isUniqueViolation reports whether the driver refused a write for breaking a
// unique constraint.
//
// It checks the SQLSTATE as well as gorm's translated sentinel, because the
// translation only happens when the connection was opened with
// TranslateError -- which the service does and the repository test harness does
// not. Depending on a flag set in another file for the correctness of an error
// branch is how a branch ends up working in production and untestable everywhere
// else.
func isUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == _pgUniqueViolation
	}

	return false
}
