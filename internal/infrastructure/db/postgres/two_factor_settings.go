package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"user-service/internal/domain"
	"user-service/tools"

	"github.com/whagency/core-common/db"
	"github.com/whagency/core-common/logger"
	"gorm.io/gorm"
)

type twoFactorSettingsSQL struct {
	UserID          uint64         `gorm:"column:user_id;primaryKey"`
	ContactID       *uint64        `gorm:"column:contact_id"`
	Method          uint8          `gorm:"column:method"`
	Secret          sql.NullString `gorm:"column:secret"`
	LastTOTPCounter int64          `gorm:"column:last_totp_counter"`
	CreatedAt       time.Time      `gorm:"column:created_at"`
}

// TableName specifies the table name for GORM
func (twoFactorSettingsSQL) TableName() string {
	return "two_factor_settings"
}

// decode converts twoFactorSettingsSQL to domain.TwoFactorSettings
func (s twoFactorSettingsSQL) decode() domain.TwoFactorSettings {
	settings := domain.TwoFactorSettings{
		UserID:          domain.NewIDFromUint64(s.UserID),
		Method:          domain.TwoFactorMethod(s.Method),
		LastTOTPCounter: s.LastTOTPCounter,
		CreatedAt:       s.CreatedAt,
	}
	if s.ContactID != nil {
		id := domain.NewIDFromUint64(*s.ContactID)
		settings.ContactID = &id
	}
	if s.Secret.Valid {
		settings.Secret = s.Secret.String
	}

	return settings
}

type TwoFactorSettingsRepo struct {
	db *gorm.DB
}

// NewTwoFactorSettingsRepository creates a new instance of TwoFactorSettingsRepo
func NewTwoFactorSettingsRepository(db *gorm.DB) *TwoFactorSettingsRepo {
	return &TwoFactorSettingsRepo{db: db}
}

// WithTxFromContext sets the transaction from the context if it exists
func (r TwoFactorSettingsRepo) WithTxFromContext(ctx context.Context) domain.TwoFactorSettingsRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// FindByUserID retrieves the 2FA settings for a given user ID
func (r TwoFactorSettingsRepo) FindByUserID(ctx context.Context, userID domain.ID) (domain.TwoFactorSettings, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorSettingsRepo:FindByUserID][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row twoFactorSettingsSQL
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID.Uint64()).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.TwoFactorSettings{}, fmt.Errorf("[TwoFactorSettingsRepo:FindByUserID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.TwoFactorSettings{}, fmt.Errorf("[TwoFactorSettingsRepo:FindByUserID][err: %w]", err)
	}

	return row.decode(), nil
}

// Create creates the 2FA settings for a user
func (r TwoFactorSettingsRepo) Create(ctx context.Context, in *domain.TwoFactorSettings) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorSettingsRepo:Create][userID: %d][method: %s]", in.UserID, in.Method.String())
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).Create(encodeTwoFactorSettingsForCreate(in)).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorSettingsRepo:Create][err: %w]", err)
	}

	return nil
}

// encodeTwoFactorSettingsForCreate encodes domain.TwoFactorSettings into twoFactorSettingsSQL
func encodeTwoFactorSettingsForCreate(in *domain.TwoFactorSettings) *twoFactorSettingsSQL {
	row := &twoFactorSettingsSQL{
		UserID: in.UserID.Uint64(),
		Method: in.Method.Uint8(),
		// Seeded with the step that enrolment accepted, so the code the user just
		// typed cannot be turned round and used to sign in.
		LastTOTPCounter: in.LastTOTPCounter,
		CreatedAt:       time.Now().UTC(),
	}
	if in.ContactID != nil {
		contactID := in.ContactID.Uint64()
		row.ContactID = &contactID
	}
	if in.Secret != "" {
		row.Secret = sql.NullString{String: in.Secret, Valid: true}
	}

	return row
}

// Delete removes the 2FA settings for a given user ID
func (r TwoFactorSettingsRepo) Delete(ctx context.Context, userID domain.ID) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorSettingsRepo:Delete][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID.Uint64()).
		Delete(&twoFactorSettingsSQL{}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorSettingsRepo:Delete][err: %w]", err)
	}

	return nil
}

// AdvanceTOTPCounter moves the accepted time step forward, reporting whether it
// actually moved.
//
// The comparison is in the WHERE clause on purpose. Reading the stored counter
// and then writing a larger one would let two requests carrying the same code
// both read the old value and both decide they had won; here the database
// decides, and exactly one row is affected.
func (r TwoFactorSettingsRepo) AdvanceTOTPCounter(ctx context.Context, userID domain.ID, counter int64) (bool, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorSettingsRepo:AdvanceTOTPCounter][userID:%d][counter:%d]", userID, counter)
	defer tools.EndDBRequestTimer(time.Now())

	result := r.db.WithContext(ctx).
		Model(&twoFactorSettingsSQL{}).
		Where("user_id = ? AND last_totp_counter < ?", userID.Uint64(), counter).
		Update("last_totp_counter", counter)
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return false, fmt.Errorf("[TwoFactorSettingsRepo:AdvanceTOTPCounter][err: %w]", result.Error)
	}

	return result.RowsAffected == 1, nil
}
