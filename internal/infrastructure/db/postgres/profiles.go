package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"user-service/internal/domain"
	"user-service/tools"

	"github.com/whagency/core-common/db"
	"github.com/whagency/core-common/logger"
	"gorm.io/gorm"
)

// profileSQL represents the SQL model for a user profile in the database.
// It defines the structure for storing profile information such as name, country, and locale.
// Fields are mapped to specific database columns using GORM tags.
type profileSQL struct {
	ID          uint64     `gorm:"column:id;primaryKey"`
	UserID      uint64     `gorm:"column:user_id"`
	FirstName   *string    `gorm:"column:first_name"`
	LastName    *string    `gorm:"column:last_name"`
	Country     *string    `gorm:"column:country;char(2)"`
	DateOfBirth *time.Time `gorm:"column:dob"`
	Address     *string    `gorm:"column:address"`
	Locale      *string    `gorm:"column:locale"`
	Timezone    *string    `gorm:"column:timezone"`
}

// TableName returns the name of the database table associated with the profileSQL model.
func (profileSQL) TableName() string {
	return "profiles"
}

type ProfileRepo struct {
	db *gorm.DB
}

// NewProfileRepository creates a new instance of ProfileRepo
func NewProfileRepository(db *gorm.DB) *ProfileRepo {
	return &ProfileRepo{db: db}
}

// WithTxFromContext returns a new ProfileRepo with the transaction from the context
func (r ProfileRepo) WithTxFromContext(ctx context.Context) domain.ProfileRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new contact method into the database
func (r ProfileRepo) Create(ctx context.Context, profile *domain.Profile) error {
	logger.LogCtx(ctx).Debugf(
		"[ProfileRepo:Create][userID:%d][hasCountry:%t][hasTimezone:%t][hasLocale:%t]",
		profile.UserID,
		profile.Country != "",
		profile.Timezone != "",
		profile.Locale != nil,
	)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeProfileForCreate(profile)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[ProfileRepo:Create][err: %w]", err)
	}

	profile.ID = domain.NewIDFromUint64(row.ID)

	return nil
}

// Exists checks if a profile exists for the given user
func (r ProfileRepo) Exists(ctx context.Context, userID domain.ID) (bool, error) {
	logger.LogCtx(ctx).Debugf("[ProfileRepo:Exists][userID:%s]", userID.String())
	defer tools.EndDBRequestTimer(time.Now())

	var count int64
	if err := r.db.WithContext(ctx).
		Model(&profileSQL{}).
		Where("user_id = ?", userID.Uint64()).
		Count(&count).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return false, fmt.Errorf("[ProfileRepo:Exists][err: %w]", err)
	}

	return count > 0, nil
}

// FindByUserID retrieves a user's profile.
func (r ProfileRepo) FindByUserID(ctx context.Context, userID domain.ID) (domain.ProfileDetails, error) {
	logger.LogCtx(ctx).Debugf("[ProfileRepo:FindByUserID][userID:%s]", userID.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row profileSQL
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID.Uint64()).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ProfileDetails{}, fmt.Errorf("[ProfileRepo:FindByUserID][err: %w]", domain.ErrRecordNotFound)
		}

		tools.TrackMetricDBErrorAdd()
		return domain.ProfileDetails{}, fmt.Errorf("[ProfileRepo:FindByUserID][err: %w]", err)
	}

	return row.decodeDetails(), nil
}

// Update updates profile data of the selected user.
func (r ProfileRepo) Update(ctx context.Context, profile domain.UpdateProfileParams) error {
	logger.LogCtx(ctx).Debugf(
		"[ProfileRepo:Update][userID:%d][firstName:%t][lastName:%t][dob:%t][address:%t][locale:%t][timezone:%t]",
		profile.UserID,
		profile.FirstName != nil,
		profile.LastName != nil,
		profile.DateOfBirth != nil,
		profile.Address != nil,
		profile.Locale != nil,
		profile.Timezone != nil,
	)
	defer tools.EndDBRequestTimer(time.Now())

	updateData := encodeProfileForUpdate(profile)
	if len(updateData) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).
		Model(&profileSQL{}).
		Where("user_id = ?", profile.UserID.Uint64()).
		Updates(updateData)

	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[ProfileRepo:Update][err: %w]", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("[ProfileRepo:Update][err: %w]", domain.ErrRecordNotFound)
	}

	return nil
}

// encodeProfileForCreate returns a contactSQL struct for creating a new profile
func encodeProfileForCreate(profile *domain.Profile) *profileSQL {
	return &profileSQL{
		UserID:   profile.UserID.Uint64(),
		Country:  &profile.Country,
		Timezone: &profile.Timezone,
		Locale:   profile.Locale,
	}
}

// encodeProfileForUpdate encodes a UpdateProfile struct for updating profile
func encodeProfileForUpdate(profile domain.UpdateProfileParams) map[string]any {
	updateData := make(map[string]any)
	if profile.FirstName != nil {
		updateData["first_name"] = *profile.FirstName
	}
	if profile.LastName != nil {
		updateData["last_name"] = *profile.LastName
	}
	if profile.DateOfBirth != nil {
		updateData["dob"] = *profile.DateOfBirth
	}
	if profile.Address != nil {
		updateData["address"] = *profile.Address
	}
	if profile.Locale != nil {
		updateData["locale"] = *profile.Locale
	}
	if profile.Timezone != nil {
		updateData["timezone"] = *profile.Timezone
	}

	return updateData
}

// decodeDetails decodes the profileSQL struct into a domain.ProfileDetails struct
func (p profileSQL) decodeDetails() domain.ProfileDetails {
	var profile domain.ProfileDetails

	if p.Country != nil {
		profile.Country = *p.Country
	}
	if p.FirstName != nil {
		firstName := *p.FirstName
		profile.FirstName = &firstName
	}
	if p.LastName != nil {
		lastName := *p.LastName
		profile.LastName = &lastName
	}
	if p.DateOfBirth != nil {
		dob := *p.DateOfBirth
		profile.DateOfBirth = &dob
	}
	if p.Address != nil {
		address := *p.Address
		profile.Address = &address
	}
	if p.Locale != nil {
		profile.Locale = p.Locale
	} else {
		locale := domain.ProfileDefaultLocale
		profile.Locale = &locale
	}
	if p.Timezone != nil {
		timezone := *p.Timezone
		profile.Timezone = &timezone
	}

	return profile
}
