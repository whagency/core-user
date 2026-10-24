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

type userSQL struct {
	ID                uint64     `gorm:"column:id;primaryKey"`
	Number            uint64     `gorm:"column:user_number;->"`
	Status            uint8      `gorm:"column:status"`
	PrimaryContactID  *uint64    `gorm:"column:primary_contact_id"`
	VerificationLevel uint8      `gorm:"column:verification_level"`
	CreatedAt         time.Time  `gorm:"column:created_at"`
	UpdatedAt         *time.Time `gorm:"column:updated_at"`
	DeletedAt         *time.Time `gorm:"column:deleted_at"`
}

// TableName sets the insert table name for this struct type
func (userSQL) TableName() string {
	return "users"
}

// decode converts eventSQL to domain.Event
func (u userSQL) decode() domain.User {
	var primaryContact *domain.ID
	if u.PrimaryContactID != nil {
		id := domain.NewIDFromUint64(*u.PrimaryContactID)
		primaryContact = &id
	}

	return domain.User{
		ID:                domain.NewIDFromUint64(u.ID),
		Number:            u.Number,
		Status:            domain.NewUserStatus(u.Status),
		PrimaryContactID:  primaryContact,
		VerificationLevel: domain.NewVerificationLevel(u.VerificationLevel),
		CreatedAt:         u.CreatedAt,
		UpdatedAt:         u.UpdatedAt,
	}
}

type UserRepo struct {
	db *gorm.DB
}

// NewUserRepository creates a new instance of UserRepo
func NewUserRepository(db *gorm.DB) *UserRepo {
	return &UserRepo{db: db}
}

// WithTxFromContext returns a new UserRepo with the transaction from the context
func (r UserRepo) WithTxFromContext(ctx context.Context) domain.UserRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new user into the database
func (r UserRepo) Create(ctx context.Context, user *domain.User) error {
	logger.LogCtx(ctx).Debugf(
		"[UserRepo:Create][status:%s][verificationLevel:%s][hasPrimaryContact:%t]",
		user.Status.String(),
		user.VerificationLevel.String(),
		user.PrimaryContactID != nil,
	)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeUserForCreate(user)
	if err := r.db.WithContext(ctx).
		Create(row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[UserRepo:Create][err: %w]", err)
	}

	// Set the generated ID back to the domain user
	user.ID = domain.NewIDFromUint64(row.ID)
	user.CreatedAt = row.CreatedAt

	return nil
}

// encodeUserForCreate returns a userSQL struct for creating a new user
func encodeUserForCreate(in *domain.User) *userSQL {
	return &userSQL{
		Status:    in.Status.Uint8(),
		CreatedAt: time.Now().UTC(),
	}
}

// SetPrimaryContact sets the primary contact ID for a user
func (r UserRepo) SetPrimaryContact(ctx context.Context, userID, contactID domain.ID) error {
	logger.LogCtx(ctx).Debugf("[UserRepo:SetPrimaryContact][userID: %s][contactID: %s]", userID.String(), contactID.String())
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&userSQL{}).
		Where("id = ?", userID.Uint64()).
		Updates(map[string]any{
			"primary_contact_id": contactID.Uint64(),
			"updated_at":         time.Now().UTC(),
		}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[UserRepo:SetPrimaryContact][err: %w]", err)
	}

	return nil
}

// FindByID fetches a user aggregate by identifier.
func (r UserRepo) FindByID(ctx context.Context, id domain.ID) (domain.User, error) {
	logger.LogCtx(ctx).Debugf("[UserRepo:FindByID][userID: %s]", id.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row userSQL
	if err := r.db.WithContext(ctx).Where("id = ?", id.Uint64()).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.User{}, fmt.Errorf("[UserRepo:FindByID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.User{}, fmt.Errorf("[UserRepo:FindByID][err: %w]", err)
	}

	return row.decode(), nil
}

// FindByNumber fetches a user aggregate by number.
func (r UserRepo) FindByNumber(ctx context.Context, number int64) (domain.User, error) {
	logger.LogCtx(ctx).Debugf("[UserRepo:FindByNumber][number: %d]", number)
	defer tools.EndDBRequestTimer(time.Now())

	var row userSQL
	if err := r.db.WithContext(ctx).Where("user_number = ?", number).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.User{}, fmt.Errorf("[UserRepo:FindByNumber][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.User{}, fmt.Errorf("[UserRepo:FindByNumber][err: %w]", err)
	}

	return row.decode(), nil
}

// ActivateIfPendingByUserID activates a user if it is pending contact verification.
func (r UserRepo) ActivateIfPendingByUserID(ctx context.Context, userID domain.ID) error {
	logger.LogCtx(ctx).Debugf("[UserRepo:ActivateIfPendingByUserID][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&userSQL{}).
		Where("id = ? AND status = ?", userID.Uint64(), domain.UserStatusPendingContactVerification.Uint8()).
		Updates(map[string]any{
			"status":     domain.UserStatusActive.Uint8(),
			"updated_at": time.Now().UTC(),
		}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[UserRepo:ActivateIfPendingByUserID][err: %w]", err)
	}
	return nil
}

// UpdateStatus updates the status of a user.
func (r UserRepo) UpdateStatus(ctx context.Context, userID domain.ID, status domain.UserStatus) error {
	logger.LogCtx(ctx).Debugf("[UserRepo:UpdateStatus][userID: %d][status: %s]", userID, status.String())

	return r.updateUser(ctx, "UpdateStatus", userID, map[string]any{"status": status.Uint8()})
}

// SetVerificationLevel sets the verification level for a user.
func (r UserRepo) SetVerificationLevel(ctx context.Context, userID domain.ID, level domain.VerificationLevel) error {
	logger.LogCtx(ctx).Debugf("[UserRepo:SetVerificationLevel][userID: %d][level: %s]", userID, level.String())

	return r.updateUser(ctx, "SetVerificationLevel", userID, map[string]any{"verification_level": level.Uint8()})
}

// updateUser applies a partial update to one user row and stamps updated_at.
//
// A matched-nothing UPDATE is reported as ErrRecordNotFound rather than success.
// UpdateStatus used to swallow it, which is how blocking a user id that does not
// exist returned 200 and left the caller satisfied that someone dangerous had
// been shut out.
func (r UserRepo) updateUser(ctx context.Context, scope string, userID domain.ID, updates map[string]any) error {
	defer tools.EndDBRequestTimer(time.Now())

	updates["updated_at"] = time.Now().UTC()

	result := r.db.WithContext(ctx).
		Model(&userSQL{}).
		Where("id = ?", userID.Uint64()).
		Updates(updates)
	if err := result.Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[UserRepo:%s][err: %w]", scope, err)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("[UserRepo:%s][err: %w]", scope, domain.ErrRecordNotFound)
	}

	return nil
}
