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

type contactSQL struct {
	ID         uint64     `gorm:"column:id;primaryKey"`
	UserID     uint64     `gorm:"column:user_id"`
	Type       uint8      `gorm:"column:type"`
	Value      string     `gorm:"column:value"`
	Status     uint8      `gorm:"column:status"`
	IsPrimary  bool       `gorm:"column:is_primary"`
	VerifiedAt *time.Time `gorm:"column:verified_at"`
	CreatedAt  time.Time  `gorm:"column:created_at"`
	UpdatedAt  *time.Time `gorm:"column:updated_at"`
}

// TableName sets the insert table name for this struct type
func (contactSQL) TableName() string {
	return "contacts"
}

// decode converts contactSQL to domain.ContactMethod
func (c contactSQL) decode() domain.ContactMethod {
	return domain.ContactMethod{
		ID:         domain.NewIDFromUint64(c.ID),
		UserID:     domain.NewIDFromUint64(c.UserID),
		Type:       domain.NewContactType(c.Type),
		Value:      c.Value,
		Status:     domain.NewContactStatus(c.Status),
		IsPrimary:  c.IsPrimary,
		VerifiedAt: c.VerifiedAt,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}

type ContactRepo struct {
	db *gorm.DB
}

// NewContactRepository creates a new instance of ContactRepo
func NewContactRepository(db *gorm.DB) *ContactRepo {
	return &ContactRepo{db: db}
}

// WithTxFromContext returns a new ContactRepo with the transaction from the context
func (r ContactRepo) WithTxFromContext(ctx context.Context) domain.ContactRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// ExistsForTypeAndValue checks if a contact method exists for the given type and value
func (r ContactRepo) ExistsForTypeAndValue(ctx context.Context, contactType domain.ContactType, value string) (bool, error) {
	logger.LogCtx(ctx).Debugf("[ContactRepo:ExistsForTypeAndValue][type:%s][valueLen:%d]", contactType.String(), len(value))
	defer tools.EndDBRequestTimer(time.Now())

	var count int64
	if err := r.db.WithContext(ctx).
		Model(&contactSQL{}).
		Where("type = ? AND value = ?", contactType.Uint8(), value).
		Count(&count).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return false, fmt.Errorf("[ContactRepo:ExistsForTypeAndValue][err: %w]", err)
	}

	return count > 0, nil
}

// Create inserts a new contact method into the database
func (r ContactRepo) Create(ctx context.Context, contact *domain.ContactMethod) error {
	logger.LogCtx(ctx).Debugf(
		"[ContactRepo:Create][userID:%d][type:%s][status:%s][isPrimary:%t][valueLen:%d]",
		contact.UserID,
		contact.Type.String(),
		contact.Status.String(),
		contact.IsPrimary,
		len(contact.Value),
	)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeContactForCreate(contact)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return fmt.Errorf("[ContactRepo:Create][err: %w]", domain.ErrRecordExists)
		}
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[ContactRepo:Create][err: %w]", err)
	}

	contact.ID = domain.NewIDFromUint64(row.ID)
	contact.CreatedAt = row.CreatedAt

	return nil
}

// encodeContactForCreate returns a contactSQL struct for creating a new contact method
func encodeContactForCreate(contact *domain.ContactMethod) *contactSQL {
	return &contactSQL{
		UserID:    contact.UserID.Uint64(),
		Type:      contact.Type.Uint8(),
		Value:     contact.Value,
		Status:    contact.Status.Uint8(),
		IsPrimary: contact.IsPrimary,
		CreatedAt: time.Now().UTC(),
	}
}

// FindByID retrieves a contact method by its identifier.
func (r ContactRepo) FindByID(ctx context.Context, id domain.ID) (domain.ContactMethod, error) {
	logger.LogCtx(ctx).Debugf("[ContactRepo:FindByID][id: %s]", id.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row contactSQL
	if err := r.db.WithContext(ctx).Where("id = ?", id.Uint64()).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindByID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindByID][err: %w]", err)
	}

	return row.decode(), nil
}

// FindByValue retrieves a contact method by its unique value.
func (r ContactRepo) FindByValue(ctx context.Context, value string) (domain.ContactMethod, error) {
	logger.LogCtx(ctx).Debugf("[ContactRepo:FindByValue][valueLen:%d]", len(value))
	defer tools.EndDBRequestTimer(time.Now())

	var row contactSQL
	if err := r.db.WithContext(ctx).
		Where("value = ?", value).
		Order("is_primary DESC, id ASC").
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindByValue][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindByValue][err: %w]", err)
	}

	return row.decode(), nil
}

// MarkVerified marks a contact method as verified.
func (r ContactRepo) MarkVerified(ctx context.Context, contactID domain.ID, now time.Time) error {
	logger.LogCtx(ctx).Debugf("[ContactRepo:MarkVerified][contactID: %d]", contactID)
	defer tools.EndDBRequestTimer(time.Now())

	result := r.db.WithContext(ctx).
		Model(&contactSQL{}).
		Where("id = ? AND status <> ?", contactID.Uint64(), domain.ContactStatusVerified.Uint8()).
		Updates(map[string]any{
			"status":      domain.ContactStatusVerified.Uint8(),
			"verified_at": now,
			"updated_at":  now,
		})
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[ContactRepo:MarkVerified][err: %w]", result.Error)
	}

	if result.RowsAffected == 0 {
		var count int64
		if err := r.db.WithContext(ctx).
			Model(&contactSQL{}).
			Where("id = ?", contactID.Uint64()).
			Count(&count).Error; err != nil {
			tools.TrackMetricDBErrorAdd()
			return fmt.Errorf("[ContactRepo:MarkVerified][err: %w]", err)
		}
		if count == 0 {
			return fmt.Errorf("[ContactRepo:MarkVerified][err: %w]", domain.ErrRecordNotFound)
		}
	}

	return nil
}

// FindPrimaryByValue retrieves the primary contact method by its unique value.
func (r ContactRepo) FindPrimaryByValue(ctx context.Context, value string) (domain.ContactMethod, error) {
	logger.LogCtx(ctx).Debugf("[ContactRepo:FindPrimaryByValue][valueLen:%d]", len(value))
	defer tools.EndDBRequestTimer(time.Now())

	var row contactSQL
	if err := r.db.WithContext(ctx).
		Where("value = ? and is_primary = ?", value, true).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindPrimaryByValue][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindPrimaryByValue][err: %w]", err)
	}

	return row.decode(), nil
}

// FindPrimaryByUserAndType fetches the primary contact for the given user and type.
func (r ContactRepo) FindPrimaryByUserAndType(ctx context.Context, userID domain.ID, contactType domain.ContactType) (domain.ContactMethod, error) {
	logger.LogCtx(ctx).Debugf("[ContactRepo:FindPrimaryByUserAndType][userID:%d][type:%s]", userID, contactType.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row contactSQL
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ? AND is_primary = ?", userID.Uint64(), contactType.Uint8(), true).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindPrimaryByUserAndType][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindPrimaryByUserAndType][err: %w]", err)
	}

	return row.decode(), nil
}

// FindPrimaryByUser fetches the primary contact for the given user.
func (r ContactRepo) FindPrimaryByUser(ctx context.Context, userID domain.ID) (domain.ContactMethod, error) {
	logger.LogCtx(ctx).Debugf("[ContactRepo:FindPrimaryByUser][userID:%d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row contactSQL
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND is_primary = ?", userID.Uint64(), true).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindPrimaryByUser][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.ContactMethod{}, fmt.Errorf("[ContactRepo:FindPrimaryByUser][err: %w]", err)
	}

	return row.decode(), nil
}
