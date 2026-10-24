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

type passwordChangeLogSQL struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	UserID    uint64    `gorm:"column:user_id"`
	IP        string    `gorm:"column:ip"`
	UserAgent string    `gorm:"column:user_agent"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

// TableName returns the associated table for the password change log entity.
func (passwordChangeLogSQL) TableName() string {
	return "password_change_logs"
}

// decode converts a passwordChangeLogSQL instance to a domain.PasswordChangeLog.
func (p passwordChangeLogSQL) decode() domain.PasswordChangeLog {
	return domain.PasswordChangeLog{
		ID:        p.ID,
		UserID:    domain.NewIDFromUint64(p.UserID),
		IPAddress: p.IP,
		UserAgent: p.UserAgent,
		CreatedAt: p.CreatedAt,
	}
}

type PasswordChangeLogRepo struct {
	db *gorm.DB
}

// NewPasswordChangeLogRepository creates a new repository for password change log entries.
func NewPasswordChangeLogRepository(db *gorm.DB) *PasswordChangeLogRepo {
	return &PasswordChangeLogRepo{db: db}
}

// WithTxFromContext returns a repository bound to the transaction stored in the context, if any.
func (r PasswordChangeLogRepo) WithTxFromContext(ctx context.Context) domain.PasswordChangeLogRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create stores a new password change log entry.
func (r PasswordChangeLogRepo) Create(ctx context.Context, log *domain.PasswordChangeLog) error {
	logger.LogCtx(ctx).Debugf("[PasswordChangeLogRepo:Create][userID: %d]", log.UserID)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodePasswordChangeLogForCreate(log)
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[PasswordChangeLogRepo:Create][err: %w]", err)
	}

	log.ID = row.ID
	log.CreatedAt = row.CreatedAt
	return nil
}

// FindLastByUserID returns the latest password change log for the given user.
func (r PasswordChangeLogRepo) FindLastByUserID(ctx context.Context, userID domain.ID) (domain.PasswordChangeLog, error) {
	logger.LogCtx(ctx).Debugf("[PasswordChangeLogRepo:FindLastByUserID][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row passwordChangeLogSQL
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID.Uint64()).
		Order("created_at DESC").
		Take(&row).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.PasswordChangeLog{}, fmt.Errorf("[PasswordChangeLogRepo:FindLastByUserID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.PasswordChangeLog{}, fmt.Errorf("[PasswordChangeLogRepo:FindLastByUserID][err: %w]", err)
	}

	return row.decode(), nil
}

// encodePasswordChangeLogForCreate converts a domain.PasswordChangeLog to a passwordChangeLogSQL for database insertion.
func encodePasswordChangeLogForCreate(in *domain.PasswordChangeLog) *passwordChangeLogSQL {
	return &passwordChangeLogSQL{
		ID:        in.ID,
		UserID:    in.UserID.Uint64(),
		IP:        in.IPAddress,
		UserAgent: in.UserAgent,
		CreatedAt: time.Now().UTC(),
	}
}
