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
	"gorm.io/gorm/clause"
)

type revokedSessionSQL struct {
	UUID             string         `gorm:"column:uuid;primaryKey"`
	UserID           uint64         `gorm:"column:user_id"`
	Reason           uint8          `gorm:"column:reason"`
	RefreshTokenHash sql.NullString `gorm:"column:refresh_token_hash"`
	CreatedAt        time.Time      `gorm:"column:created_at"`
	ExpireAt         *time.Time     `gorm:"column:expire_at"`
}

// decode converts revokedSessionSQL to domain.RevokedSession
func (r revokedSessionSQL) decode() domain.RevokedSession {
	out := domain.RevokedSession{
		UUID:      domain.SessionID(r.UUID),
		UserID:    domain.NewIDFromUint64(r.UserID),
		Reason:    domain.SessionRevocationReason(r.Reason),
		CreatedAt: r.CreatedAt,
		ExpireAt:  r.ExpireAt,
	}
	if r.RefreshTokenHash.Valid {
		out.RefreshTokenHash = r.RefreshTokenHash.String
	}

	return out
}

// TableName sets the insert table name for this struct type
func (revokedSessionSQL) TableName() string {
	return "revoked_sessions"
}

type RevokedSessionRepo struct {
	db *gorm.DB
}

// NewRevokedSessionRepository creates a new instance of RevokedSessionRepo
func NewRevokedSessionRepository(db *gorm.DB) *RevokedSessionRepo {
	return &RevokedSessionRepo{db: db}
}

// WithTxFromContext returns a new RevokedSessionRepo with the transaction from the context
func (r RevokedSessionRepo) WithTxFromContext(ctx context.Context) domain.RevokedSessionRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new revoked session into the database
func (r RevokedSessionRepo) Create(ctx context.Context, revoked *domain.RevokedSession) error {
	logger.LogCtx(ctx).Debugf("[RevokedSessionRepo:Create][sessionID: %s]", revoked.UUID)
	defer tools.EndDBRequestTimer(time.Now())

	tx := r.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(encodeRevokedSessionForCreate(revoked))
	if err := tx.Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[RevokedSessionRepo:Create][err: %w]", err)
	}

	// If nothing was inserted due to ON CONFLICT DO NOTHING, treat it as already exists
	if tx.RowsAffected == 0 {
		return fmt.Errorf("[RevokedSessionRepo:Create][err: %w]", domain.ErrRecordExists)
	}

	return nil
}

// encodeRevokedSessionForCreate converts revokedSessionSQL to domain.RevokedSession
func encodeRevokedSessionForCreate(in *domain.RevokedSession) *revokedSessionSQL {
	row := &revokedSessionSQL{
		UUID:      in.UUID.String(),
		UserID:    in.UserID.Uint64(),
		Reason:    in.Reason.Uint8(),
		CreatedAt: time.Now().UTC(),
		ExpireAt:  in.ExpireAt,
	}
	if in.RefreshTokenHash != "" {
		row.RefreshTokenHash = sql.NullString{String: in.RefreshTokenHash, Valid: true}
	}

	return row
}

// DeleteCreatedBefore removes revoked rows older than the cutoff.
//
// Keyed on created_at rather than expire_at on purpose. expire_at tracks the
// fifteen-minute access token, while the refresh token hash this row carries has
// to outlive the refresh TTL -- it is the only thing detectRefreshTokenReuse can
// compare a replayed token against.
func (r RevokedSessionRepo) DeleteCreatedBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	logger.LogCtx(ctx).Debugf("[RevokedSessionRepo:DeleteCreatedBefore][cutoff: %s]", cutoff.Format(time.RFC3339))
	defer tools.EndDBRequestTimer(time.Now())

	result := r.db.WithContext(ctx).
		Where("created_at < ?", cutoff).
		Delete(&revokedSessionSQL{})
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return 0, fmt.Errorf("[RevokedSessionRepo:DeleteCreatedBefore][err: %w]", result.Error)
	}

	return result.RowsAffected, nil
}

// FindByUUID retrieves a revoked session by its identifier.
func (r RevokedSessionRepo) FindByUUID(ctx context.Context, uuid domain.SessionID) (domain.RevokedSession, error) {
	logger.LogCtx(ctx).Debugf("[RevokedSessionRepo:FindByUUID][sessionID: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	var row revokedSessionSQL
	if err := r.db.WithContext(ctx).Where("uuid = ?", uuid.String()).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.RevokedSession{}, fmt.Errorf("[RevokedSessionRepo:FindByUUID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.RevokedSession{}, fmt.Errorf("[RevokedSessionRepo:FindByUUID][err: %w]", err)
	}

	return row.decode(), nil
}
