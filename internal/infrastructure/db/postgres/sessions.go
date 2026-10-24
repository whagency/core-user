package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"user-service/internal/domain"
	"user-service/tools"

	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/db"
	"github.com/whagency/core-common/logger"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type sessionSQL struct {
	UUID             string         `gorm:"column:uuid;primaryKey"`
	Expire           int64          `gorm:"column:expire"`
	UserID           uint64         `gorm:"column:user_id"`
	RefreshTokenHash string         `gorm:"column:refresh_token"`
	RefreshExpire    int64          `gorm:"column:refresh_expire"`
	IP               string         `gorm:"column:ip"`
	Agent            string         `gorm:"column:agent"`
	Browser          string         `gorm:"column:browser"`
	Device           string         `gorm:"column:device"`
	City             string         `gorm:"column:city"`
	Region           string         `gorm:"column:region"`
	AnonymousData    datatypes.JSON `gorm:"column:anonymous_data;type:jsonb"`
	CreatedAt        time.Time      `gorm:"column:created_at"`
	LastActivityAt   *time.Time     `gorm:"column:last_activity_at"`
}

// TableName sets the insert table name for this struct type
func (sessionSQL) TableName() string {
	return "sessions"
}

// decode converts sessionSQL to domain.Session
func (s sessionSQL) decode() domain.Session {
	var expireAt *time.Time
	if s.Expire > 0 {
		t := time.Unix(s.Expire, 0).UTC()
		expireAt = &t
	}

	var refreshAt *time.Time
	if s.RefreshExpire > 0 {
		t := time.Unix(s.RefreshExpire, 0).UTC()
		refreshAt = &t
	}

	return domain.Session{
		UUID:             domain.SessionID(s.UUID),
		ExpireAt:         expireAt,
		RefreshExpireAt:  refreshAt,
		UserID:           domain.NewIDFromUint64(s.UserID),
		RefreshTokenHash: s.RefreshTokenHash,
		SessionClientDeviceData: domain.SessionClientDeviceData{
			IPAddress: s.IP,
			UserAgent: s.Agent,
			Browser:   s.Browser,
			Device:    s.Device,
		},
		CreatedAt:      s.CreatedAt,
		LastActivityAt: s.LastActivityAt,
	}
}

type SessionRepo struct {
	db *gorm.DB
}

// NewSessionRepository creates a new instance of SessionRepo
func NewSessionRepository(db *gorm.DB) *SessionRepo {
	return &SessionRepo{db: db}
}

// WithTxFromContext returns a new SessionRepo with the transaction from the context
func (r SessionRepo) WithTxFromContext(ctx context.Context) domain.SessionRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new session into the database
func (r SessionRepo) Create(ctx context.Context, session *domain.Session) error {
	logger.LogCtx(ctx).Debugf(
		"[SessionRepo:Create][uuid:%s][userID:%d][hasExpireAt:%t][hasRefreshExpireAt:%t]",
		session.UUID,
		session.UserID,
		session.ExpireAt != nil,
		session.RefreshExpireAt != nil,
	)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeSessionForCreate(ctx, session)
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[SessionRepo:Create][err: %w]", err)
	}

	return nil
}

// encodeSessionForCreate returns a sessionSQL struct for creating a new session
func encodeSessionForCreate(ctx context.Context, in *domain.Session) *sessionSQL {
	var expire int64
	if in.ExpireAt != nil {
		expire = in.ExpireAt.Unix()
	}

	var refreshExpire int64
	if in.RefreshExpireAt != nil {
		refreshExpire = in.RefreshExpireAt.Unix()
	}

	anonymousData, err := jsoniter.Marshal(in.AnonymousInfo)
	if err != nil {
		logger.LogCtx(ctx).Errorf("[encodeSessionForCreate]%s", err)
	}

	// A refresh writes a new row for the same login, so created_at comes from
	// the session being continued when there is one. last_activity_at is always
	// now: this write is the activity.
	now := time.Now().UTC()
	createdAt := now
	if !in.CreatedAt.IsZero() {
		createdAt = in.CreatedAt.UTC()
	}

	return &sessionSQL{
		UUID:             in.UUID.String(),
		Expire:           expire,
		UserID:           in.UserID.Uint64(),
		RefreshTokenHash: in.RefreshTokenHash,
		RefreshExpire:    refreshExpire,
		IP:               in.IPAddress,
		Agent:            in.UserAgent,
		Browser:          in.Browser,
		Device:           in.Device,
		City:             in.City,
		Region:           in.CountryName,
		AnonymousData:    anonymousData,
		CreatedAt:        createdAt,
		LastActivityAt:   &now,
	}
}

// FindByUUID retrieves a session by its unique identifier
func (r SessionRepo) FindByUUID(ctx context.Context, uuid domain.SessionID) (domain.Session, error) {
	logger.LogCtx(ctx).Debugf("[SessionRepo:FindByUUID][uuid: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	var row sessionSQL
	if err := r.db.WithContext(ctx).Where("uuid = ?", uuid.String()).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Session{}, fmt.Errorf("[SessionRepo:FindByUUID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.Session{}, fmt.Errorf("[SessionRepo:FindByUUID][err: %w]", err)
	}

	return row.decode(), nil
}

// FindByUUIDForUpdate retrieves a session by its unique identifier with a row-level lock.
func (r SessionRepo) FindByUUIDForUpdate(ctx context.Context, uuid domain.SessionID) (domain.Session, error) {
	logger.LogCtx(ctx).Debugf("[SessionRepo:FindByUUIDForUpdate][uuid: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	var row sessionSQL
	err := r.db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE", Options: "NOWAIT"}).
		Where("uuid = ?", uuid.String()).
		Take(&row).Error
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return domain.Session{}, fmt.Errorf("[SessionRepo:FindByUUIDForUpdate][err: %w]", domain.ErrRecordNotFound)
		case db.IsRowLockConflict(err):
			return domain.Session{}, fmt.Errorf("[SessionRepo:FindByUUIDForUpdate][err: %w]", domain.ErrConcurrencyConflict)
		default:
			tools.TrackMetricDBErrorAdd()
			return domain.Session{}, fmt.Errorf("[SessionRepo:FindByUUIDForUpdate][err: %w]", err)
		}
	}

	return row.decode(), nil
}

// ListByUserID retrieves a list of sessions for a given user
func (r SessionRepo) ListByUserID(ctx context.Context, userID domain.ID) ([]domain.Session, error) {
	logger.LogCtx(ctx).Debugf("[SessionRepo:ListByUserID][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var rows []sessionSQL
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID.Uint64()).Find(&rows).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return nil, fmt.Errorf("[SessionRepo:ListByUserID][err: %w]", err)
	}

	sessions := make([]domain.Session, 0, len(rows))
	for _, row := range rows {
		sessions = append(sessions, row.decode())
	}

	return sessions, nil
}

// DeleteByUUID deletes a session by its unique identifier
func (r SessionRepo) DeleteByUUID(ctx context.Context, uuid domain.SessionID) error {
	logger.LogCtx(ctx).Debugf("[SessionRepo:DeleteByUUID][uuid: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	result := r.db.WithContext(ctx).Where("uuid = ?", uuid.String()).Delete(&sessionSQL{})
	if err := result.Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[SessionRepo:DeleteByUUID][err: %w]", err)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("[SessionRepo:DeleteByUUID][err: %w]", domain.ErrRecordNotFound)
	}

	return nil
}

// DeleteByUserID deletes all sessions for a given user
func (r SessionRepo) DeleteByUserID(ctx context.Context, userID domain.ID) error {
	logger.LogCtx(ctx).Debugf("[SessionRepo:DeleteByUserID][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).Where("user_id = ?", userID.Uint64()).Delete(&sessionSQL{}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[SessionRepo:DeleteByUserID][err: %w]", err)
	}

	return nil
}

// DeleteUnusableBefore removes sessions whose access and refresh windows have
// both closed.
//
// expire and refresh_expire are unix seconds, and either can be 0 when the
// session was written without that window, so the comparison takes the later of
// the two. A row past both is dead: it cannot authenticate and it cannot
// refresh.
func (r SessionRepo) DeleteUnusableBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	logger.LogCtx(ctx).Debugf("[SessionRepo:DeleteUnusableBefore][cutoff: %s]", cutoff.Format(time.RFC3339))
	defer tools.EndDBRequestTimer(time.Now())

	result := r.db.WithContext(ctx).
		Where("GREATEST(expire, refresh_expire) < ?", cutoff.Unix()).
		Delete(&sessionSQL{})
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return 0, fmt.Errorf("[SessionRepo:DeleteUnusableBefore][err: %w]", result.Error)
	}

	return result.RowsAffected, nil
}
