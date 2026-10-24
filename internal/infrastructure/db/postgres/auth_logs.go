package postgres

import (
	"context"
	"fmt"
	"time"

	"user-service/internal/domain"
	"user-service/tools"

	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/db"
	"github.com/whagency/core-common/logger"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type authLogSQL struct {
	ID            uint64         `gorm:"column:id;primaryKey;autoIncrement"`
	UserID        *uint64        `gorm:"column:user_id"`
	IP            string         `gorm:"column:ip"`
	Agent         string         `gorm:"column:agent"`
	Browser       string         `gorm:"column:browser"`
	Device        string         `gorm:"column:device"`
	City          string         `gorm:"column:city"`
	Region        string         `gorm:"column:region"`
	AnonymousData datatypes.JSON `gorm:"column:anonymous_data;type:jsonb"`
	Status        uint8          `gorm:"column:status"`
	CreatedAt     time.Time      `gorm:"column:created_at"`
}

// TableName sets the insert table name for this struct type
func (authLogSQL) TableName() string {
	return "auth_logs"
}

// decode decodes the auth log from the database
func (a authLogSQL) decode() domain.AuthLog {
	var userID domain.ID
	if a.UserID != nil {
		userID = domain.NewIDFromUint64(*a.UserID)
	}

	return domain.AuthLog{
		ID:     a.ID,
		UserID: userID,
		SessionClientDeviceData: domain.SessionClientDeviceData{
			IPAddress: a.IP,
			UserAgent: a.Agent,
			Browser:   a.Browser,
			Device:    a.Device,
		},
		Status:    domain.AuthLogStatus(a.Status),
		CreatedAt: a.CreatedAt,
	}
}

type AuthLogRepo struct {
	db *gorm.DB
}

// NewAuthLogRepository creates a new instance of AuthLogRepo
func NewAuthLogRepository(db *gorm.DB) *AuthLogRepo {
	return &AuthLogRepo{db: db}
}

// WithTxFromContext returns a new AuthLogRepo with the transaction from the context
func (r AuthLogRepo) WithTxFromContext(ctx context.Context) domain.AuthLogRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new auth log into the database
func (r AuthLogRepo) Create(ctx context.Context, log *domain.AuthLog) error {
	logger.LogCtx(ctx).Debugf("[AuthLogRepo:Create][userID: %d][status: %d]", log.UserID, log.Status)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeAuthLogForCreate(log)
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[AuthLogRepo:Create][err: %w]", err)
	}

	log.ID = row.ID
	return nil
}

// encodeAuthLogForCreate  encodes the auth log for creating a new auth log
func encodeAuthLogForCreate(in *domain.AuthLog) *authLogSQL {
	var userID *uint64
	if in.UserID != 0 {
		id := in.UserID.Uint64()
		userID = &id
	}

	anonymousData, err := jsoniter.Marshal(in.AnonymousInfo)
	if err != nil {
		logger.Log().Errorf("[encodeAuthLogForCreate]%w", err)
	}

	return &authLogSQL{
		ID:            in.ID,
		UserID:        userID,
		IP:            in.IPAddress,
		Agent:         in.UserAgent,
		Browser:       in.Browser,
		Device:        in.Device,
		City:          in.City,
		Region:        in.CountryName,
		AnonymousData: anonymousData,
		Status:        in.Status.Uint8(),
		CreatedAt:     time.Now().UTC(),
	}
}
