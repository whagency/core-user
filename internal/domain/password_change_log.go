package domain

import (
	"context"
	"time"
)

// PasswordChangeLog captures metadata about a password rotation event.
type PasswordChangeLog struct {
	ID        uint64
	UserID    ID
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

// NewPasswordChangeLog constructs a log entry using the provided context data.
func NewPasswordChangeLog(userID ID, deviceData SessionClientDeviceData) PasswordChangeLog {
	return PasswordChangeLog{
		UserID:    userID,
		IPAddress: deviceData.IPAddress,
		UserAgent: deviceData.UserAgent,
	}
}

// PasswordChangeLogRepository persists password change log entries.
type PasswordChangeLogRepository interface {
	Create(context.Context, *PasswordChangeLog) error
	FindLastByUserID(context.Context, ID) (PasswordChangeLog, error)

	WithTxFromContext(context.Context) PasswordChangeLogRepository
}
