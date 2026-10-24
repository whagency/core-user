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
	"gorm.io/gorm/clause"
)

type credentialSQL struct {
	UserID              uint64     `gorm:"column:user_id;primaryKey"`
	PasswordHash        string     `gorm:"column:password_hash"`
	Algorithm           string     `gorm:"column:algorithm"`
	PasswordUpdatedAt   *time.Time `gorm:"column:password_updated_at"`
	MustRotate          bool       `gorm:"column:must_rotate"`
	FailedLoginAttempts uint16     `gorm:"column:failed_login_attempts"`
	LoginLockedUntil    *time.Time `gorm:"column:login_locked_until"`
}

// TableName sets the insert table name for this struct type
func (credentialSQL) TableName() string {
	return "credentials"
}

// decode converts credentialSQL to domain.Credential
func (c credentialSQL) decode() domain.Credential {
	return domain.Credential{
		UserID:              domain.NewIDFromUint64(c.UserID),
		PasswordHash:        c.PasswordHash,
		Algorithm:           domain.CredentialAlgorithm(c.Algorithm),
		PasswordUpdatedAt:   c.PasswordUpdatedAt,
		MustRotate:          c.MustRotate,
		FailedLoginAttempts: c.FailedLoginAttempts,
		LoginLockedUntil:    c.LoginLockedUntil,
	}
}

type CredentialRepo struct {
	db *gorm.DB
}

// NewCredentialRepository creates a new instance of CredentialRepo
func NewCredentialRepository(db *gorm.DB) *CredentialRepo {
	return &CredentialRepo{db: db}
}

// WithTxFromContext returns a new CredentialRepo with the transaction from the context
func (r CredentialRepo) WithTxFromContext(ctx context.Context) domain.CredentialRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create stores a new credential in the database
func (r CredentialRepo) Create(ctx context.Context, credential *domain.Credential) error {
	logger.LogCtx(ctx).Debugf("[CredentialRepo:Create][userID: %d]", credential.UserID)
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeCredentialForCreate(credential)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[CredentialRepo:Create][err: %w]", err)
	}
	return nil
}

// encodeCredentialForCreate returns a credentialSQL struct for creating a new credential
func encodeCredentialForCreate(in *domain.Credential) *credentialSQL {
	return &credentialSQL{
		UserID:       in.UserID.Uint64(),
		PasswordHash: in.PasswordHash,
		Algorithm:    in.Algorithm.String(),
	}
}

// FindByUserID retrieves stored credentials for a given user.
func (r CredentialRepo) FindByUserID(ctx context.Context, userID domain.ID) (domain.Credential, error) {
	logger.LogCtx(ctx).Debugf("[CredentialRepo:FindByUserID][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row credentialSQL
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID.Uint64()).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Credential{}, fmt.Errorf("[CredentialRepo:FindByUserID][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.Credential{}, fmt.Errorf("[CredentialRepo:FindByUserID][err: %w]", err)
	}

	return row.decode(), nil
}

// Update rotates the stored password hash for the given user.
func (r CredentialRepo) Update(ctx context.Context, credential *domain.Credential) error {
	logger.LogCtx(ctx).Debugf("[CredentialRepo:UpdatePassword][userID: %d]", credential.UserID)
	defer tools.EndDBRequestTimer(time.Now())

	updateData := encodeCredentialForUpdate(credential)
	result := r.db.WithContext(ctx).
		Model(&credentialSQL{}).
		Where("user_id = ?", credential.UserID.Uint64()).
		Updates(updateData)

	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[CredentialRepo:UpdatePassword][err: %w]", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("[CredentialRepo:UpdatePassword][err: %w]", domain.ErrRecordNotFound)
	}

	return nil
}

// encodeCredentialForUpdate prepares the update map for rotating a password hash.
//
// A map rather than a struct, because Updates skips a struct's zero values. That
// silently dropped the must_rotate reset below -- the field is dormant today, so
// nothing has depended on it, but it would have bitten whoever first set it.
// Clearing the lockout has the same requirement, and for the same reason.
func encodeCredentialForUpdate(in *domain.Credential) map[string]any {
	return map[string]any{
		"password_hash":       in.PasswordHash,
		"algorithm":           in.Algorithm.String(),
		"password_updated_at": time.Now().UTC(),

		// Rotating the password releases any lockout. Whoever got here proved
		// control of the account, either by knowing the current password or by
		// answering the recovery code, so making them wait out a window that
		// someone else filled up would be punishing the wrong party.
		"must_rotate":           false,
		"failed_login_attempts": 0,
		"login_locked_until":    nil,
	}
}

// RegisterFailedLogin increments the failure counter and stamps the lock
// deadline once the policy is passed.
//
// Deliberately one statement. Two concurrent wrong guesses read-modify-writing
// the same row would both store the same increment, handing the attacker a free
// attempt for every request they run in parallel. Postgres serializes the
// increment for us, and RETURNING hands back the state that was actually
// written rather than the one we hoped for.
func (r CredentialRepo) RegisterFailedLogin(ctx context.Context, userID domain.ID, policy domain.LoginLockPolicy) (domain.Credential, error) {
	logger.LogCtx(ctx).Debugf("[CredentialRepo:RegisterFailedLogin][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row credentialSQL
	result := r.db.WithContext(ctx).
		Model(&row).
		Clauses(clause.Returning{}).
		Where("user_id = ?", userID.Uint64()).
		Updates(map[string]any{
			"failed_login_attempts": gorm.Expr("failed_login_attempts + 1"),
			"login_locked_until": gorm.Expr(
				"CASE WHEN failed_login_attempts + 1 >= ? THEN NOW() + ? * INTERVAL '1 microsecond' ELSE login_locked_until END",
				policy.MaxFailedAttempts,
				policy.LockFor.Microseconds(),
			),
		})
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return domain.Credential{}, fmt.Errorf("[CredentialRepo:RegisterFailedLogin][err: %w]", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.Credential{}, fmt.Errorf("[CredentialRepo:RegisterFailedLogin][err: %w]", domain.ErrRecordNotFound)
	}

	return row.decode(), nil
}

// ClearLoginFailures resets the counter and releases any lock.
//
// The WHERE clause keeps an ordinary sign-in from writing to the row at all,
// which is the common case by a wide margin.
func (r CredentialRepo) ClearLoginFailures(ctx context.Context, userID domain.ID) error {
	logger.LogCtx(ctx).Debugf("[CredentialRepo:ClearLoginFailures][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&credentialSQL{}).
		Where("user_id = ? AND (failed_login_attempts <> 0 OR login_locked_until IS NOT NULL)", userID.Uint64()).
		Updates(map[string]any{
			"failed_login_attempts": 0,
			"login_locked_until":    nil,
		}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[CredentialRepo:ClearLoginFailures][err: %w]", err)
	}

	return nil
}

// FindByUserIDForUpdate retrieves stored credentials for a given user with a database lock for update.
func (r CredentialRepo) FindByUserIDForUpdate(ctx context.Context, userID domain.ID) (domain.Credential, error) {
	logger.LogCtx(ctx).Debugf("[CredentialRepo:FindByUserIDForUpdate][userID: %d]", userID)
	defer tools.EndDBRequestTimer(time.Now())

	var row credentialSQL
	if err := r.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE", Options: "NOWAIT"}).Where("user_id = ?", userID.Uint64()).Take(&row).Error; err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return domain.Credential{}, fmt.Errorf("[CredentialRepo:FindByUserIDForUpdate][err: %w]", domain.ErrRecordNotFound)
		case db.IsRowLockConflict(err):
			return domain.Credential{}, fmt.Errorf("[CredentialRepo:FindByUserIDForUpdate][err: %w]", domain.ErrConcurrencyConflict)
		default:
			tools.TrackMetricDBErrorAdd()
			return domain.Credential{}, fmt.Errorf("[CredentialRepo:FindByUserIDForUpdate][err: %w]", err)
		}
	}

	return row.decode(), nil
}
