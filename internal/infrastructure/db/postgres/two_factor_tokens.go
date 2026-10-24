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

type twoFactorTokenSQL struct {
	UUID         string         `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID       uint64         `gorm:"column:user_id"`
	ContactID    *uint64        `gorm:"column:contact_id"`
	Type         uint8          `gorm:"column:type"`
	Method       uint8          `gorm:"column:method"`
	Secret       sql.NullString `gorm:"column:secret"`
	CodeHash     sql.NullString `gorm:"column:code_hash"`
	CodeSalt     sql.NullString `gorm:"column:code_salt"`
	Attempts     uint16         `gorm:"column:attempts"`
	Status       uint8          `gorm:"column:status"`
	ConsumedAt   *time.Time     `gorm:"column:consumed_at"`
	ExpiresAt    time.Time      `gorm:"column:expires_at"`
	CreatedAt    time.Time      `gorm:"column:created_at"`
	DispatchedAt time.Time      `gorm:"column:dispatched_at"`
}

// TableName sets the insert table name for this struct type
func (twoFactorTokenSQL) TableName() string {
	return "two_factor_tokens"
}

// decode converts twoFactorTokenSQL to domain.TwoFactorToken
func (t twoFactorTokenSQL) decode() domain.TwoFactorToken {
	token := domain.TwoFactorToken{
		UUID:         t.UUID,
		UserID:       domain.NewIDFromUint64(t.UserID),
		Type:         domain.TwoFactorTokenType(t.Type),
		Method:       domain.TwoFactorMethod(t.Method),
		Attempts:     t.Attempts,
		Status:       domain.TwoFactorTokenStatus(t.Status),
		ConsumedAt:   t.ConsumedAt,
		ExpiresAt:    t.ExpiresAt,
		CreatedAt:    t.CreatedAt,
		DispatchedAt: t.DispatchedAt,
	}
	if t.CodeHash.Valid {
		token.CodeHash = t.CodeHash.String
	}
	if t.CodeSalt.Valid {
		token.CodeSalt = t.CodeSalt.String
	}
	if t.Secret.Valid {
		token.Secret = t.Secret.String
	}
	if t.ContactID != nil {
		id := domain.NewIDFromUint64(*t.ContactID)
		token.ContactID = &id
	}

	return token
}

type TwoFactorTokenRepo struct {
	db *gorm.DB
}

// NewTwoFactorTokenRepository creates a new instance of TwoFactorTokenRepo
func NewTwoFactorTokenRepository(db *gorm.DB) *TwoFactorTokenRepo {
	return &TwoFactorTokenRepo{db: db}
}

// WithTxFromContext returns a new TwoFactorTokenRepo with the transaction from the context
func (r TwoFactorTokenRepo) WithTxFromContext(ctx context.Context) domain.TwoFactorTokenRepository {
	if tx := db.GetTxFromContext(ctx); tx != nil {
		r.db = tx
	}
	return r
}

// Create inserts a new TwoFactorToken into the database.
func (r TwoFactorTokenRepo) Create(ctx context.Context, token *domain.TwoFactorToken) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:Create][userID: %d][type: %s]", token.UserID, token.Type.String())
	defer tools.EndDBRequestTimer(time.Now())

	row := encodeTwoFactorTokenForCreate(token)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorTokenRepo:Create][err: %w]", err)
	}

	token.UUID = row.UUID
	token.CreatedAt = row.CreatedAt

	return nil
}

// encodeTwoFactorTokenForCreate encodes a domain.TwoFactorToken into a twoFactorTokenSQL for database insertion.
func encodeTwoFactorTokenForCreate(in *domain.TwoFactorToken) *twoFactorTokenSQL {
	timeNow := time.Now().UTC()
	row := &twoFactorTokenSQL{
		UserID:       in.UserID.Uint64(),
		Type:         in.Type.Uint8(),
		Method:       in.Method.Uint8(),
		Attempts:     in.Attempts,
		Status:       in.Status.Uint8(),
		ExpiresAt:    in.ExpiresAt,
		CreatedAt:    timeNow,
		DispatchedAt: timeNow,
	}
	if in.ContactID != nil {
		contactID := in.ContactID.Uint64()
		row.ContactID = &contactID
	}
	if in.CodeHash != "" {
		row.CodeHash = sql.NullString{String: in.CodeHash, Valid: true}
	}
	if in.CodeSalt != "" {
		row.CodeSalt = sql.NullString{String: in.CodeSalt, Valid: true}
	}
	if in.Secret != "" {
		row.Secret = sql.NullString{String: in.Secret, Valid: true}
	}

	return row
}

// FindLatestByContactForUpdate retrieves the latest token for a given contact and type, applying a row-level lock for update.
func (r TwoFactorTokenRepo) FindLatestByContactForUpdate(ctx context.Context, contactID domain.ID, tokenType domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:FindLatestByContactForUpdate][contactID: %d][type: %s]", contactID, tokenType.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row twoFactorTokenSQL
	err := r.db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("contact_id = ? AND type = ?", contactID.Uint64(), tokenType).
		Order("created_at DESC").
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindLatestByContactForUpdate][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindLatestByContactForUpdate][err: %w]", err)
	}

	return row.decode(), nil
}

// FindByUUIDAndTypeForUpdate retrieves a token by its UUID and type, applying a row-level lock for update.
func (r TwoFactorTokenRepo) FindByUUIDAndTypeForUpdate(ctx context.Context, uuid string, tokenType domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:FindByUUIDAndTypeForUpdate][uuid: %s][type: %s]", uuid, tokenType.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row twoFactorTokenSQL
	err := r.db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE", Options: "NOWAIT"}).
		Where("uuid = ? AND type = ?", uuid, tokenType).
		Take(&row).Error
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindByUUIDAndTypeForUpdate][err: %w]", domain.ErrRecordNotFound)
		case db.IsRowLockConflict(err):
			return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindByUUIDAndTypeForUpdate][err: %w]", domain.ErrConcurrencyConflict)
		default:
			tools.TrackMetricDBErrorAdd()
			return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindByUUIDAndTypeForUpdate][err: %w]", err)
		}
	}

	return row.decode(), nil
}

// FindActiveByUserAndType retrieves the most recent active token for a given user and type.
func (r TwoFactorTokenRepo) FindActiveByUserAndType(ctx context.Context, userID domain.ID, tokenType domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:FindActiveByUserAndType][userID: %d][type: %s]", userID, tokenType.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row twoFactorTokenSQL
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ? AND status = ? AND expires_at > ?", userID.Uint64(), tokenType, domain.TwoFactorTokenStatusActive, time.Now().UTC()).
		Order("created_at DESC").
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindActiveByUserAndType][err: %w]", domain.ErrRecordNotFound)
		}
		tools.TrackMetricDBErrorAdd()
		return domain.TwoFactorToken{}, fmt.Errorf("[TwoFactorTokenRepo:FindActiveByUserAndType][err: %w]", err)
	}

	return row.decode(), nil
}

// HasActiveForContact checks if there is an active token for the given contact and type.
func (r TwoFactorTokenRepo) HasActiveForContact(ctx context.Context, contactID domain.ID, tokenType domain.TwoFactorTokenType) (bool, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:HasActiveForContact][contactID: %d][type: %s]", contactID, tokenType.String())
	defer tools.EndDBRequestTimer(time.Now())

	var row twoFactorTokenSQL
	err := r.db.WithContext(ctx).
		Select("uuid").
		Where("contact_id = ? AND type = ? AND status = ? AND consumed_at IS NULL AND expires_at > ?", contactID.Uint64(), tokenType, domain.TwoFactorTokenStatusActive, time.Now().UTC()).
		Order("created_at DESC").
		Take(&row).Error
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return false, nil
	default:
		tools.TrackMetricDBErrorAdd()
		return false, fmt.Errorf("[TwoFactorTokenRepo:HasActiveForContact][err: %w]", err)
	}
}

// InvalidateActiveByUserAndType sets all active tokens for the given user and type to expired.
func (r TwoFactorTokenRepo) InvalidateActiveByUserAndType(ctx context.Context, userID domain.ID, tokenType domain.TwoFactorTokenType) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:InvalidateActiveByUserAndType][userID: %d][type: %s]", userID, tokenType.String())
	defer tools.EndDBRequestTimer(time.Now())

	updates := map[string]any{
		"status":      domain.TwoFactorTokenStatusExpired,
		"consumed_at": gorm.Expr("COALESCE(consumed_at, ?)", time.Now().UTC()),
	}

	if err := r.db.WithContext(ctx).
		Model(&twoFactorTokenSQL{}).
		Where("user_id = ? AND type = ? AND status = ?", userID.Uint64(), tokenType, domain.TwoFactorTokenStatusActive).
		Updates(updates).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorTokenRepo:InvalidateActiveByUserAndType][err: %w]", err)
	}

	return nil
}

// IncrementAttempts increments the attempt count for the token identified by the given UUID.
func (r TwoFactorTokenRepo) IncrementAttempts(ctx context.Context, uuid string) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:IncrementAttempts][uuid: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&twoFactorTokenSQL{}).
		Where("uuid = ?", uuid).
		UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorTokenRepo:IncrementAttempts][err: %w]", err)
	}

	return nil
}

// Consume marks the token as consumed, optionally incrementing the attempt count.
func (r TwoFactorTokenRepo) Consume(ctx context.Context, uuid string, incAttempt bool) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:Consume][uuid: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	updates := map[string]any{
		"consumed_at": time.Now().UTC(),
		"status":      domain.TwoFactorTokenStatusUsed,
	}
	if incAttempt {
		updates["attempts"] = gorm.Expr("attempts + 1")
	}

	// The WHERE clause is what makes a double-consume impossible, but it only
	// helps if the caller is told. Without the RowsAffected check this returns nil
	// on a token that was already used, and the caller reads that as a successful
	// verification — one OTP accepted twice.
	res := r.db.WithContext(ctx).
		Model(&twoFactorTokenSQL{}).
		Where("uuid = ? AND consumed_at IS NULL", uuid).
		Updates(updates)
	if res.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorTokenRepo:Consume][err: %w]", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("[TwoFactorTokenRepo:Consume][uuid: %s][err: %w]", uuid, domain.ErrTokenAlreadyConsumed)
	}

	return nil
}

// ClearDispatchedAt resets the dispatch timestamp for a token.
//
// DispatchedAt drives the resend cooldown, and it is stamped when the token is
// created — before the code is actually sent. When the send then fails, the
// cooldown would run against a dispatch that never happened, so the user waits a
// minute for a resend they need immediately. Clearing it puts RetryAfter in the
// past, which IsRefreshable already reads as "resend allowed".
func (r TwoFactorTokenRepo) ClearDispatchedAt(ctx context.Context, uuid string) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:ClearDispatchedAt][uuid: %s]", uuid)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&twoFactorTokenSQL{}).
		Where("uuid = ?", uuid).
		Update("dispatched_at", time.Time{}).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorTokenRepo:ClearDispatchedAt][err: %w]", err)
	}

	return nil
}

// DeleteExpiredBefore removes tokens that expired before the cutoff.
//
// Expiry rather than creation: ResendChallenge pushes expires_at forward, so a
// token someone is still working through is never past it, however old the row.
func (r TwoFactorTokenRepo) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:DeleteExpiredBefore][cutoff: %s]", cutoff.Format(time.RFC3339))
	defer tools.EndDBRequestTimer(time.Now())

	result := r.db.WithContext(ctx).
		Where("expires_at < ?", cutoff).
		Delete(&twoFactorTokenSQL{})
	if result.Error != nil {
		tools.TrackMetricDBErrorAdd()
		return 0, fmt.Errorf("[TwoFactorTokenRepo:DeleteExpiredBefore][err: %w]", result.Error)
	}

	return result.RowsAffected, nil
}

// Refresh updates the token's code hash, salt, expiration, attempts, status, and consumed time.
func (r TwoFactorTokenRepo) Refresh(ctx context.Context, token *domain.TwoFactorToken) error {
	logger.LogCtx(ctx).Debugf("[TwoFactorTokenRepo:Refresh][uuid: %s]", token.UUID)
	defer tools.EndDBRequestTimer(time.Now())

	if err := r.db.WithContext(ctx).
		Model(&twoFactorTokenSQL{}).
		Where("uuid = ?", token.UUID).
		Updates(encodeTwoFactorTokenForRefresh(token)).Error; err != nil {
		tools.TrackMetricDBErrorAdd()
		return fmt.Errorf("[TwoFactorTokenRepo:Refresh][err: %w]", err)
	}

	return nil
}

// encodeTwoFactorTokenForRefresh encodes a domain.TwoFactorToken into a twoFactorTokenSQL for database update.
func encodeTwoFactorTokenForRefresh(in *domain.TwoFactorToken) map[string]any {
	return map[string]any{
		"code_hash":     in.CodeHash,
		"code_salt":     in.CodeSalt,
		"expires_at":    in.ExpiresAt,
		"attempts":      in.Attempts,
		"status":        in.Status,
		"consumed_at":   in.ConsumedAt,
		"dispatched_at": in.DispatchedAt,
	}
}
