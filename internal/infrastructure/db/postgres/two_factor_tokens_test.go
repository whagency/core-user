package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"user-service/internal/domain"

	"github.com/whagency/core-common/testkit/loggertest"
	"github.com/whagency/core-common/testkit/postgrestest"
	"gorm.io/gorm"
)

var pgSuite *postgrestest.Suite

// TestMain owns one disposable PostgreSQL container for this package.
//
// These are the first repository tests in user-service. They run against a real
// engine because the behaviour under test is a database property — whether a
// conditional UPDATE matched any row — and that is exactly what a mock cannot
// express.
func TestMain(m *testing.M) {
	ctx := context.Background()

	suite, err := postgrestest.Start(ctx, postgrestest.ContainerConfig{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start postgres container: %v\n", err)
		os.Exit(1)
	}
	pgSuite = suite

	code := m.Run()

	if errTerminate := pgSuite.Terminate(ctx); errTerminate != nil {
		fmt.Fprintf(os.Stderr, "failed to terminate postgres container: %v\n", errTerminate)
	}

	os.Exit(code)
}

// openDB creates an isolated schema with the service's real migrations applied.
func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	loggertest.Init(t, "user-service-test")

	return pgSuite.OpenGormDB(t, postgrestest.OpenConfig{
		MigrationsDir:     "../../../../data/db/migrations/postgres",
		SchemaPrefix:      "twofa",
		SkipMigrationLine: postgrestest.SkipDatabaseLevelMigrationLine,
	})
}

// seedToken inserts a user and an active token for it, returning the token UUID.
func seedToken(t *testing.T, db *gorm.DB) string {
	t.Helper()

	var userID uint64
	if err := db.Raw(`
		INSERT INTO users (status, created_at) VALUES (1, NOW()) RETURNING id
	`).Scan(&userID).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	var uuid string
	if err := db.Raw(`
		INSERT INTO two_factor_tokens (user_id, type, method, code_hash, code_salt, status, expires_at, dispatched_at)
		VALUES (?, 1, 2, 'hash', 'salt', 1, NOW() + interval '5 minutes', NOW())
		RETURNING uuid
	`, userID).Scan(&uuid).Error; err != nil {
		t.Fatalf("failed to seed token: %v", err)
	}

	return uuid
}

// TestTwoFactorTokenRepo_ConsumeRejectsSecondUse is the point of this package.
//
// Consume updates under "WHERE consumed_at IS NULL", so a second consume changes
// nothing — but before this it also returned nil, and the caller read that as a
// successful verification. That is one OTP accepted twice.
func TestTwoFactorTokenRepo_ConsumeRejectsSecondUse(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	repo := NewTwoFactorTokenRepository(db)
	ctx := context.Background()
	uuid := seedToken(t, db)

	if err := repo.Consume(ctx, uuid, true); err != nil {
		t.Fatalf("first Consume failed: %v", err)
	}

	err := repo.Consume(ctx, uuid, true)
	if err == nil {
		t.Fatal("expected the second consume to be refused")
	}
	if !errors.Is(err, domain.ErrTokenAlreadyConsumed) {
		t.Fatalf("expected ErrTokenAlreadyConsumed, got %v", err)
	}
}

// TestTwoFactorTokenRepo_ConsumeRejectsUnknownToken checks the same guard covers a
// token that never existed, rather than silently reporting success.
func TestTwoFactorTokenRepo_ConsumeRejectsUnknownToken(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	repo := NewTwoFactorTokenRepository(db)

	err := repo.Consume(context.Background(), "00000000-0000-4000-8000-000000000000", true)
	if err == nil {
		t.Fatal("expected consuming an unknown token to be refused")
	}
	if !errors.Is(err, domain.ErrTokenAlreadyConsumed) {
		t.Fatalf("expected ErrTokenAlreadyConsumed, got %v", err)
	}
}

// TestTwoFactorTokenRepo_ClearDispatchedAtClearsTheColumn covers the other half of
// the registration fix.
//
// It asserts only the column, not IsRefreshable: the cooldown window is domain
// behaviour driven by OTPRefreshInterval, and pulling service config into a
// persistence test would couple it to something it does not own. That the cleared
// value reads as "resend allowed" is covered in the controller package.
func TestTwoFactorTokenRepo_ClearDispatchedAtClearsTheColumn(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	repo := NewTwoFactorTokenRepository(db)
	ctx := context.Background()
	uuid := seedToken(t, db)

	before, errBefore := repo.FindByUUIDAndTypeForUpdate(ctx, uuid, domain.TwoFactorTokenTypeVerifyContact)
	if errBefore != nil {
		t.Fatalf("failed to read the seeded token: %v", errBefore)
	}
	if before.DispatchedAt.IsZero() {
		t.Fatal("the seeded token should carry a dispatch timestamp")
	}

	if err := repo.ClearDispatchedAt(ctx, uuid); err != nil {
		t.Fatalf("ClearDispatchedAt failed: %v", err)
	}

	after, errAfter := repo.FindByUUIDAndTypeForUpdate(ctx, uuid, domain.TwoFactorTokenTypeVerifyContact)
	if errAfter != nil {
		t.Fatalf("failed to re-read the token: %v", errAfter)
	}

	// Postgres stores the Go zero time as year 1, so compare against a date no
	// real dispatch could predate rather than relying on IsZero round-tripping.
	if after.DispatchedAt.After(time.Date(1971, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected the dispatch timestamp to be cleared, got %s", after.DispatchedAt)
	}
}
