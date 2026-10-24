package postgres

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"user-service/internal/domain"

	"github.com/whagency/core-common/testkit/loggertest"
	"github.com/whagency/core-common/testkit/postgrestest"
	"gorm.io/gorm"
)

// openCredentialsDB gives each test its own schema with the real migrations
// applied, so the lockout SQL runs against the actual column types.
func openCredentialsDB(t *testing.T) *gorm.DB {
	t.Helper()
	loggertest.Init(t, "user-service-test")

	return pgSuite.OpenGormDB(t, postgrestest.OpenConfig{
		MigrationsDir:     "../../../../data/db/migrations/postgres",
		SchemaPrefix:      "cred",
		SkipMigrationLine: postgrestest.SkipDatabaseLevelMigrationLine,
	})
}

// seedCredential inserts a user with a credential and returns the user id.
func seedCredential(t *testing.T, db *gorm.DB) domain.ID {
	t.Helper()

	var userID uint64
	if err := db.Raw(
		"INSERT INTO users (status, verification_level, created_at) VALUES (?, 0, NOW()) RETURNING id",
		domain.UserStatusActive.Uint8(),
	).Scan(&userID).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	if err := db.Exec(
		"INSERT INTO credentials (user_id, password_hash, algorithm) VALUES (?, 'hash', 'bcrypt')",
		userID,
	).Error; err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	return domain.NewIDFromUint64(userID)
}

func TestCredentialRepo_RegisterFailedLoginLocksAtTheThreshold(t *testing.T) {
	t.Parallel()

	db := openCredentialsDB(t)
	repo := NewCredentialRepository(db)
	ctx := context.Background()
	userID := seedCredential(t, db)

	policy := domain.LoginLockPolicy{MaxFailedAttempts: 3, LockFor: 15 * time.Minute}

	for attempt := 1; attempt <= 2; attempt++ {
		got, err := repo.RegisterFailedLogin(ctx, userID, policy)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if got.FailedLoginAttempts != uint16(attempt) {
			t.Fatalf("attempt %d: expected count %d, got %d", attempt, attempt, got.FailedLoginAttempts)
		}
		if got.LoginLockedUntil != nil {
			t.Fatalf("attempt %d: must not lock before the threshold, got %v", attempt, got.LoginLockedUntil)
		}
	}

	// The third crosses it.
	got, err := repo.RegisterFailedLogin(ctx, userID, policy)
	if err != nil {
		t.Fatalf("third attempt: %v", err)
	}
	if got.LoginLockedUntil == nil {
		t.Fatal("expected the third failure to stamp the deadline")
	}
	if !got.IsLoginLocked(time.Now().UTC()) {
		t.Fatalf("expected the account to read as locked, deadline %v", got.LoginLockedUntil)
	}

	// The window is roughly the one asked for, which is what pins the interval
	// arithmetic in the UPDATE.
	remaining := time.Until(*got.LoginLockedUntil)
	if remaining < 14*time.Minute || remaining > 16*time.Minute {
		t.Fatalf("expected roughly 15 minutes of lock, got %s", remaining)
	}
}

func TestCredentialRepo_ConcurrentFailuresAllCount(t *testing.T) {
	t.Parallel()

	// The reason RegisterFailedLogin is a single statement. Read-modify-write
	// would let parallel guesses store the same increment, handing the attacker a
	// free attempt for every request they run at once.
	db := openCredentialsDB(t)
	repo := NewCredentialRepository(db)
	ctx := context.Background()
	userID := seedCredential(t, db)

	const attempts = 12
	policy := domain.LoginLockPolicy{MaxFailedAttempts: 100, LockFor: time.Minute}

	var wg sync.WaitGroup
	errs := make(chan error, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := repo.RegisterFailedLogin(ctx, userID, policy); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent failure: %v", err)
	}

	stored, err := repo.FindByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if stored.FailedLoginAttempts != attempts {
		t.Fatalf("expected every one of %d failures to count, got %d", attempts, stored.FailedLoginAttempts)
	}
}

func TestCredentialRepo_ClearLoginFailuresReleasesTheLock(t *testing.T) {
	t.Parallel()

	db := openCredentialsDB(t)
	repo := NewCredentialRepository(db)
	ctx := context.Background()
	userID := seedCredential(t, db)

	policy := domain.LoginLockPolicy{MaxFailedAttempts: 1, LockFor: time.Hour}
	if _, err := repo.RegisterFailedLogin(ctx, userID, policy); err != nil {
		t.Fatalf("RegisterFailedLogin: %v", err)
	}

	if err := repo.ClearLoginFailures(ctx, userID); err != nil {
		t.Fatalf("ClearLoginFailures: %v", err)
	}

	stored, err := repo.FindByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if stored.FailedLoginAttempts != 0 || stored.LoginLockedUntil != nil {
		t.Fatalf("expected a clean slate, got attempts=%d until=%v",
			stored.FailedLoginAttempts, stored.LoginLockedUntil)
	}
}

func TestCredentialRepo_UpdateReleasesTheLockAndClearsMustRotate(t *testing.T) {
	t.Parallel()

	// Rotating the password clears both. Update used to pass a struct, and GORM
	// skips a struct's zero values, so must_rotate=false was silently dropped;
	// the lockout would have gone the same way.
	db := openCredentialsDB(t)
	repo := NewCredentialRepository(db)
	ctx := context.Background()
	userID := seedCredential(t, db)

	if err := db.Exec("UPDATE credentials SET must_rotate = TRUE WHERE user_id = ?", userID.Uint64()).Error; err != nil {
		t.Fatalf("set must_rotate: %v", err)
	}
	if _, err := repo.RegisterFailedLogin(ctx, userID, domain.LoginLockPolicy{
		MaxFailedAttempts: 1,
		LockFor:           time.Hour,
	}); err != nil {
		t.Fatalf("RegisterFailedLogin: %v", err)
	}

	rotated := domain.Credential{
		UserID:       userID,
		PasswordHash: "new-hash",
		Algorithm:    domain.CredentialAlgorithmBcrypt,
	}
	if err := repo.Update(ctx, &rotated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	stored, err := repo.FindByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if stored.MustRotate {
		t.Fatal("must_rotate must be cleared by a rotation")
	}
	if stored.FailedLoginAttempts != 0 || stored.LoginLockedUntil != nil {
		t.Fatalf("a rotation must release the lock, got attempts=%d until=%v",
			stored.FailedLoginAttempts, stored.LoginLockedUntil)
	}
	if stored.PasswordHash != "new-hash" {
		t.Fatalf("expected the new hash, got %q", stored.PasswordHash)
	}
}

// TestContactsValueIsIndexed guards the index sign-in depends on.
//
// FindByValue and FindPrimaryByValue filter on value alone, and the only other
// index holding the column is UNIQUE (type, value) -- useless for a predicate
// that does not constrain type. Without idx_contacts_value both queries fall
// back to a sequential scan of the whole table, on every sign-in and every
// recovery request. Dropping it would be silent: the queries still return the
// right rows, just slower and slower as the table grows.
func TestContactsValueIsIndexed(t *testing.T) {
	t.Parallel()

	db := openCredentialsDB(t)

	// Scoped to this test's own schema. pg_indexes is a view that calls
	// pg_get_indexdef over every matching relation in the database, and the
	// parallel tests here are dropping their schemas as it scans -- which shows
	// up as "could not open relation with OID". Reading the catalog directly and
	// resolving the definition only for the one index this test owns keeps the
	// query away from anything another test might be tearing down.
	var indexDef string
	if err := db.Raw(`
		SELECT pg_get_indexdef(i.indexrelid)
		FROM pg_index i
		JOIN pg_class idx ON idx.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = idx.relnamespace
		JOIN pg_class tbl ON tbl.oid = i.indrelid
		WHERE n.nspname = current_schema()
		  AND tbl.relname = 'contacts'
		  AND idx.relname = 'idx_contacts_value'`,
	).Scan(&indexDef).Error; err != nil {
		t.Fatalf("look up the index: %v", err)
	}

	if indexDef == "" {
		t.Fatal("idx_contacts_value is missing; sign-in falls back to a sequential scan without it")
	}
	if !strings.Contains(indexDef, "(value)") {
		t.Fatalf("expected the index to be on value alone, got %q", indexDef)
	}
}
