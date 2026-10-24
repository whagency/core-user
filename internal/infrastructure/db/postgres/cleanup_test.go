package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"user-service/internal/domain"

	"github.com/whagency/core-common/testkit/loggertest"
	"github.com/whagency/core-common/testkit/postgrestest"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func openCleanupDB(t *testing.T) *gorm.DB {
	t.Helper()
	loggertest.Init(t, "user-service-test")

	return pgSuite.OpenGormDB(t, postgrestest.OpenConfig{
		MigrationsDir:     "../../../../data/db/migrations/postgres",
		SchemaPrefix:      "clean",
		SkipMigrationLine: postgrestest.SkipDatabaseLevelMigrationLine,
	})
}

func seedUser(t *testing.T, db *gorm.DB) domain.ID {
	t.Helper()

	var userID uint64
	if err := db.Raw(
		"INSERT INTO users (status, verification_level, created_at) VALUES (?, 0, NOW()) RETURNING id",
		domain.UserStatusActive.Uint8(),
	).Scan(&userID).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	return domain.NewIDFromUint64(userID)
}

// A session is only unusable once both its windows have closed. Deleting one
// whose refresh token still works would sign a user out for no reason.
func TestSessionRepo_DeleteUnusableBeforeSparesLiveSessions(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewSessionRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	now := time.Now().UTC()
	insert := func(uuid string, expire, refreshExpire time.Time) {
		if err := db.Exec(
			"INSERT INTO sessions (uuid, expire, user_id, refresh_token, refresh_expire, ip, created_at) VALUES (?, ?, ?, ?, ?, '1.2.3.4', NOW())",
			uuid, expire.Unix(), userID.Uint64(), uuid+"-hash", refreshExpire.Unix(),
		).Error; err != nil {
			t.Fatalf("seed session %s: %v", uuid, err)
		}
	}

	dead := "00000000-0000-0000-0000-000000000001"
	refreshable := "00000000-0000-0000-0000-000000000002"
	live := "00000000-0000-0000-0000-000000000003"

	insert(dead, now.Add(-40*24*time.Hour), now.Add(-10*24*time.Hour))
	// Access token long gone, but the refresh token still works.
	insert(refreshable, now.Add(-40*24*time.Hour), now.Add(20*24*time.Hour))
	insert(live, now.Add(time.Hour), now.Add(30*24*time.Hour))

	removed, err := repo.DeleteUnusableBefore(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteUnusableBefore: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected exactly the dead session to go, got %d", removed)
	}

	for _, uuid := range []string{refreshable, live} {
		if _, errFind := repo.FindByUUID(ctx, domain.SessionID(uuid)); errFind != nil {
			t.Fatalf("session %s must survive: %v", uuid, errFind)
		}
	}
	if _, errFind := repo.FindByUUID(ctx, domain.SessionID(dead)); errFind == nil {
		t.Fatal("the dead session should have been deleted")
	}
}

// The hash on a revoked row is what reuse detection compares a replayed refresh
// token against, so the sweep must not reach rows younger than the refresh TTL.
func TestRevokedSessionRepo_DeleteCreatedBeforeKeepsRecentRows(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewRevokedSessionRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	now := time.Now().UTC()
	insert := func(uuid string, createdAt time.Time) {
		if err := db.Exec(
			"INSERT INTO revoked_sessions (uuid, user_id, reason, refresh_token_hash, created_at, expire_at) VALUES (?, ?, ?, ?, ?, ?)",
			uuid, userID.Uint64(), domain.SessionRevocationReasonRefresh.Uint8(), uuid+"-hash", createdAt,
			// expire_at tracks the fifteen-minute access token and is long past
			// on both rows; pruning by it would take the recent one too.
			createdAt.Add(15*time.Minute),
		).Error; err != nil {
			t.Fatalf("seed revoked %s: %v", uuid, err)
		}
	}

	old := "00000000-0000-0000-0000-0000000000a1"
	recent := "00000000-0000-0000-0000-0000000000a2"

	insert(old, now.Add(-40*24*time.Hour))
	insert(recent, now.Add(-20*24*time.Hour))

	removed, err := repo.DeleteCreatedBefore(ctx, now.Add(-35*24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteCreatedBefore: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected only the old row to go, got %d", removed)
	}

	kept, errFind := repo.FindByUUID(ctx, domain.SessionID(recent))
	if errFind != nil {
		t.Fatalf("a row inside the refresh window must survive: %v", errFind)
	}
	if kept.RefreshTokenHash == "" {
		t.Fatal("the surviving row lost its hash, which is what reuse detection needs")
	}
}

// Expiry rather than age: ResendChallenge pushes expires_at forward, so a token
// someone is still working through must survive however old the row is.
func TestTwoFactorTokenRepo_DeleteExpiredBeforeSparesResentTokens(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewTwoFactorTokenRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	now := time.Now().UTC()
	insert := func(createdAt, expiresAt time.Time) string {
		var uuid string
		if err := db.Raw(
			"INSERT INTO two_factor_tokens (user_id, type, method, status, attempts, expires_at, created_at, dispatched_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?) RETURNING uuid",
			userID.Uint64(),
			domain.TwoFactorTokenTypeVerifyContact.Uint8(),
			domain.TwoFactorMethodEmail.Uint8(),
			domain.TwoFactorTokenStatusActive.Uint8(),
			expiresAt, createdAt, createdAt,
		).Scan(&uuid).Error; err != nil {
			t.Fatalf("seed token: %v", err)
		}
		return uuid
	}

	stale := insert(now.Add(-72*time.Hour), now.Add(-71*time.Hour))
	// Old row, but resends kept pushing the expiry forward.
	resent := insert(now.Add(-72*time.Hour), now.Add(5*time.Minute))

	removed, err := repo.DeleteExpiredBefore(ctx, now.Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpiredBefore: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected only the stale token to go, got %d", removed)
	}

	if _, errFind := repo.FindByUUIDAndTypeForUpdate(ctx, resent, domain.TwoFactorTokenTypeVerifyContact); errFind != nil {
		t.Fatalf("a token still being resent must survive: %v", errFind)
	}
	if _, errFind := repo.FindByUUIDAndTypeForUpdate(ctx, stale, domain.TwoFactorTokenTypeVerifyContact); errFind == nil {
		t.Fatal("the stale token should have been deleted")
	}
}

// The partial unique index is what makes Init's check meaningful: without it two
// concurrent requests both saw no open verification, both paid the KYC provider
// for an applicant form, and both wrote a row.
func TestVerificationRepo_OnlyOneOpenVerificationPerUserAndProvider(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewVerificationRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	first := domain.NewVerification(userID, domain.VerificationProvidersAmlBot, domain.VerificationLevelBasic)
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("the first open verification must be accepted: %v", err)
	}

	second := domain.NewVerification(userID, domain.VerificationProvidersAmlBot, domain.VerificationLevelBasic)
	err := repo.Create(ctx, second)
	if !errors.Is(err, domain.ErrRecordExists) {
		t.Fatalf("expected the second open verification to be refused as ErrRecordExists, got %v", err)
	}

	// Once the first is finished it no longer occupies the slot, so the user can
	// come back for the next level.
	if errUpdate := repo.Update(ctx, domain.VerificationUpdateParams{
		VerificationID: first.ID,
		Status:         domain.VerificationStatusCompleteYes,
	}); errUpdate != nil {
		t.Fatalf("Update: %v", errUpdate)
	}

	third := domain.NewVerification(userID, domain.VerificationProvidersAmlBot, domain.VerificationLevelAdvanced)
	if errCreate := repo.Create(ctx, third); errCreate != nil {
		t.Fatalf("a completed verification must not block the next one: %v", errCreate)
	}
}

func TestVerificationRepo_SetProviderDataFillsAReservedRow(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewVerificationRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	reserved := domain.NewVerification(userID, domain.VerificationProvidersAmlBot, domain.VerificationLevelBasic)
	if err := repo.Create(ctx, reserved); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.SetProviderData(ctx, reserved.ID, domain.ProviderAmlBotDataPayload{FormURL: "https://kyc.example/form"}); err != nil {
		t.Fatalf("SetProviderData: %v", err)
	}

	stored, err := repo.GetLastPendingByUserIDAndProvider(ctx, userID, domain.VerificationProvidersAmlBot)
	if err != nil {
		t.Fatalf("GetLastPendingByUserIDAndProvider: %v", err)
	}
	if stored.ProviderData == nil {
		t.Fatal("expected the reserved row to carry the form after the provider answered")
	}
	if !strings.Contains(string(stored.ProviderData.(datatypes.JSON)), "kyc.example") {
		t.Fatalf("expected the form url to be stored, got %v", stored.ProviderData)
	}
}

func seedTwoFactorSettings(t *testing.T, db *gorm.DB, userID domain.ID) {
	t.Helper()

	if err := db.Exec(
		"INSERT INTO two_factor_settings (user_id, method, secret, created_at) VALUES (?, ?, 'SECRET', NOW())",
		userID.Uint64(), domain.TwoFactorMethodGoogle.Uint8(),
	).Error; err != nil {
		t.Fatalf("seed settings: %v", err)
	}
}

// Only one of two requests carrying the same TOTP code may win. Read-then-write
// would let both read the old counter and both decide they had, which is exactly
// the replay the counter exists to stop.
func TestTwoFactorSettingsRepo_ConcurrentAdvanceHasOneWinner(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewTwoFactorSettingsRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)
	seedTwoFactorSettings(t, db, userID)

	const racers = 8
	const step = int64(58000000)

	var wg sync.WaitGroup
	results := make(chan bool, racers)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			advanced, err := repo.AdvanceTOTPCounter(ctx, userID, step)
			if err != nil {
				t.Errorf("AdvanceTOTPCounter: %v", err)
				return
			}
			results <- advanced
		}()
	}
	wg.Wait()
	close(results)

	winners := 0
	for advanced := range results {
		if advanced {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one request to spend the step, got %d", winners)
	}
}

func TestTwoFactorSettingsRepo_AdvanceRefusesAStepAlreadySpent(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewTwoFactorSettingsRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)
	seedTwoFactorSettings(t, db, userID)

	if advanced, err := repo.AdvanceTOTPCounter(ctx, userID, 100); err != nil || !advanced {
		t.Fatalf("the first step must be accepted: advanced=%t err=%v", advanced, err)
	}

	for _, step := range []int64{100, 99, 0} {
		advanced, err := repo.AdvanceTOTPCounter(ctx, userID, step)
		if err != nil {
			t.Fatalf("AdvanceTOTPCounter(%d): %v", step, err)
		}
		if advanced {
			t.Fatalf("step %d is not above the last accepted one and must be refused", step)
		}
	}

	if advanced, err := repo.AdvanceTOTPCounter(ctx, userID, 101); err != nil || !advanced {
		t.Fatalf("a later step must still be accepted: advanced=%t err=%v", advanced, err)
	}

	stored, err := repo.FindByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if stored.LastTOTPCounter != 101 {
		t.Fatalf("expected the stored step to be 101, got %d", stored.LastTOTPCounter)
	}
}

// The session expiry columns held Unix seconds in a 32-bit INT, which stops at
// 2147483647 -- 2038-01-19. refresh_expire is stamped 30 days ahead, so sign-in
// would have started failing on 2037-12-20, and failing hard: Postgres refuses
// the INSERT with "integer out of range" rather than storing something wrong.
func TestSessionRepo_ExpiryOutlives2038(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewSessionRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	// One second past what the old column could hold.
	beyond := time.Unix(2147483648, 0).UTC()
	refreshBeyond := beyond.Add(30 * 24 * time.Hour)

	session := domain.Session{
		UUID:             domain.SessionID("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		UserID:           userID,
		RefreshTokenHash: "hash-beyond-2038",
		ExpireAt:         &beyond,
		RefreshExpireAt:  &refreshBeyond,
		SessionClientDeviceData: domain.SessionClientDeviceData{
			IPAddress: "1.2.3.4",
		},
	}

	if err := repo.Create(ctx, &session); err != nil {
		t.Fatalf("a session expiring past 2038 must be storable: %v", err)
	}

	stored, err := repo.FindByUUID(ctx, session.UUID)
	if err != nil {
		t.Fatalf("FindByUUID: %v", err)
	}

	if stored.ExpireAt == nil || !stored.ExpireAt.Equal(beyond) {
		t.Fatalf("expected the access expiry to round-trip as %s, got %v", beyond, stored.ExpireAt)
	}
	if stored.RefreshExpireAt == nil || !stored.RefreshExpireAt.Equal(refreshBeyond) {
		t.Fatalf("expected the refresh expiry to round-trip as %s, got %v", refreshBeyond, stored.RefreshExpireAt)
	}
}

// created_at carries across a refresh; last_activity_at does not.
//
// A refresh does not update the session row, it writes a new one and deletes the
// old. So the repository has to accept a created_at from the session being
// continued, or every rotation resets the sign-in time -- and with a
// fifteen-minute access token the session list ends up telling the user that
// every device signed in minutes ago. last_activity_at is the opposite: it is
// stamped on each write, which is what makes it mean anything at all.
func TestSessionRepo_CreateCarriesTheSignInTimeAndStampsActivity(t *testing.T) {
	t.Parallel()

	db := openCleanupDB(t)
	repo := NewSessionRepository(db)
	ctx := context.Background()
	userID := seedUser(t, db)

	signedInAt := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Microsecond)
	before := time.Now().UTC().Add(-time.Second)

	refreshed := domain.Session{
		UUID:                    domain.SessionID("00000000-0000-0000-0000-0000000000aa"),
		UserID:                  userID,
		RefreshTokenHash:        "hash-of-the-new-token",
		SessionClientDeviceData: domain.SessionClientDeviceData{IPAddress: "1.2.3.4"},
		CreatedAt:               signedInAt,
	}
	if err := repo.Create(ctx, &refreshed); err != nil {
		t.Fatalf("Create refreshed session: %v", err)
	}

	stored, err := repo.FindByUUID(ctx, refreshed.UUID)
	if err != nil {
		t.Fatalf("FindByUUID: %v", err)
	}

	if !stored.CreatedAt.UTC().Equal(signedInAt) {
		t.Fatalf("expected created_at to keep the sign-in time %s, got %s", signedInAt, stored.CreatedAt.UTC())
	}
	if stored.LastActivityAt == nil {
		t.Fatal("expected last_activity_at to be stamped")
	}
	if activity := stored.LastActivityAt.UTC(); activity.Before(before) {
		t.Fatalf("expected last_activity_at to be stamped at write time, got %s", activity)
	}

	// A fresh sign-in has nothing to carry, and the repository fills both in.
	fresh := domain.Session{
		UUID:                    domain.SessionID("00000000-0000-0000-0000-0000000000bb"),
		UserID:                  userID,
		RefreshTokenHash:        "hash-of-a-first-token",
		SessionClientDeviceData: domain.SessionClientDeviceData{IPAddress: "1.2.3.4"},
	}
	if errCreate := repo.Create(ctx, &fresh); errCreate != nil {
		t.Fatalf("Create fresh session: %v", errCreate)
	}

	storedFresh, errFresh := repo.FindByUUID(ctx, fresh.UUID)
	if errFresh != nil {
		t.Fatalf("FindByUUID fresh: %v", errFresh)
	}
	if storedFresh.CreatedAt.UTC().Before(before) {
		t.Fatalf("expected created_at stamped at write time, got %s", storedFresh.CreatedAt.UTC())
	}
}
