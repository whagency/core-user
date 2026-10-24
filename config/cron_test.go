package config

import (
	"testing"
	"time"
)

// The refresh token TTL in internal/infrastructure/security/sessions.
const refreshTokenTTL = 30 * 24 * time.Hour

// The revoked-session retention is not a free number.
//
// Those rows carry the hash of the refresh token the session held, and that hash
// is the only thing detectRefreshTokenReuse can compare a replayed token
// against. Keeping them for less than the refresh TTL would delete the evidence
// while the token it describes is still usable, and reuse detection would go
// back to answering "unknown session" to every replay -- silently, because
// nothing about that looks like a failure.
func TestCleanupRetentionDefaultsOutlastRefreshTokens(t *testing.T) {
	if err := loadCronConfig(); err != nil {
		t.Fatalf("loadCronConfig: %v", err)
	}

	cleanup := Cron().Cleanup

	if cleanup.RevokedSessionRetention <= refreshTokenTTL {
		t.Fatalf(
			"revoked sessions are kept %s but a refresh token lives %s; reuse detection would find the row already pruned",
			cleanup.RevokedSessionRetention, refreshTokenTTL,
		)
	}

	// A sweep still has to be scheduled, or the retention is just documentation.
	if cleanup.Spec == "" {
		t.Fatal("the cleanup job has no schedule")
	}
	for name, d := range map[string]time.Duration{
		"SessionRetention":        cleanup.SessionRetention,
		"RevokedSessionRetention": cleanup.RevokedSessionRetention,
		"TwoFactorTokenRetention": cleanup.TwoFactorTokenRetention,
	} {
		if d <= 0 {
			t.Errorf("%s is %s; a non-positive retention would delete rows the service still needs", name, d)
		}
	}
}
