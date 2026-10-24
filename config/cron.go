package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/whagency/core-common/outbox"
)

var cronSettings CronSettings

type CronSettings struct {
	// Outbox runtime and retention. The values themselves live in common because
	// every adopting service shares one dashboard and one alert set — see
	// outbox.Settings. Override through the environment when this service really
	// needs a different number, and say why.
	Outbox outbox.Settings

	// Cleanup retention for the tables this service grows on its own.
	Cleanup CleanupSettings
}

// CleanupSettings decides how long the service keeps rows nothing reads any more.
//
// Every one of these tables grew without bound before: the outbox had a prune
// job and nothing else did. revoked_sessions took a row per logout, per admin
// kick and per refresh -- with a fifteen-minute access token that is around
// 35,000 rows a year for one active user.
type CleanupSettings struct {
	// Spec is how often the sweep runs. Hourly matches the outbox prune and the
	// dedupe-key cleanups in notification-service and restriction-service.
	Spec string `envconfig:"CRON_CLEANUP_SPEC" default:"@every 1h"`

	// SessionRetention is the grace kept after a session can no longer be used
	// at all -- both its access token and its refresh token expired.
	SessionRetention time.Duration `envconfig:"CRON_SESSION_RETENTION" default:"24h"`

	// RevokedSessionRetention must comfortably exceed the refresh token TTL,
	// which is 30 days.
	//
	// Not a free number. A revoked row carries the hash of the refresh token the
	// session held, and that hash is the only thing a replayed token can be
	// compared against -- see detectRefreshTokenReuse. Pruning by expire_at
	// instead, which tracks the fifteen-minute access token, would delete the
	// evidence within the hour and leave reuse detection quietly answering
	// "unknown session" to every replay.
	RevokedSessionRetention time.Duration `envconfig:"CRON_REVOKED_SESSION_RETENTION" default:"840h"`

	// TwoFactorTokenRetention is the grace kept after a token expires. Tokens
	// live five to ten minutes, so this is generous on purpose: it leaves a
	// recently consumed code visible while a support conversation is still
	// happening.
	TwoFactorTokenRetention time.Duration `envconfig:"CRON_TWO_FACTOR_TOKEN_RETENTION" default:"48h"`
}

// Cron returns the loaded cron settings.
func Cron() CronSettings {
	return cronSettings
}

// loadCronConfig loads the cron configuration from environment variables.
func loadCronConfig() error {
	if err := envconfig.Process("", &cronSettings); err != nil {
		return fmt.Errorf("[loadCronConfig][err: %w]", err)
	}
	return nil
}
