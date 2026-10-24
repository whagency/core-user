package controllers

import (
	"context"
	"fmt"
	"time"

	"user-service/internal/domain"

	"github.com/whagency/core-common/logger"
)

// CleanupCtrl deletes rows the service has finished with.
//
// Before this the outbox had a prune job and nothing else did, so every table
// here grew for the life of the deployment. revoked_sessions was the worst of
// them: one row per logout, per admin kick and per refresh, which with a
// fifteen-minute access token is roughly 35,000 rows a year for a single active
// user.
//
// Each sweep is independent. One failing must not stop the others, or a single
// stuck table would quietly hold back every other one.
type CleanupCtrl struct {
	sessions        domain.SessionRepository
	revokedSessions domain.RevokedSessionRepository
	twoFaTokens     domain.TwoFactorTokenRepository
	retention       CleanupRetention
	clock           func() time.Time
}

// CleanupRetention is how long each table keeps rows nothing reads any more.
type CleanupRetention struct {
	Sessions        time.Duration
	RevokedSessions time.Duration
	TwoFactorTokens time.Duration
}

// NewCleanupController builds the maintenance controller.
func NewCleanupController(
	sessions domain.SessionRepository,
	revokedSessions domain.RevokedSessionRepository,
	twoFaTokens domain.TwoFactorTokenRepository,
	retention CleanupRetention,
) *CleanupCtrl {
	return &CleanupCtrl{
		sessions:        sessions,
		revokedSessions: revokedSessions,
		twoFaTokens:     twoFaTokens,
		retention:       retention,
		clock:           func() time.Time { return time.Now().UTC() },
	}
}

// Run sweeps every table once.
//
// It keeps going after a failure and returns the first error at the end, so a
// table that cannot be swept does not shield the rest from ever being swept
// either.
func (c *CleanupCtrl) Run(ctx context.Context) error {
	now := c.clock()

	sweeps := []struct {
		name   string
		cutoff time.Time
		delete func(context.Context, time.Time) (int64, error)
	}{
		{
			name:   "sessions",
			cutoff: now.Add(-c.retention.Sessions),
			delete: c.sessions.DeleteUnusableBefore,
		},
		{
			name:   "revoked_sessions",
			cutoff: now.Add(-c.retention.RevokedSessions),
			delete: c.revokedSessions.DeleteCreatedBefore,
		},
		{
			name:   "two_factor_tokens",
			cutoff: now.Add(-c.retention.TwoFactorTokens),
			delete: c.twoFaTokens.DeleteExpiredBefore,
		},
	}

	var firstErr error
	for _, sweep := range sweeps {
		removed, err := sweep.delete(ctx, sweep.cutoff)
		if err != nil {
			logger.LogCtx(ctx).Errorf("[CleanupCtrl:Run][table:%s]%s", sweep.name, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("[CleanupCtrl:Run][table:%s]%w", sweep.name, err)
			}
			continue
		}

		if removed > 0 {
			logger.LogCtx(ctx).Infof(
				"[CleanupCtrl:Run][table:%s][rows:%d][cutoff:%s]",
				sweep.name, removed, sweep.cutoff.Format(time.RFC3339),
			)
		}
	}

	return firstErr
}
