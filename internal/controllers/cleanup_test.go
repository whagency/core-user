package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"
)

type cleanupSessionsStub struct {
	sessionRepoStub

	cutoff time.Time
	err    error
}

func (s *cleanupSessionsStub) DeleteUnusableBefore(_ context.Context, cutoff time.Time) (int64, error) {
	s.cutoff = cutoff
	if s.err != nil {
		return 0, s.err
	}
	return 3, nil
}

type cleanupRevokedStub struct {
	revokedSessionRepoStub

	cutoff time.Time
	err    error
}

func (s *cleanupRevokedStub) DeleteCreatedBefore(_ context.Context, cutoff time.Time) (int64, error) {
	s.cutoff = cutoff
	if s.err != nil {
		return 0, s.err
	}
	return 7, nil
}

type cleanupTokensStub struct {
	cutoff time.Time
	called bool
	err    error
}

func (s *cleanupTokensStub) Create(context.Context, *domain.TwoFactorToken) error { return nil }
func (s *cleanupTokensStub) FindLatestByContactForUpdate(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}
func (s *cleanupTokensStub) FindByUUIDAndTypeForUpdate(context.Context, string, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}
func (s *cleanupTokensStub) FindActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}
func (s *cleanupTokensStub) HasActiveForContact(context.Context, domain.ID, domain.TwoFactorTokenType) (bool, error) {
	return false, nil
}
func (s *cleanupTokensStub) InvalidateActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) error {
	return nil
}
func (s *cleanupTokensStub) IncrementAttempts(context.Context, string) error       { return nil }
func (s *cleanupTokensStub) Consume(context.Context, string, bool) error           { return nil }
func (s *cleanupTokensStub) ClearDispatchedAt(context.Context, string) error       { return nil }
func (s *cleanupTokensStub) Refresh(context.Context, *domain.TwoFactorToken) error { return nil }

func (s *cleanupTokensStub) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	s.called = true
	s.cutoff = cutoff
	if s.err != nil {
		return 0, s.err
	}
	return 2, nil
}

func (s *cleanupTokensStub) WithTxFromContext(context.Context) domain.TwoFactorTokenRepository {
	return s
}

func newCleanupFixture(retention CleanupRetention, now time.Time) (*CleanupCtrl, *cleanupSessionsStub, *cleanupRevokedStub, *cleanupTokensStub) {
	sessions := &cleanupSessionsStub{}
	revoked := &cleanupRevokedStub{}
	tokens := &cleanupTokensStub{}

	ctrl := NewCleanupController(sessions, revoked, tokens, retention)
	ctrl.clock = func() time.Time { return now }

	return ctrl, sessions, revoked, tokens
}

func TestCleanupRunUsesEachTablesOwnRetention(t *testing.T) {
	initTestLogger(t)

	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	retention := CleanupRetention{
		Sessions:        24 * time.Hour,
		RevokedSessions: 35 * 24 * time.Hour,
		TwoFactorTokens: 48 * time.Hour,
	}

	ctrl, sessions, revoked, tokens := newCleanupFixture(retention, now)

	if err := ctrl.Run(context.Background()); err != nil {
		t.Fatalf("expected the sweep to succeed, got %v", err)
	}

	for _, tc := range []struct {
		name string
		got  time.Time
		want time.Time
	}{
		{name: "sessions", got: sessions.cutoff, want: now.Add(-retention.Sessions)},
		{name: "revoked_sessions", got: revoked.cutoff, want: now.Add(-retention.RevokedSessions)},
		{name: "two_factor_tokens", got: tokens.cutoff, want: now.Add(-retention.TwoFactorTokens)},
	} {
		if !tc.got.Equal(tc.want) {
			t.Errorf("%s cutoff = %s, want %s", tc.name, tc.got, tc.want)
		}
	}
}

func TestCleanupRunKeepsGoingAfterAFailure(t *testing.T) {
	initTestLogger(t)

	// A table that cannot be swept must not shield the others from ever being
	// swept either.
	now := time.Now().UTC()
	ctrl, sessions, _, tokens := newCleanupFixture(CleanupRetention{
		Sessions:        time.Hour,
		RevokedSessions: time.Hour,
		TwoFactorTokens: time.Hour,
	}, now)

	sessions.err = errors.New("sessions unavailable")

	err := ctrl.Run(context.Background())
	if err == nil {
		t.Fatal("expected the failure to be reported")
	}

	if !tokens.called {
		t.Fatal("a failure on the first table must not stop the later ones")
	}
}
