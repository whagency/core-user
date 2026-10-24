package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"

	"github.com/whagency/core-common/testkit/loggertest"
)

// revocationCacheStub answers the one question checkRevoked asks.
type revocationCacheStub struct {
	revoked map[string]bool
	err     error
}

func (c *revocationCacheStub) Exists(_ context.Context, key string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	return c.revoked[key], nil
}

func (c *revocationCacheStub) Get(context.Context, string) (domain.RevokedSession, error) {
	return domain.RevokedSession{}, nil
}
func (c *revocationCacheStub) Update(context.Context, string, domain.RevokedSession) error {
	return nil
}
func (c *revocationCacheStub) UpdateWithTTL(context.Context, string, domain.RevokedSession, time.Duration) error {
	return nil
}
func (c *revocationCacheStub) GetWithRefresh(context.Context, string) (domain.RevokedSession, error) {
	return domain.RevokedSession{}, nil
}
func (c *revocationCacheStub) RefreshAndGet(context.Context, string) (domain.RevokedSession, error) {
	return domain.RevokedSession{}, nil
}
func (c *revocationCacheStub) DeleteKey(context.Context, string) error { return nil }

func newValidationHelper(t *testing.T, cache *revocationCacheStub, opts ...Option) *JWTSessionHelper {
	t.Helper()
	loggertest.Init(t, "user-service-test")

	h, err := NewJWTSessionHelper([]byte("0123456789abcdef0123456789abcdef"), cache, opts...)
	if err != nil {
		t.Fatalf("NewJWTSessionHelper: %v", err)
	}

	return h
}

// issueFor mints a token and reports its session id, so the test can mark that
// exact session revoked.
func issueFor(t *testing.T, h *JWTSessionHelper) (token string, sessionID string) {
	t.Helper()

	out, err := h.Issue(context.Background(), domain.SessionIssueParams{UserID: domain.NewIDFromUint64(9)})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	return out.AccessToken, out.SessionID.String()
}

// Waiving expiry used to waive revocation with it: both lived in isExpiredToken
// behind one flag. notification-service passes that flag on every websocket
// handshake, so a signed-out or admin-blocked user kept authenticating for as
// long as their JWT was signed correctly.
func TestValidate_RevocationIsCheckedEvenWhenExpiryIsWaived(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		opts    domain.ValidateOptions
		wantErr error
	}{
		{
			name:    "default rejects a revoked session",
			opts:    domain.ValidateOptions{},
			wantErr: ErrRevoked,
		},
		{
			// The regression this test exists for.
			name:    "waiving expiry does not waive revocation",
			opts:    domain.ValidateOptions{AllowExpired: true},
			wantErr: ErrRevoked,
		},
		{
			name: "only the refresh path may accept a revoked session",
			opts: domain.ValidateOptions{AllowExpired: true, AllowRevoked: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cache := &revocationCacheStub{revoked: map[string]bool{}}
			h := newValidationHelper(t, cache)

			token, sid := issueFor(t, h)
			cache.revoked[sid] = true

			_, err := h.Validate(context.Background(), token, tc.opts)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the token to validate, got %v", err)
			}
		})
	}
}

// The other half of the split: a live session with an expired token is refused
// unless the caller asks for expired tokens, and revocation has nothing to do
// with it.
func TestValidate_ExpiryIsCheckedIndependently(t *testing.T) {
	t.Parallel()

	cache := &revocationCacheStub{revoked: map[string]bool{}}
	past := time.Now().UTC().Add(-2 * time.Hour)
	issuer := newValidationHelper(t, cache, WithClock(func() time.Time { return past }))

	token, _ := issueFor(t, issuer)

	h := newValidationHelper(t, cache)

	if _, err := h.Validate(context.Background(), token, domain.ValidateOptions{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if _, err := h.Validate(context.Background(), token, domain.ValidateOptions{AllowExpired: true}); err != nil {
		t.Fatalf("expected the expired token to be readable on request, got %v", err)
	}
}

// Not knowing whether a session was revoked is not the same as knowing it was
// not, so a cache failure has to fail the validation.
func TestValidate_CacheFailureIsNotAPass(t *testing.T) {
	t.Parallel()

	cache := &revocationCacheStub{err: errors.New("hazelcast unreachable")}
	h := newValidationHelper(t, cache)

	token, _ := issueFor(t, h)

	if _, err := h.Validate(context.Background(), token, domain.ValidateOptions{}); err == nil {
		t.Fatal("expected a cache failure to refuse the token")
	}
}
