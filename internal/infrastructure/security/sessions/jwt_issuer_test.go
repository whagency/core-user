package sessions

import (
	"context"
	"errors"
	"testing"

	"user-service/internal/domain"

	"github.com/whagency/core-common/testkit/loggertest"
)

// newIssuerHelper builds a helper over a fixed key. The key is what makes the
// scenario real: admin-service holds the same JWT_ACCESS_SECRET, so a token it
// signs verifies here and only the claims can tell the two apart.
func newIssuerHelper(t *testing.T, issuer string, additional ...string) *JWTSessionHelper {
	t.Helper()
	loggertest.Init(t, "user-service-test")

	opts := []Option{WithIssuer(issuer)}
	if len(additional) > 0 {
		opts = append(opts, WithAdditionalIssuers(additional...))
	}

	h, err := NewJWTSessionHelper([]byte("0123456789abcdef0123456789abcdef"), nil, opts...)
	if err != nil {
		t.Fatalf("NewJWTSessionHelper: %v", err)
	}

	return h
}

// mint signs a token the way the named issuer would, using the shared key.
func mint(t *testing.T, issuer string) string {
	t.Helper()

	token, err := newIssuerHelper(t, issuer).Issue(context.Background(), domain.SessionIssueParams{
		UserID: domain.NewIDFromUint64(11),
	})
	if err != nil {
		t.Fatalf("Issue as %q: %v", issuer, err)
	}

	return token.AccessToken
}

func TestParseToken_IssuerIsRequiredWhenConfigured(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		additional []string
		tokenFrom  string
		wantErr    bool
	}{
		{
			name:      "own tokens pass",
			tokenFrom: "user-service",
		},
		{
			// The defect: the check ran only when iss was present, so a token
			// carrying no iss at all was accepted from anyone holding the key.
			name:      "a token with no issuer is rejected",
			tokenFrom: "",
			wantErr:   true,
		},
		{
			name:      "an unknown issuer is rejected",
			tokenFrom: "some-other-service",
			wantErr:   true,
		},
		{
			name:       "a named additional issuer passes",
			additional: []string{"admin-service"},
			tokenFrom:  "admin-service",
			wantErr:    false,
		},
		{
			name:       "naming one issuer does not admit another",
			additional: []string{"admin-service"},
			tokenFrom:  "metrics-service",
			wantErr:    true,
		},
		{
			// A blank entry in JWT_ADDITIONAL_ISSUERS must not become a license
			// for tokens with no iss.
			name:       "a blank additional issuer admits nothing",
			additional: []string{"  ", ""},
			tokenFrom:  "",
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newIssuerHelper(t, "user-service", tc.additional...)

			_, err := h.parseTokenAndValidate(context.Background(), mint(t, tc.tokenFrom))
			if tc.wantErr {
				if !errors.Is(err, ErrIssuerMismatch) {
					t.Fatalf("expected ErrIssuerMismatch, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the token to validate, got %v", err)
			}
		})
	}
}

// A service that configures no issuer of its own checks nothing, which is what
// keeps the option optional rather than a trap for a helper built without it.
func TestParseToken_NoConfiguredIssuerChecksNothing(t *testing.T) {
	t.Parallel()

	h := newIssuerHelper(t, "")

	for _, from := range []string{"", "anyone-at-all"} {
		if _, err := h.parseTokenAndValidate(context.Background(), mint(t, from)); err != nil {
			t.Fatalf("expected a token from %q to pass an unconfigured issuer check, got %v", from, err)
		}
	}
}
