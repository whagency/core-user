package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"user-service/internal/domain"
	"user-service/internal/infrastructure/security/sessions"

	"github.com/gin-gonic/gin"
	"github.com/whagency/core-common/testkit/loggertest"
)

// sessionHelperSpy records what the middleware asked for and answers the way the
// real helper would for a session that has been revoked.
type sessionHelperSpy struct {
	got domain.ValidateOptions
}

func (s *sessionHelperSpy) Issue(context.Context, domain.SessionIssueParams) (domain.SessionToken, error) {
	return domain.SessionToken{}, nil
}

func (s *sessionHelperSpy) Validate(_ context.Context, _ string, opts domain.ValidateOptions) (domain.AuthenticatedSession, error) {
	s.got = opts
	if !opts.AllowRevoked {
		return domain.AuthenticatedSession{}, sessions.ErrRevoked
	}
	return domain.AuthenticatedSession{SessionID: domain.SessionID("s1"), UserID: domain.NewIDFromUint64(1)}, nil
}

func (s *sessionHelperSpy) HashRefreshToken(string) string { return "" }

func run(t *testing.T, mw gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	loggertest.Init(t, "user-service-test")
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(mw)
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer a.b.c")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// Waiving expiry is a routine need -- an access token can be seconds stale when a
// websocket handshake arrives. Waiving revocation is not, and no ordinary route
// may do it: a revoked session is one somebody signed out, an admin blocked, or a
// leaked refresh token cost the user.
func TestValidateUserSession_AllowExpiredDoesNotAdmitARevokedSession(t *testing.T) {
	t.Parallel()

	spy := &sessionHelperSpy{}
	w := run(t, ValidateUserSession(spy, ValidateSessionOptions{AllowExpired: true}))

	if !spy.got.AllowExpired {
		t.Fatal("AllowExpired did not reach the helper")
	}
	if spy.got.AllowRevoked {
		t.Fatal("the general middleware must never waive revocation")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected the revoked session to be refused, got %d", w.Code)
	}
}

// The refresh route is the single exception, and it exists so reuse detection can
// run: rotation revokes the session it replaces, so a replayed refresh token
// always arrives against a revoked one.
func TestValidateUserSessionForRefresh_AcceptsARevokedSession(t *testing.T) {
	t.Parallel()

	spy := &sessionHelperSpy{}
	w := run(t, ValidateUserSessionForRefresh(spy))

	if !spy.got.AllowRevoked || !spy.got.AllowExpired {
		t.Fatalf("the refresh guard must waive both, got %+v", spy.got)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected the request to reach the handler, got %d", w.Code)
	}
}
