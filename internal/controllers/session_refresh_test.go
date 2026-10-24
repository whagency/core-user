package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
)

// sessionHelperStub mints predictable tokens and hashes them the way the real
// helper does, so a test can reason about what should be stored.
type sessionHelperStub struct {
	issued domain.SessionToken
}

func (s *sessionHelperStub) Issue(context.Context, domain.SessionIssueParams) (domain.SessionToken, error) {
	return s.issued, nil
}

func (s *sessionHelperStub) Validate(context.Context, string, domain.ValidateOptions) (domain.AuthenticatedSession, error) {
	return domain.AuthenticatedSession{}, nil
}

func (s *sessionHelperStub) HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type refreshFixture struct {
	ctrl     SessionCtrl
	tx       *txManagerStub
	sessions *sessionRepoStub
	revoked  *revokedSessionRepoStub
	authLogs *authLogRepoStub
	cache    *cacheRepoStub
}

func newRefreshFixture(stored []domain.Session, alreadyRevoked map[domain.SessionID]domain.RevokedSession) refreshFixture {
	tx := &txManagerStub{}
	sessions := &sessionRepoStub{list: stored, find: map[domain.SessionID]domain.Session{}}
	for _, s := range stored {
		sessions.find[s.UUID] = s
	}
	revoked := &revokedSessionRepoStub{find: alreadyRevoked}
	authLogs := &authLogRepoStub{}
	cacheRepo := &cacheRepoStub{}

	return refreshFixture{
		ctrl: SessionCtrl{
			geoCtrl:         &registerGeoStub{},
			sessions:        sessions,
			revokedSessions: revoked,
			authLogs:        authLogs,
			revocationCache: cacheRepo,
			sessionHelper: &sessionHelperStub{issued: domain.SessionToken{
				SessionID:        domain.SessionID("fresh"),
				AccessToken:      "access",
				AccessExpiresAt:  time.Now().UTC().Add(15 * time.Minute),
				RefreshToken:     "fresh-refresh-token",
				RefreshExpiresAt: time.Now().UTC().Add(720 * time.Hour),
			}},
			transactionManager: tx,
		},
		tx:       tx,
		sessions: sessions,
		revoked:  revoked,
		authLogs: authLogs,
		cache:    cacheRepo,
	}
}

func refreshParams(userID domain.ID, sessionID domain.SessionID, token string) domain.SessionRefreshParams {
	return domain.SessionRefreshParams{
		AuthSession:  domain.AuthenticatedSession{UserID: userID, SessionID: sessionID},
		RefreshToken: token,
	}
}

func TestRefreshSession_PersistsOnlyTheHash(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(5)
	future := time.Now().UTC().Add(time.Hour)
	current := domain.Session{
		UUID:             domain.SessionID("current"),
		UserID:           userID,
		RefreshTokenHash: hashOf("valid-token"),
		RefreshExpireAt:  &future,
	}

	f := newRefreshFixture([]domain.Session{current}, nil)

	out, err := f.ctrl.RefreshSession(context.Background(), refreshParams(userID, current.UUID, "valid-token"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// The client gets the raw token...
	if out.RefreshToken != "fresh-refresh-token" {
		t.Fatalf("expected the raw token in the response, got %q", out.RefreshToken)
	}

	// ...and the table gets only its hash.
	if len(f.sessions.created) != 1 {
		t.Fatalf("expected one session row written, got %d", len(f.sessions.created))
	}
	got := f.sessions.created[0].RefreshTokenHash
	if got != hashOf("fresh-refresh-token") {
		t.Fatalf("stored value is not the hash of the issued token: %q", got)
	}
	if got == "fresh-refresh-token" {
		t.Fatal("the raw refresh token must never reach the sessions table")
	}

	// The rotated-away session keeps its hash, which is what reuse detection
	// later compares against.
	if f.revoked.hashes[current.UUID] != current.RefreshTokenHash {
		t.Fatalf("expected the revoked row to carry the old hash, got %q", f.revoked.hashes[current.UUID])
	}
	if f.revoked.reasons[current.UUID] != domain.SessionRevocationReasonRefresh {
		t.Fatalf("expected reason refresh, got %s", f.revoked.reasons[current.UUID])
	}
}

func TestRefreshSession_WrongTokenIsRejected(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(5)
	future := time.Now().UTC().Add(time.Hour)
	current := domain.Session{
		UUID:             domain.SessionID("current"),
		UserID:           userID,
		RefreshTokenHash: hashOf("valid-token"),
		RefreshExpireAt:  &future,
	}

	f := newRefreshFixture([]domain.Session{current}, nil)

	_, err := f.ctrl.RefreshSession(context.Background(), refreshParams(userID, current.UUID, "wrong-token"))
	if err == nil {
		t.Fatal("expected a wrong refresh token to be rejected")
	}
	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != svcErrors.UserSessionRefreshTokenInvalidError {
		t.Fatalf("expected UserSessionRefreshTokenInvalidError, got %d", er.Code)
	}
	if len(f.sessions.created) != 0 {
		t.Fatalf("no session may be issued for a wrong token, got %+v", f.sessions.created)
	}
}

func TestRefreshSession_ReplayedTokenRevokesEverything(t *testing.T) {
	initTestLogger(t)

	// The theft scenario: the token was already rotated once, so the session row
	// is gone and only the revoked row remembers its hash. Whoever arrives second
	// is holding a copy.
	userID := domain.NewIDFromUint64(5)
	stolen := domain.SessionID("rotated-away")

	survivor := domain.Session{
		UUID:             domain.SessionID("attackers-or-victims"),
		UserID:           userID,
		RefreshTokenHash: hashOf("some-other-token"),
	}
	anotherDevice := domain.Session{
		UUID:             domain.SessionID("another-device"),
		UserID:           userID,
		RefreshTokenHash: hashOf("third-token"),
	}

	f := newRefreshFixture(
		[]domain.Session{survivor, anotherDevice},
		map[domain.SessionID]domain.RevokedSession{
			stolen: {
				UUID:             stolen,
				UserID:           userID,
				Reason:           domain.SessionRevocationReasonRefresh,
				RefreshTokenHash: hashOf("replayed-token"),
			},
		},
	)

	_, err := f.ctrl.RefreshSession(context.Background(), refreshParams(userID, stolen, "replayed-token"))
	if err == nil {
		t.Fatal("expected a replayed refresh token to be rejected")
	}

	// The caller learns only that the token is no good.
	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != svcErrors.UserSessionRefreshTokenInvalidError {
		t.Fatalf("expected UserSessionRefreshTokenInvalidError, got %d", er.Code)
	}

	// Every session the user had is gone, marked as token reuse.
	if len(f.revoked.created) != 2 {
		t.Fatalf("expected both remaining sessions revoked, got %+v", f.revoked.created)
	}
	for _, id := range []domain.SessionID{survivor.UUID, anotherDevice.UUID} {
		if f.revoked.reasons[id] != domain.SessionRevocationReasonTokenReuse {
			t.Fatalf("expected reason token_reuse for %s, got %s", id, f.revoked.reasons[id])
		}
	}
	if len(f.authLogs.created) != 1 {
		t.Fatalf("expected a single audit entry for the sweep, got %+v", f.authLogs.created)
	}
	if len(f.sessions.created) != 0 {
		t.Fatalf("no new session may be issued on reuse, got %+v", f.sessions.created)
	}

	// The sweep happens on the request's own transaction, so it has to be
	// committed before the error is returned. Rolling back here would discard the
	// revocations and leave the stolen token's family alive — the failure this
	// whole path exists to prevent, hidden behind a passing-looking error.
	if f.tx.commitCalls != 1 || f.tx.rollbackCalls != 0 {
		t.Fatalf("the revocation must be committed, not rolled back: commit=%d rollback=%d",
			f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

func TestRefreshSession_StaleSessionIDAloneCannotForceRevocation(t *testing.T) {
	initTestLogger(t)

	// The reason detection compares the token and not just the id. Session ids
	// travel inside the access token, which users leave in logs and storage; if
	// the id were enough, anyone holding a stale JWT could sign a victim out of
	// every device at will.
	userID := domain.NewIDFromUint64(5)
	stolen := domain.SessionID("rotated-away")

	living := domain.Session{
		UUID:             domain.SessionID("living"),
		UserID:           userID,
		RefreshTokenHash: hashOf("some-other-token"),
	}

	f := newRefreshFixture(
		[]domain.Session{living},
		map[domain.SessionID]domain.RevokedSession{
			stolen: {
				UUID:             stolen,
				UserID:           userID,
				Reason:           domain.SessionRevocationReasonRefresh,
				RefreshTokenHash: hashOf("the-real-old-token"),
			},
		},
	)

	_, err := f.ctrl.RefreshSession(context.Background(), refreshParams(userID, stolen, "a-guess"))
	if err == nil {
		t.Fatal("expected the refresh to fail")
	}
	er, _ := appErrors.AsErrorResponse(err)
	if er.Code != appErrors.RecordNotFoundError {
		t.Fatalf("expected a plain not-found, got %d", er.Code)
	}

	if len(f.revoked.created) != 0 {
		t.Fatalf("nothing may be revoked without the matching token, got %+v", f.revoked.created)
	}
	if len(f.authLogs.created) != 0 {
		t.Fatalf("expected no audit entry, got %+v", f.authLogs.created)
	}
	if f.tx.commitCalls != 0 || f.tx.rollbackCalls != 1 {
		t.Fatalf("a plain not-found must roll back: commit=%d rollback=%d",
			f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

func TestRefreshSession_PreMigrationRevokedRowDoesNotTrigger(t *testing.T) {
	initTestLogger(t)

	// Rows revoked before the hash column existed carry no hash. They must read
	// as "unknown session", not as a match against the empty string.
	userID := domain.NewIDFromUint64(5)
	old := domain.SessionID("revoked-long-ago")

	f := newRefreshFixture(
		[]domain.Session{{UUID: domain.SessionID("living"), UserID: userID, RefreshTokenHash: hashOf("t")}},
		map[domain.SessionID]domain.RevokedSession{
			old: {UUID: old, UserID: userID, Reason: domain.SessionRevocationReasonLogout},
		},
	)

	_, err := f.ctrl.RefreshSession(context.Background(), refreshParams(userID, old, ""))
	if err == nil {
		t.Fatal("expected the refresh to fail")
	}
	er, _ := appErrors.AsErrorResponse(err)
	if er.Code != appErrors.RecordNotFoundError {
		t.Fatalf("expected a plain not-found, got %d", er.Code)
	}
	if len(f.revoked.created) != 0 {
		t.Fatalf("a hashless revoked row must not trigger a sweep, got %+v", f.revoked.created)
	}
}

func TestRefreshSession_KeepsTheOriginalSignInTime(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(6)
	future := time.Now().UTC().Add(time.Hour)
	signedInAt := time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)
	current := domain.Session{
		UUID:             domain.SessionID("current"),
		UserID:           userID,
		RefreshTokenHash: hashOf("valid-token"),
		RefreshExpireAt:  &future,
		CreatedAt:        signedInAt,
	}

	f := newRefreshFixture([]domain.Session{current}, nil)

	if _, err := f.ctrl.RefreshSession(context.Background(), refreshParams(userID, current.UUID, "valid-token")); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(f.sessions.created) != 1 {
		t.Fatalf("expected one session row written, got %d", len(f.sessions.created))
	}

	// A refresh replaces the row rather than updating it. The new row is the same
	// login continued, so it has to carry the sign-in time with it -- otherwise
	// the session list dates a month-old login to the last token rotation, which
	// for a fifteen-minute access token means "minutes ago", always.
	if got := f.sessions.created[0].CreatedAt; !got.Equal(signedInAt) {
		t.Fatalf("expected the refreshed row to keep createdAt %s, got %s", signedInAt, got)
	}
}

func TestIssueSession_FreshSignInLeavesTheStampToTheRepository(t *testing.T) {
	initTestLogger(t)

	// A first sign-in has no earlier session to continue. The zero value is what
	// tells the repository to stamp created_at itself.
	f := newRefreshFixture(nil, nil)

	if _, err := f.ctrl.Issue(context.Background(), &domain.SessionIssueParams{
		UserID: domain.NewIDFromUint64(7),
	}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(f.sessions.created) != 1 {
		t.Fatalf("expected one session row written, got %d", len(f.sessions.created))
	}
	if got := f.sessions.created[0].CreatedAt; !got.IsZero() {
		t.Fatalf("expected a zero createdAt on a fresh sign-in, got %s", got)
	}
}
