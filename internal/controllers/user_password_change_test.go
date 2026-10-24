package controllers

import (
	"context"
	"testing"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
)

const (
	passwordChangeCurrent = "Current!123"
	passwordChangeNew     = "BrandNew!456"
	passwordChangeHash    = "hash-of-current"
	passwordChangeNewHash = "hash-of-new"

	// passwordChangeCallerSession is the session performing the change: the one
	// session a rotation must leave alive.
	passwordChangeCallerSession = domain.SessionID("current")
)

type passwordChangeCredentialsStub struct {
	credential domain.Credential
	findErr    error
	updated    []string

	// lockedCredential, when set, is what the locked read returns instead of
	// credential -- how a concurrent change that landed in between looks.
	lockedCredential *domain.Credential
}

func (s *passwordChangeCredentialsStub) Create(context.Context, *domain.Credential) error { return nil }

func (s *passwordChangeCredentialsStub) FindByUserID(context.Context, domain.ID) (domain.Credential, error) {
	return s.credential, nil
}

func (s *passwordChangeCredentialsStub) FindByUserIDForUpdate(context.Context, domain.ID) (domain.Credential, error) {
	if s.findErr != nil {
		return domain.Credential{}, s.findErr
	}
	if s.lockedCredential != nil {
		return *s.lockedCredential, nil
	}
	return s.credential, nil
}

func (s *passwordChangeCredentialsStub) Update(_ context.Context, in *domain.Credential) error {
	s.updated = append(s.updated, in.PasswordHash)
	return nil
}

func (s *passwordChangeCredentialsStub) RegisterFailedLogin(context.Context, domain.ID, domain.LoginLockPolicy) (domain.Credential, error) {
	return domain.Credential{}, nil
}

func (s *passwordChangeCredentialsStub) ClearLoginFailures(context.Context, domain.ID) error {
	return nil
}

func (s *passwordChangeCredentialsStub) WithTxFromContext(context.Context) domain.CredentialRepository {
	return s
}

type passwordChangeLogsStub struct {
	created int
}

func (s *passwordChangeLogsStub) Create(context.Context, *domain.PasswordChangeLog) error {
	s.created++
	return nil
}

func (s *passwordChangeLogsStub) FindLastByUserID(context.Context, domain.ID) (domain.PasswordChangeLog, error) {
	return domain.PasswordChangeLog{}, domain.ErrRecordNotFound
}

func (s *passwordChangeLogsStub) WithTxFromContext(context.Context) domain.PasswordChangeLogRepository {
	return s
}

// passwordChangeHelperStub matches only the current password, so the reuse check
// on the new one comes back false the way it would in production.
type passwordChangeHelperStub struct{}

func (s *passwordChangeHelperStub) Hash(string) (string, error) { return passwordChangeNewHash, nil }

func (s *passwordChangeHelperStub) Verify(password, hashed string) (bool, error) {
	return password == passwordChangeCurrent && hashed == passwordChangeHash, nil
}

func (s *passwordChangeHelperStub) Algorithm() domain.CredentialAlgorithm {
	return domain.CredentialAlgorithmBcrypt
}

type passwordChangeFixture struct {
	ctrl        UserCtrl
	tx          *txManagerStub
	credentials *passwordChangeCredentialsStub
	changeLogs  *passwordChangeLogsStub
	sessions    *sessionRepoStub
	revoked     *revokedSessionRepoStub
	authLogs    *authLogRepoStub
	cache       *cacheRepoStub
}

// newPasswordChangeFixture wires the real SessionCtrl rather than a fake one:
// the point of the test is that the rotation and the revocation share a
// transaction, and a fake controller would assert nothing about that.
func newPasswordChangeFixture(userID domain.ID, stored []domain.Session, cacheRepo *cacheRepoStub) passwordChangeFixture {
	tx := &txManagerStub{}
	credentials := &passwordChangeCredentialsStub{
		credential: domain.Credential{UserID: userID, PasswordHash: passwordChangeHash},
	}
	changeLogs := &passwordChangeLogsStub{}
	sessions := &sessionRepoStub{list: stored}
	revoked := &revokedSessionRepoStub{}
	authLogs := &authLogRepoStub{}

	sessionCtrl := SessionCtrl{
		sessions:        sessions,
		revokedSessions: revoked,
		authLogs:        authLogs,
		revocationCache: cacheRepo,
	}

	return passwordChangeFixture{
		ctrl: UserCtrl{
			credentials:        credentials,
			passwordChangeLogs: changeLogs,
			passwordHelper:     &passwordChangeHelperStub{},
			sessionCtrl:        sessionCtrl,
			transactionManager: tx,
		},
		tx:          tx,
		credentials: credentials,
		changeLogs:  changeLogs,
		sessions:    sessions,
		revoked:     revoked,
		authLogs:    authLogs,
		cache:       cacheRepo,
	}
}

func passwordChangeParams(userID domain.ID) domain.PasswordChangeParams {
	return domain.PasswordChangeParams{
		UserID:          userID,
		SessionID:       passwordChangeCallerSession,
		CurrentPassword: passwordChangeCurrent,
		NewPassword:     passwordChangeNew,
	}
}

func TestChangePassword_RevokesEveryOtherSession(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(9)
	current := passwordChangeCallerSession

	f := newPasswordChangeFixture(userID, []domain.Session{
		{UUID: current, UserID: userID},
		{UUID: domain.SessionID("stolen"), UserID: userID},
		{UUID: domain.SessionID("old-phone"), UserID: userID},
	}, &cacheRepoStub{})

	if err := f.ctrl.ChangePassword(context.Background(), passwordChangeParams(userID)); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(f.credentials.updated) != 1 || f.credentials.updated[0] != passwordChangeNewHash {
		t.Fatalf("expected the password hash to be rotated once, got %+v", f.credentials.updated)
	}
	if f.changeLogs.created != 1 {
		t.Fatalf("expected one password change log, got %d", f.changeLogs.created)
	}

	if len(f.revoked.created) != 2 {
		t.Fatalf("expected the two other sessions revoked, got %+v", f.revoked.created)
	}
	for id, reason := range f.revoked.reasons {
		if reason != domain.SessionRevocationReasonPasswordChange {
			t.Fatalf("expected reason password_change for %s, got %s", id, reason)
		}
	}
	if _, ok := f.revoked.reasons[current]; ok {
		t.Fatalf("the caller's own session must survive the rotation")
	}

	// Everything above landed in one transaction, committed once.
	if f.tx.beginCalls != 1 || f.tx.commitCalls != 1 || f.tx.rollbackCalls != 0 {
		t.Fatalf("expected a single committed transaction: begin=%d commit=%d rollback=%d",
			f.tx.beginCalls, f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

func TestChangePassword_WrongCurrentPasswordRevokesNothing(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(9)
	current := passwordChangeCallerSession

	f := newPasswordChangeFixture(userID, []domain.Session{
		{UUID: current, UserID: userID},
		{UUID: domain.SessionID("other"), UserID: userID},
	}, &cacheRepoStub{})

	in := passwordChangeParams(userID)
	in.CurrentPassword = "not-the-password"

	err := f.ctrl.ChangePassword(context.Background(), in)
	if err == nil {
		t.Fatalf("expected an error for a wrong current password")
	}
	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != svcErrors.PasswordChangeCurrentPasswordInvalidError {
		t.Fatalf("expected PasswordChangeCurrentPasswordInvalidError, got %d", er.Code)
	}

	// A failed guess must not become a way to sign other devices out.
	if len(f.revoked.created) != 0 || len(f.sessions.deleted) != 0 {
		t.Fatalf("expected no revocation, got revoked=%+v deleted=%+v", f.revoked.created, f.sessions.deleted)
	}
	// The verification now happens before the transaction opens, so a wrong
	// password costs no transaction at all -- not even one to roll back.
	if f.tx.beginCalls != 0 {
		t.Fatalf("a wrong password must not open a transaction, got begin=%d", f.tx.beginCalls)
	}
	if f.tx.commitCalls != 0 {
		t.Fatalf("expected no commit, got %d", f.tx.commitCalls)
	}
}

func TestChangePassword_RevocationFailureAbortsTheRotation(t *testing.T) {
	initTestLogger(t)

	// The whole reason the revocation runs inside the transaction: if it cannot be
	// carried out, the password must not change either. Committing the new
	// password while the old sessions live on is the exact state this fix exists
	// to prevent.
	userID := domain.NewIDFromUint64(9)
	current := passwordChangeCallerSession

	f := newPasswordChangeFixture(userID, []domain.Session{
		{UUID: current, UserID: userID},
		{UUID: domain.SessionID("stolen"), UserID: userID},
	}, &cacheRepoStub{updateErr: context.DeadlineExceeded})

	err := f.ctrl.ChangePassword(context.Background(), passwordChangeParams(userID))
	if err == nil {
		t.Fatalf("expected an error when the revocation cannot be completed")
	}
	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.CacheError {
		t.Fatalf("expected the revocation failure to surface as CacheError, got %d", er.Code)
	}

	if f.tx.commitCalls != 0 {
		t.Fatalf("expected no commit, got %d", f.tx.commitCalls)
	}
	if f.tx.rollbackCalls != 1 {
		t.Fatalf("expected exactly one rollback, got %d", f.tx.rollbackCalls)
	}
}

func TestChangePassword_SoleSessionSurvives(t *testing.T) {
	initTestLogger(t)

	// A user with one device keeps it. Signing them out of the browser that just
	// changed the password would be a regression the frontend does not expect.
	userID := domain.NewIDFromUint64(9)
	current := passwordChangeCallerSession

	f := newPasswordChangeFixture(userID, []domain.Session{
		{UUID: current, UserID: userID},
	}, &cacheRepoStub{})

	if err := f.ctrl.ChangePassword(context.Background(), passwordChangeParams(userID)); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(f.revoked.created) != 0 || len(f.sessions.deleted) != 0 {
		t.Fatalf("expected nothing revoked, got revoked=%+v deleted=%+v", f.revoked.created, f.sessions.deleted)
	}
	if len(f.cache.updated) != 0 {
		t.Fatalf("expected no revocation cache marks, got %+v", f.cache.updated)
	}
	if f.tx.commitCalls != 1 {
		t.Fatalf("expected the rotation to commit, got commit=%d", f.tx.commitCalls)
	}
}

// txPhase is shared between the transaction manager and the password helper so a
// test can see which side of Begin the expensive work happened on.
type txPhase struct{ open bool }

type phaseTrackingTxManager struct {
	phase *txPhase

	beginCalls    int
	commitCalls   int
	rollbackCalls int
}

func (m *phaseTrackingTxManager) Begin(ctx context.Context) context.Context {
	m.beginCalls++
	m.phase.open = true
	return context.WithValue(ctx, txKey{}, true)
}

func (m *phaseTrackingTxManager) Commit(context.Context) error {
	m.commitCalls++
	m.phase.open = false
	return nil
}

func (m *phaseTrackingTxManager) Rollback(context.Context) error {
	m.rollbackCalls++
	m.phase.open = false
	return nil
}

// phaseTrackingPasswordHelper notes whether bcrypt was asked to run while a
// transaction was open.
type phaseTrackingPasswordHelper struct {
	phase *txPhase

	hashedInTx   bool
	verifiedInTx bool
}

func (h *phaseTrackingPasswordHelper) Hash(string) (string, error) {
	if h.phase.open {
		h.hashedInTx = true
	}
	return passwordChangeNewHash, nil
}

func (h *phaseTrackingPasswordHelper) Verify(password, hashed string) (bool, error) {
	if h.phase.open {
		h.verifiedInTx = true
	}
	return password == passwordChangeCurrent && hashed == passwordChangeHash, nil
}

func (h *phaseTrackingPasswordHelper) Algorithm() domain.CredentialAlgorithm {
	return domain.CredentialAlgorithmBcrypt
}

// bcrypt is deliberately slow -- around 135ms for the two verifies and the hash
// this flow runs. Doing it inside the transaction pinned a pooled connection and
// a FOR UPDATE lock on the credential row for that whole time, for work the
// database has no part in.
func TestChangePassword_HashingHappensOutsideTheTransaction(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(9)
	phase := &txPhase{}
	helper := &phaseTrackingPasswordHelper{phase: phase}
	tx := &phaseTrackingTxManager{phase: phase}

	credentials := &passwordChangeCredentialsStub{
		credential: domain.Credential{UserID: userID, PasswordHash: passwordChangeHash},
	}

	ctrl := UserCtrl{
		credentials:        credentials,
		passwordChangeLogs: &passwordChangeLogsStub{},
		passwordHelper:     helper,
		sessionCtrl: SessionCtrl{
			sessions:        &sessionRepoStub{},
			revokedSessions: &revokedSessionRepoStub{},
			authLogs:        &authLogRepoStub{},
			revocationCache: &cacheRepoStub{},
		},
		transactionManager: tx,
	}

	if err := ctrl.ChangePassword(context.Background(), passwordChangeParams(userID)); err != nil {
		t.Fatalf("expected the change to succeed, got %v", err)
	}

	if helper.verifiedInTx {
		t.Error("the current-password and reuse checks must run before the transaction opens")
	}
	if helper.hashedInTx {
		t.Error("the new password must be hashed before the transaction opens")
	}
	if tx.commitCalls != 1 {
		t.Errorf("expected the change to commit once, got %d", tx.commitCalls)
	}
}

// Verifying outside the lock is only safe because of the re-check inside it.
func TestChangePassword_ConcurrentChangeIsRejected(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(9)

	// Another change committed between the unlocked read and the locked one, so
	// the password this request proved knowledge of is no longer the account's.
	movedOn := domain.Credential{UserID: userID, PasswordHash: "someone-elses-new-hash"}

	f := newPasswordChangeFixture(userID, []domain.Session{
		{UUID: passwordChangeCallerSession, UserID: userID},
	}, &cacheRepoStub{})
	f.credentials.lockedCredential = &movedOn

	err := f.ctrl.ChangePassword(context.Background(), passwordChangeParams(userID))
	if err == nil {
		t.Fatal("expected a superseded password not to be accepted")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.ConcurrencyConflictError {
		t.Fatalf("expected ConcurrencyConflictError, got %d", er.Code)
	}

	if len(f.credentials.updated) != 0 {
		t.Fatalf("the password must not be overwritten, got %+v", f.credentials.updated)
	}
	if f.tx.commitCalls != 0 || f.tx.rollbackCalls != 1 {
		t.Fatalf("expected a rollback and no commit: commit=%d rollback=%d",
			f.tx.commitCalls, f.tx.rollbackCalls)
	}
}
