package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

type txKey struct{}

func initTestLogger(t *testing.T) {
	t.Helper()
	if err := logger.Init(logger.Config{
		AppName:     "user-service-test",
		Environment: "test",
		Version:     "test",
		Level:       "debug",
	}); err != nil {
		t.Fatalf("init logger: %v", err)
	}
}

type txManagerStub struct {
	commitErr error

	beginCalls    int
	commitCalls   int
	rollbackCalls int
}

func (m *txManagerStub) Begin(ctx context.Context) context.Context {
	m.beginCalls++
	return context.WithValue(ctx, txKey{}, true)
}

func (m *txManagerStub) Commit(context.Context) error {
	m.commitCalls++
	return m.commitErr
}

func (m *txManagerStub) Rollback(context.Context) error {
	m.rollbackCalls++
	return nil
}

type sessionRepoStub struct {
	list    []domain.Session
	listErr error

	// created captures rows written by issueSession, so a test can assert what
	// actually reaches the sessions table.
	created []domain.Session

	find    map[domain.SessionID]domain.Session
	findErr map[domain.SessionID]error

	deleteErr map[domain.SessionID]error
	deleted   []domain.SessionID
}

func (r *sessionRepoStub) Create(_ context.Context, in *domain.Session) error {
	r.created = append(r.created, *in)
	return nil
}

func (r *sessionRepoStub) FindByUUID(_ context.Context, id domain.SessionID) (domain.Session, error) {
	if err, ok := r.findErr[id]; ok {
		return domain.Session{}, err
	}
	if s, ok := r.find[id]; ok {
		return s, nil
	}
	return domain.Session{}, domain.ErrRecordNotFound
}

func (r *sessionRepoStub) FindByUUIDForUpdate(ctx context.Context, id domain.SessionID) (domain.Session, error) {
	return r.FindByUUID(ctx, id)
}

func (r *sessionRepoStub) ListByUserID(context.Context, domain.ID) ([]domain.Session, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := make([]domain.Session, len(r.list))
	copy(out, r.list)
	return out, nil
}

func (r *sessionRepoStub) DeleteByUUID(_ context.Context, id domain.SessionID) error {
	if err, ok := r.deleteErr[id]; ok {
		return err
	}
	r.deleted = append(r.deleted, id)
	return nil
}

func (r *sessionRepoStub) DeleteByUserID(context.Context, domain.ID) error { return nil }

func (r *sessionRepoStub) DeleteUnusableBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (r *sessionRepoStub) WithTxFromContext(context.Context) domain.SessionRepository { return r }

type revokedSessionRepoStub struct {
	createErr map[domain.SessionID]error
	created   []domain.SessionID
	reasons   map[domain.SessionID]domain.SessionRevocationReason
	hashes    map[domain.SessionID]string

	// find backs FindByUUID: what a lookup of an already-revoked session returns.
	find map[domain.SessionID]domain.RevokedSession
}

func (r *revokedSessionRepoStub) Create(_ context.Context, in *domain.RevokedSession) error {
	if err, ok := r.createErr[in.UUID]; ok {
		return err
	}
	r.created = append(r.created, in.UUID)
	if r.reasons == nil {
		r.reasons = make(map[domain.SessionID]domain.SessionRevocationReason)
	}
	r.reasons[in.UUID] = in.Reason
	if r.hashes == nil {
		r.hashes = make(map[domain.SessionID]string)
	}
	r.hashes[in.UUID] = in.RefreshTokenHash
	return nil
}

func (r *revokedSessionRepoStub) FindByUUID(_ context.Context, uuid domain.SessionID) (domain.RevokedSession, error) {
	if revoked, ok := r.find[uuid]; ok {
		return revoked, nil
	}
	return domain.RevokedSession{}, domain.ErrRecordNotFound
}

func (r *revokedSessionRepoStub) DeleteCreatedBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (r *revokedSessionRepoStub) WithTxFromContext(context.Context) domain.RevokedSessionRepository {
	return r
}

type authLogRepoStub struct {
	created []domain.AuthLogStatus
}

func (r *authLogRepoStub) Create(_ context.Context, in *domain.AuthLog) error {
	r.created = append(r.created, in.Status)
	return nil
}

func (r *authLogRepoStub) WithTxFromContext(context.Context) domain.AuthLogRepository { return r }

type cacheRepoStub struct {
	updateErr error
	updated   []string
}

func (r *cacheRepoStub) Get(context.Context, string) (domain.RevokedSession, error) {
	return domain.RevokedSession{}, nil
}

func (r *cacheRepoStub) Exists(context.Context, string) (bool, error) { return false, nil }

func (r *cacheRepoStub) Update(context.Context, string, domain.RevokedSession) error { return nil }

func (r *cacheRepoStub) UpdateWithTTL(_ context.Context, key string, _ domain.RevokedSession, _ time.Duration) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.updated = append(r.updated, key)
	return nil
}

func (r *cacheRepoStub) GetWithRefresh(context.Context, string) (domain.RevokedSession, error) {
	return domain.RevokedSession{}, nil
}

func (r *cacheRepoStub) RefreshAndGet(context.Context, string) (domain.RevokedSession, error) {
	return domain.RevokedSession{}, nil
}

func (r *cacheRepoStub) DeleteKey(context.Context, string) error { return nil }

func TestSessionCtrlRunTx_Success(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}
	ctrl := SessionCtrl{transactionManager: tm}

	gotTx := false
	err := ctrl.runTx(context.Background(), func(ctx context.Context) error {
		_, gotTx = ctx.Value(txKey{}).(bool)
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !gotTx {
		t.Fatalf("expected tx context marker in function")
	}
	if tm.beginCalls != 1 || tm.commitCalls != 1 || tm.rollbackCalls != 0 {
		t.Fatalf("unexpected tx calls: begin=%d commit=%d rollback=%d", tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
	}
}

func TestSessionCtrlRunTx_FnErrorRollsBack(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}
	ctrl := SessionCtrl{transactionManager: tm}

	sentinel := errors.New("fn failed")
	err := ctrl.runTx(context.Background(), func(context.Context) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if tm.beginCalls != 1 || tm.commitCalls != 0 || tm.rollbackCalls != 1 {
		t.Fatalf("unexpected tx calls: begin=%d commit=%d rollback=%d", tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
	}
}

func TestSessionCtrlRunTx_CommitErrorRollsBack(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{commitErr: errors.New("commit failed")}
	ctrl := SessionCtrl{transactionManager: tm}

	err := ctrl.runTx(context.Background(), func(context.Context) error { return nil })
	if err == nil {
		t.Fatalf("expected error on commit failure")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.DatabaseError {
		t.Fatalf("expected DatabaseError code, got %d", er.Code)
	}
	if tm.beginCalls != 1 || tm.commitCalls != 1 || tm.rollbackCalls != 1 {
		t.Fatalf("unexpected tx calls: begin=%d commit=%d rollback=%d", tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
	}
}

func TestRevokeAllOnBlock_EndsEverySessionAsAdminKick(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(77)
	first := domain.Session{UUID: domain.SessionID("first"), UserID: userID}
	second := domain.Session{UUID: domain.SessionID("second"), UserID: userID}

	sessions := &sessionRepoStub{list: []domain.Session{first, second}}
	revoked := &revokedSessionRepoStub{}
	cacheRepo := &cacheRepoStub{}
	tm := &txManagerStub{}

	ctrl := SessionCtrl{
		sessions:           sessions,
		revokedSessions:    revoked,
		authLogs:           &authLogRepoStub{},
		revocationCache:    cacheRepo,
		transactionManager: tm,
	}

	if err := ctrl.RevokeAllOnBlock(context.Background(), userID); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Blocking spares nothing -- unlike a password change, the account holder is
	// not the one being trusted here.
	if len(revoked.created) != 2 {
		t.Fatalf("expected both sessions revoked, got %+v", revoked.created)
	}
	for _, id := range []domain.SessionID{first.UUID, second.UUID} {
		if revoked.reasons[id] != domain.SessionRevocationReasonAdminKick {
			t.Fatalf("expected reason admin_kick for %s, got %s", id, revoked.reasons[id])
		}
	}
	if len(cacheRepo.updated) != 2 {
		t.Fatalf("expected both marked revoked in cache, got %+v", cacheRepo.updated)
	}

	// It runs on the caller's transaction, which is what lets Block commit the
	// status change and the revocation together.
	if tm.beginCalls != 0 || tm.commitCalls != 0 || tm.rollbackCalls != 0 {
		t.Fatalf("expected no transaction of its own: begin=%d commit=%d rollback=%d",
			tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
	}
}

func TestRevokeAllOnPasswordChange_KeepsCallerRevokesRest(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	current := domain.Session{UUID: domain.SessionID("current"), UserID: userID}
	phone := domain.Session{UUID: domain.SessionID("phone"), UserID: userID}
	stolen := domain.Session{UUID: domain.SessionID("stolen"), UserID: userID}

	sessions := &sessionRepoStub{list: []domain.Session{current, phone, stolen}}
	revoked := &revokedSessionRepoStub{}
	authLogs := &authLogRepoStub{}
	cacheRepo := &cacheRepoStub{}

	ctrl := SessionCtrl{
		sessions:        sessions,
		revokedSessions: revoked,
		authLogs:        authLogs,
		revocationCache: cacheRepo,
	}

	err := ctrl.RevokeAllOnPasswordChange(context.Background(), domain.AuthenticatedSession{
		UserID:    userID,
		SessionID: current.UUID,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(revoked.created) != 2 {
		t.Fatalf("expected 2 revoked sessions, got %+v", revoked.created)
	}
	for _, id := range []domain.SessionID{phone.UUID, stolen.UUID} {
		if reason, ok := revoked.reasons[id]; !ok {
			t.Fatalf("expected session %s to be revoked, got %+v", id, revoked.created)
		} else if reason != domain.SessionRevocationReasonPasswordChange {
			t.Fatalf("expected reason password_change for %s, got %s", id, reason)
		}
	}
	if _, ok := revoked.reasons[current.UUID]; ok {
		t.Fatalf("the session performing the change must survive, got %+v", revoked.created)
	}

	if len(sessions.deleted) != 2 {
		t.Fatalf("expected 2 deleted sessions, got %+v", sessions.deleted)
	}
	for _, id := range sessions.deleted {
		if id == current.UUID {
			t.Fatalf("the session performing the change must not be deleted")
		}
	}

	if len(cacheRepo.updated) != 2 {
		t.Fatalf("expected 2 revocation cache marks, got %+v", cacheRepo.updated)
	}

	// One entry for the rotation, not one per revoked session, and within the
	// status range admin-service can decode.
	if len(authLogs.created) != 1 || authLogs.created[0] != domain.AuthLogStatusLogoutAll {
		t.Fatalf("expected a single LogoutAll auth log, got %+v", authLogs.created)
	}
}

func TestRevokeAllOnPasswordChange_OnlyCallerSessionWritesNoAuditEntry(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	current := domain.Session{UUID: domain.SessionID("current"), UserID: userID}

	sessions := &sessionRepoStub{list: []domain.Session{current}}
	revoked := &revokedSessionRepoStub{}
	authLogs := &authLogRepoStub{}

	ctrl := SessionCtrl{
		sessions:        sessions,
		revokedSessions: revoked,
		authLogs:        authLogs,
		revocationCache: &cacheRepoStub{},
	}

	err := ctrl.RevokeAllOnPasswordChange(context.Background(), domain.AuthenticatedSession{
		UserID:    userID,
		SessionID: current.UUID,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(revoked.created) != 0 || len(sessions.deleted) != 0 {
		t.Fatalf("expected nothing revoked, got revoked=%+v deleted=%+v", revoked.created, sessions.deleted)
	}
	if len(authLogs.created) != 0 {
		t.Fatalf("expected no auth log when nothing was revoked, got %+v", authLogs.created)
	}
}

func TestRevokeAllOnPasswordChange_OwnsNoTransaction(t *testing.T) {
	initTestLogger(t)

	// The method must run on the caller's transaction. If it ever starts opening
	// its own, the credential update and the revocation stop being atomic and the
	// window this closes reopens.
	tm := &txManagerStub{}
	userID := domain.NewIDFromUint64(42)

	ctrl := SessionCtrl{
		sessions: &sessionRepoStub{list: []domain.Session{
			{UUID: domain.SessionID("current"), UserID: userID},
			{UUID: domain.SessionID("other"), UserID: userID},
		}},
		revokedSessions:    &revokedSessionRepoStub{},
		authLogs:           &authLogRepoStub{},
		revocationCache:    &cacheRepoStub{},
		transactionManager: tm,
	}

	if err := ctrl.RevokeAllOnPasswordChange(context.Background(), domain.AuthenticatedSession{
		UserID:    userID,
		SessionID: domain.SessionID("current"),
	}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if tm.beginCalls != 0 || tm.commitCalls != 0 || tm.rollbackCalls != 0 {
		t.Fatalf("expected no transaction of its own: begin=%d commit=%d rollback=%d",
			tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
	}
}

func TestRevokeAllOnPasswordChange_CacheFailurePropagates(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)

	ctrl := SessionCtrl{
		sessions: &sessionRepoStub{list: []domain.Session{
			{UUID: domain.SessionID("current"), UserID: userID},
			{UUID: domain.SessionID("other"), UserID: userID},
		}},
		revokedSessions: &revokedSessionRepoStub{},
		authLogs:        &authLogRepoStub{},
		revocationCache: &cacheRepoStub{updateErr: errors.New("hazelcast unavailable")},
	}

	err := ctrl.RevokeAllOnPasswordChange(context.Background(), domain.AuthenticatedSession{
		UserID:    userID,
		SessionID: domain.SessionID("current"),
	})
	if err == nil {
		t.Fatalf("expected an error when the revocation cache write fails")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.CacheError {
		t.Fatalf("expected CacheError code, got %d", er.Code)
	}
}

func TestLogoutAll_WritesOneAuditEntryForEverySession(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(88)
	current := domain.Session{UUID: domain.SessionID("current"), UserID: userID}
	phone := domain.Session{UUID: domain.SessionID("phone"), UserID: userID}
	tablet := domain.Session{UUID: domain.SessionID("tablet"), UserID: userID}

	sessions := &sessionRepoStub{list: []domain.Session{current, phone, tablet}}
	revoked := &revokedSessionRepoStub{}
	authLogs := &authLogRepoStub{}
	cacheRepo := &cacheRepoStub{}
	tm := &txManagerStub{}

	ctrl := SessionCtrl{
		sessions:           sessions,
		revokedSessions:    revoked,
		authLogs:           authLogs,
		revocationCache:    cacheRepo,
		transactionManager: tm,
	}

	err := ctrl.LogoutAll(context.Background(), domain.AuthenticatedSession{
		UserID:    userID,
		SessionID: current.UUID,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Logging out everywhere spares nothing, the requesting session included.
	if len(revoked.created) != 3 || len(sessions.deleted) != 3 || len(cacheRepo.updated) != 3 {
		t.Fatalf("expected all three sessions ended, got revoked=%+v deleted=%+v cache=%+v",
			revoked.created, sessions.deleted, cacheRepo.updated)
	}
	for _, id := range []domain.SessionID{current.UUID, phone.UUID, tablet.UUID} {
		if revoked.reasons[id] != domain.SessionRevocationReasonLogout {
			t.Fatalf("expected reason logout for %s, got %s", id, revoked.reasons[id])
		}
	}

	// The point of the fix: one row for the request, not one per session. The
	// rows the loop used to write were indistinguishable -- auth_logs has no
	// session column -- so N of them said nothing N-1 of them had not.
	if len(authLogs.created) != 1 || authLogs.created[0] != domain.AuthLogStatusLogoutAll {
		t.Fatalf("expected a single LogoutAll auth log, got %+v", authLogs.created)
	}
}

func TestLogoutAll_FailedRevocationWritesNoAuditEntry(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(89)
	first := domain.Session{UUID: domain.SessionID("first"), UserID: userID}
	second := domain.Session{UUID: domain.SessionID("second"), UserID: userID}

	revoked := &revokedSessionRepoStub{
		createErr: map[domain.SessionID]error{second.UUID: errors.New("revoked_sessions unavailable")},
	}
	authLogs := &authLogRepoStub{}
	tm := &txManagerStub{}

	ctrl := SessionCtrl{
		sessions:           &sessionRepoStub{list: []domain.Session{first, second}},
		revokedSessions:    revoked,
		authLogs:           authLogs,
		revocationCache:    &cacheRepoStub{},
		transactionManager: tm,
	}

	err := ctrl.LogoutAll(context.Background(), domain.AuthenticatedSession{
		UserID:    userID,
		SessionID: first.UUID,
	})
	if err == nil {
		t.Fatal("expected the revocation failure to be reported")
	}

	// An audit row claiming every session was ended must not outlive a sweep
	// that did not finish.
	if len(authLogs.created) != 0 {
		t.Fatalf("expected no auth log, got %+v", authLogs.created)
	}
	if tm.commitCalls != 0 || tm.rollbackCalls != 1 {
		t.Fatalf("expected a rollback: commit=%d rollback=%d", tm.commitCalls, tm.rollbackCalls)
	}
}
