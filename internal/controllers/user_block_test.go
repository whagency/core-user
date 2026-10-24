package controllers

import (
	"context"
	"errors"
	"testing"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
)

type blockUsersStub struct {
	userRepoGetProfileStub

	statusErr    error
	statusCalls  int
	statusWanted domain.UserStatus
}

func (s *blockUsersStub) UpdateStatus(_ context.Context, _ domain.ID, status domain.UserStatus) error {
	s.statusCalls++
	s.statusWanted = status
	return s.statusErr
}

func (s *blockUsersStub) WithTxFromContext(context.Context) domain.UserRepository { return s }

type blockFixture struct {
	ctrl     UserCtrl
	users    *blockUsersStub
	sessions *sessionRepoStub
	revoked  *revokedSessionRepoStub
	cache    *cacheRepoStub
	tx       *txManagerStub
}

func newBlockFixture(stored []domain.Session, statusErr error) blockFixture {
	users := &blockUsersStub{statusErr: statusErr}
	sessions := &sessionRepoStub{list: stored}
	revoked := &revokedSessionRepoStub{}
	cacheRepo := &cacheRepoStub{}
	tx := &txManagerStub{}

	return blockFixture{
		ctrl: UserCtrl{
			users: users,
			sessionCtrl: SessionCtrl{
				sessions:        sessions,
				revokedSessions: revoked,
				authLogs:        &authLogRepoStub{},
				revocationCache: cacheRepo,
			},
			transactionManager: tx,
		},
		users:    users,
		sessions: sessions,
		revoked:  revoked,
		cache:    cacheRepo,
		tx:       tx,
	}
}

func TestBlock_FlagsTheAccountAndEndsItsSessionsTogether(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	f := newBlockFixture([]domain.Session{
		{UUID: domain.SessionID("laptop"), UserID: userID},
		{UUID: domain.SessionID("phone"), UserID: userID},
	}, nil)

	if err := f.ctrl.Block(context.Background(), userID); err != nil {
		t.Fatalf("expected the block to succeed, got %v", err)
	}

	if f.users.statusWanted != domain.UserStatusBlockedSystem {
		t.Fatalf("expected the system-blocked status, got %s", f.users.statusWanted)
	}
	if len(f.revoked.created) != 2 {
		t.Fatalf("expected both sessions revoked, got %+v", f.revoked.created)
	}

	// One transaction covering both. The status is only consulted at sign-in, so
	// a flagged account whose sessions survived would carry on using the API with
	// the tokens it already had.
	if f.tx.beginCalls != 1 || f.tx.commitCalls != 1 || f.tx.rollbackCalls != 0 {
		t.Fatalf("expected a single committed transaction: begin=%d commit=%d rollback=%d",
			f.tx.beginCalls, f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

func TestBlock_UnknownUserIsReportedNotSilentlyAccepted(t *testing.T) {
	initTestLogger(t)

	// account-service calls this when a deposit or withdrawal trips AML. Answering
	// 200 for a user id that matched nothing told the caller someone dangerous had
	// been shut out when nobody had.
	userID := domain.NewIDFromUint64(42)
	f := newBlockFixture(nil, domain.ErrRecordNotFound)

	err := f.ctrl.Block(context.Background(), userID)
	if err == nil {
		t.Fatal("expected blocking an unknown user to fail")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.RecordNotFoundError {
		t.Fatalf("expected RecordNotFoundError, got %d", er.Code)
	}

	if len(f.revoked.created) != 0 {
		t.Fatalf("nothing may be revoked for a user that does not exist, got %+v", f.revoked.created)
	}
	if f.tx.commitCalls != 0 || f.tx.rollbackCalls != 1 {
		t.Fatalf("expected a rollback and no commit: commit=%d rollback=%d",
			f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

func TestBlock_RevocationFailureLeavesTheAccountUnflagged(t *testing.T) {
	initTestLogger(t)

	// The two halves stand or fall together. Committing the flag while the
	// sessions survived is the state this endpoint exists to prevent, so a
	// revocation that cannot be carried out has to take the status change with it.
	userID := domain.NewIDFromUint64(42)
	f := newBlockFixture([]domain.Session{
		{UUID: domain.SessionID("laptop"), UserID: userID},
	}, nil)
	f.cache.updateErr = errors.New("hazelcast unavailable")

	err := f.ctrl.Block(context.Background(), userID)
	if err == nil {
		t.Fatal("expected the block to fail when sessions cannot be revoked")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.CacheError {
		t.Fatalf("expected the revocation failure to surface, got %d", er.Code)
	}

	if f.tx.commitCalls != 0 {
		t.Fatalf("the status change must not commit on its own, got commit=%d", f.tx.commitCalls)
	}
	if f.tx.rollbackCalls != 1 {
		t.Fatalf("expected exactly one rollback, got %d", f.tx.rollbackCalls)
	}
}
