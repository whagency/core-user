package controllers

import (
	"context"
	"testing"
	"time"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
)

const loginTestPassword = "Correct!123"

type lockoutCredentialsStub struct {
	credential domain.Credential

	registerCalls int
	clearCalls    int
	// afterRegister is the state RegisterFailedLogin reports back, standing in
	// for what the atomic UPDATE would have written.
	afterRegister domain.Credential
}

func (s *lockoutCredentialsStub) Create(context.Context, *domain.Credential) error { return nil }

func (s *lockoutCredentialsStub) FindByUserID(context.Context, domain.ID) (domain.Credential, error) {
	return s.credential, nil
}

func (s *lockoutCredentialsStub) FindByUserIDForUpdate(context.Context, domain.ID) (domain.Credential, error) {
	return s.credential, nil
}

func (s *lockoutCredentialsStub) Update(context.Context, *domain.Credential) error { return nil }

func (s *lockoutCredentialsStub) RegisterFailedLogin(context.Context, domain.ID, domain.LoginLockPolicy) (domain.Credential, error) {
	s.registerCalls++
	return s.afterRegister, nil
}

func (s *lockoutCredentialsStub) ClearLoginFailures(context.Context, domain.ID) error {
	s.clearCalls++
	return nil
}

func (s *lockoutCredentialsStub) WithTxFromContext(context.Context) domain.CredentialRepository {
	return s
}

type lockoutContactsStub struct{ contact domain.ContactMethod }

func (s *lockoutContactsStub) ExistsForTypeAndValue(context.Context, domain.ContactType, string) (bool, error) {
	return false, nil
}
func (s *lockoutContactsStub) Create(context.Context, *domain.ContactMethod) error { return nil }
func (s *lockoutContactsStub) FindByID(context.Context, domain.ID) (domain.ContactMethod, error) {
	return s.contact, nil
}
func (s *lockoutContactsStub) FindByValue(context.Context, string) (domain.ContactMethod, error) {
	return s.contact, nil
}
func (s *lockoutContactsStub) FindPrimaryByValue(context.Context, string) (domain.ContactMethod, error) {
	return s.contact, nil
}
func (s *lockoutContactsStub) FindPrimaryByUser(context.Context, domain.ID) (domain.ContactMethod, error) {
	return s.contact, nil
}
func (s *lockoutContactsStub) FindPrimaryByUserAndType(context.Context, domain.ID, domain.ContactType) (domain.ContactMethod, error) {
	return s.contact, nil
}
func (s *lockoutContactsStub) MarkVerified(context.Context, domain.ID, time.Time) error { return nil }
func (s *lockoutContactsStub) WithTxFromContext(context.Context) domain.ContactRepository {
	return s
}

// lockoutPasswordHelperStub accepts exactly one password, so a test can choose
// whether the attempt succeeds by what it passes in.
type lockoutPasswordHelperStub struct{}

func (s *lockoutPasswordHelperStub) Hash(string) (string, error) { return "hashed", nil }
func (s *lockoutPasswordHelperStub) Verify(password, _ string) (bool, error) {
	return password == loginTestPassword, nil
}
func (s *lockoutPasswordHelperStub) Algorithm() domain.CredentialAlgorithm {
	return domain.CredentialAlgorithmBcrypt
}

// twoFactorNotConfiguredStub reports no 2FA, the branch that goes on to issue a
// session directly.
type twoFactorNotConfiguredStub struct{}

func (s *twoFactorNotConfiguredStub) Activate(context.Context, domain.TwoFactorActivateParams) (domain.TwoFactorChallengeResult, error) {
	return domain.TwoFactorChallengeResult{}, nil
}
func (s *twoFactorNotConfiguredStub) Deactivate(context.Context, domain.TwoFactorDeactivateParams) (domain.TwoFactorChallengeResult, error) {
	return domain.TwoFactorChallengeResult{}, nil
}
func (s *twoFactorNotConfiguredStub) IssueChallenge(context.Context, domain.TwoFactorIssueChallengeParams) (domain.TwoFactorChallengeResult, error) {
	return domain.TwoFactorChallengeResult{}, svcErrors.New(appErrors.RecordNotFoundError)
}
func (s *twoFactorNotConfiguredStub) VerifyChallenge(context.Context, domain.TwoFactorChallengeVerifyParams) (domain.TwoFactorToken, *appErrors.ErrorResponse) {
	return domain.TwoFactorToken{}, nil
}
func (s *twoFactorNotConfiguredStub) Confirm(context.Context, domain.TwoFactorConfirmParams) error {
	return nil
}
func (s *twoFactorNotConfiguredStub) GetSettings(context.Context, domain.ID) (domain.TwoFactorGetSettingsResult, error) {
	return domain.TwoFactorGetSettingsResult{}, nil
}
func (s *twoFactorNotConfiguredStub) ResendChallenge(context.Context, domain.TwoFactorChallengeResendParams) (domain.TwoFactorChallengeResult, error) {
	return domain.TwoFactorChallengeResult{}, nil
}

type sessionCtrlNoopStub struct{}

func (s *sessionCtrlNoopStub) Issue(context.Context, *domain.SessionIssueParams) (domain.SessionToken, error) {
	return domain.SessionToken{SessionID: domain.SessionID("issued")}, nil
}
func (s *sessionCtrlNoopStub) Logout(context.Context, domain.AuthenticatedSession) error { return nil }
func (s *sessionCtrlNoopStub) LogoutAll(context.Context, domain.AuthenticatedSession) error {
	return nil
}
func (s *sessionCtrlNoopStub) ListSessions(context.Context, domain.ID) ([]domain.Session, error) {
	return nil, nil
}
func (s *sessionCtrlNoopStub) RevokeSession(context.Context, domain.AuthenticatedSession, domain.SessionID) error {
	return nil
}
func (s *sessionCtrlNoopStub) RevokeSessionByAdmin(context.Context, domain.SessionID) error {
	return nil
}
func (s *sessionCtrlNoopStub) RevokeAllOnBlock(context.Context, domain.ID) *appErrors.ErrorResponse {
	return nil
}
func (s *sessionCtrlNoopStub) RefreshSession(context.Context, domain.SessionRefreshParams) (domain.SessionToken, error) {
	return domain.SessionToken{}, nil
}
func (s *sessionCtrlNoopStub) RevokeAllOnPasswordChange(context.Context, domain.AuthenticatedSession) error {
	return nil
}

type lockoutFixture struct {
	ctrl        AuthCtrl
	credentials *lockoutCredentialsStub
	authLogs    *authLogRepoStub
	tx          *txManagerStub
}

func newLockoutFixture(credential domain.Credential, afterRegister domain.Credential) lockoutFixture {
	userID := domain.NewIDFromUint64(11)

	credentials := &lockoutCredentialsStub{credential: credential, afterRegister: afterRegister}
	authLogs := &authLogRepoStub{}
	tx := &txManagerStub{}

	return lockoutFixture{
		ctrl: AuthCtrl{
			users: &userRepoGetProfileStub{user: domain.User{
				ID:     userID,
				Status: domain.UserStatusActive,
			}},
			contacts: &lockoutContactsStub{contact: domain.ContactMethod{
				UserID: userID,
				Status: domain.ContactStatusVerified,
			}},
			credentials:        credentials,
			authLogs:           authLogs,
			passwordHelper:     &lockoutPasswordHelperStub{},
			twoFactorCtrl:      &twoFactorNotConfiguredStub{},
			geoCtrl:            &registerGeoStub{},
			sessionCtrl:        &sessionCtrlNoopStub{},
			transactionManager: tx,
		},
		credentials: credentials,
		authLogs:    authLogs,
		tx:          tx,
	}
}

func TestLogin_WrongPasswordIsCountedAndAudited(t *testing.T) {
	initTestLogger(t)

	f := newLockoutFixture(
		domain.Credential{PasswordHash: "hashed"},
		domain.Credential{FailedLoginAttempts: 1},
	)

	_, err := f.ctrl.Login(context.Background(), domain.LoginParams{
		Identifier: "a@b.c",
		Password:   "wrong",
	})
	if err == nil {
		t.Fatal("expected a wrong password to be rejected")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	// Still the generic answer while the account is not locked yet.
	if er.Code != svcErrors.AccountInvalidCredentialsError {
		t.Fatalf("expected AccountInvalidCredentialsError, got %d", er.Code)
	}

	if f.credentials.registerCalls != 1 {
		t.Fatalf("expected the failure to be counted once, got %d", f.credentials.registerCalls)
	}
	if len(f.authLogs.created) != 1 || f.authLogs.created[0] != domain.AuthLogStatusLoginFailed {
		t.Fatalf("expected one LoginFailed audit row, got %+v", f.authLogs.created)
	}
	// The counter and its audit row commit together.
	if f.tx.commitCalls != 1 || f.tx.rollbackCalls != 0 {
		t.Fatalf("expected one committed transaction: commit=%d rollback=%d",
			f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

func TestLogin_AttemptThatTripsTheLockSaysSo(t *testing.T) {
	initTestLogger(t)

	until := time.Now().UTC().Add(15 * time.Minute)
	f := newLockoutFixture(
		domain.Credential{PasswordHash: "hashed", FailedLoginAttempts: 4},
		domain.Credential{FailedLoginAttempts: 5, LoginLockedUntil: &until},
	)

	_, err := f.ctrl.Login(context.Background(), domain.LoginParams{
		Identifier: "a@b.c",
		Password:   "wrong",
	})

	er, _ := appErrors.AsErrorResponse(err)
	if er.Code != svcErrors.AccountLoginAttemptsExceededError {
		t.Fatalf("expected AccountLoginAttemptsExceededError, got %d", er.Code)
	}
	// retryAfter is what lets a client show something better than "try again".
	if er.Data["retryAfter"] != until.Format(time.RFC3339) {
		t.Fatalf("expected retryAfter %s, got %v", until.Format(time.RFC3339), er.Data["retryAfter"])
	}
}

func TestLogin_LockedAccountIsRefusedBeforeTheHashIsChecked(t *testing.T) {
	initTestLogger(t)

	until := time.Now().UTC().Add(10 * time.Minute)
	f := newLockoutFixture(
		domain.Credential{PasswordHash: "hashed", FailedLoginAttempts: 5, LoginLockedUntil: &until},
		domain.Credential{},
	)

	// Even the right password is refused while the lock stands.
	_, err := f.ctrl.Login(context.Background(), domain.LoginParams{
		Identifier: "a@b.c",
		Password:   loginTestPassword,
	})

	er, _ := appErrors.AsErrorResponse(err)
	if er.Code != svcErrors.AccountLoginAttemptsExceededError {
		t.Fatalf("expected AccountLoginAttemptsExceededError, got %d", er.Code)
	}

	// A locked account must not spend a bcrypt round or grow the counter, and it
	// writes no audit row -- the failures that caused the lock are already there.
	if f.credentials.registerCalls != 0 {
		t.Fatalf("a refused attempt must not advance the counter, got %d", f.credentials.registerCalls)
	}
	if len(f.authLogs.created) != 0 {
		t.Fatalf("expected no audit row while locked, got %+v", f.authLogs.created)
	}
}

func TestLogin_ExpiredLockLetsTheUserBackIn(t *testing.T) {
	initTestLogger(t)

	// The deadline is in the past, so it releases itself with no job to run.
	past := time.Now().UTC().Add(-time.Minute)
	f := newLockoutFixture(
		domain.Credential{PasswordHash: "hashed", FailedLoginAttempts: 5, LoginLockedUntil: &past},
		domain.Credential{},
	)

	if _, err := f.ctrl.Login(context.Background(), domain.LoginParams{
		Identifier: "a@b.c",
		Password:   loginTestPassword,
	}); err != nil {
		t.Fatalf("an expired lock must not block sign-in, got %v", err)
	}

	if f.credentials.clearCalls != 1 {
		t.Fatalf("expected the streak to be cleared on success, got %d", f.credentials.clearCalls)
	}
}

func TestLogin_SuccessClearsTheStreak(t *testing.T) {
	initTestLogger(t)

	f := newLockoutFixture(
		domain.Credential{PasswordHash: "hashed", FailedLoginAttempts: 3},
		domain.Credential{},
	)

	if _, err := f.ctrl.Login(context.Background(), domain.LoginParams{
		Identifier: "a@b.c",
		Password:   loginTestPassword,
	}); err != nil {
		t.Fatalf("expected the sign-in to succeed, got %v", err)
	}

	if f.credentials.clearCalls != 1 {
		t.Fatalf("expected one clear, got %d", f.credentials.clearCalls)
	}
	if f.credentials.registerCalls != 0 {
		t.Fatalf("a success must not count a failure, got %d", f.credentials.registerCalls)
	}
	if len(f.authLogs.created) != 1 || f.authLogs.created[0] != domain.AuthLogStatusLoginSuccess {
		t.Fatalf("expected a LoginSuccess audit row, got %+v", f.authLogs.created)
	}
}

// lookupRecordingContactsStub remembers the value it was asked for, which is the
// thing under test: the lookup has to use the same form the value was stored in.
type lookupRecordingContactsStub struct {
	lockoutContactsStub
	askedFor string
}

func (s *lookupRecordingContactsStub) FindByValue(ctx context.Context, value string) (domain.ContactMethod, error) {
	s.askedFor = value
	return s.lockoutContactsStub.FindByValue(ctx, value)
}

func (s *lookupRecordingContactsStub) WithTxFromContext(context.Context) domain.ContactRepository {
	return s
}

func TestLogin_LooksUpTheNormalizedIdentifier(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(11)
	contacts := &lookupRecordingContactsStub{
		lockoutContactsStub: lockoutContactsStub{contact: domain.ContactMethod{
			UserID: userID,
			Status: domain.ContactStatusVerified,
		}},
	}

	f := newLockoutFixture(domain.Credential{PasswordHash: "hashed"}, domain.Credential{})
	f.ctrl.contacts = contacts

	if _, err := f.ctrl.Login(context.Background(), domain.LoginParams{
		Identifier: "  Alice@Example.COM ",
		Password:   loginTestPassword,
	}); err != nil {
		t.Fatalf("expected the sign-in to succeed, got %v", err)
	}

	if contacts.askedFor != "alice@example.com" {
		t.Fatalf("expected the lookup to use the stored form, got %q", contacts.askedFor)
	}
}
