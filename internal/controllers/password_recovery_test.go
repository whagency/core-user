package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
)

const (
	recoveryTokenUUID  = "reset-token-uuid"
	recoveryOldHash    = "hash-of-the-old-password"
	recoveryNewPass    = "BrandNew!456"
	recoveryStoredCode = "123456"
)

type recoveryTokensStub struct {
	token domain.TwoFactorToken

	consumed int
}

func (s *recoveryTokensStub) Create(context.Context, *domain.TwoFactorToken) error { return nil }
func (s *recoveryTokensStub) FindLatestByContactForUpdate(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}

func (s *recoveryTokensStub) FindByUUIDAndTypeForUpdate(context.Context, string, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return s.token, nil
}

func (s *recoveryTokensStub) FindActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}
func (s *recoveryTokensStub) HasActiveForContact(context.Context, domain.ID, domain.TwoFactorTokenType) (bool, error) {
	return false, nil
}
func (s *recoveryTokensStub) InvalidateActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) error {
	return nil
}
func (s *recoveryTokensStub) IncrementAttempts(context.Context, string) error { return nil }

func (s *recoveryTokensStub) Consume(context.Context, string, bool) error {
	s.consumed++
	return nil
}

func (s *recoveryTokensStub) ClearDispatchedAt(context.Context, string) error       { return nil }
func (s *recoveryTokensStub) Refresh(context.Context, *domain.TwoFactorToken) error { return nil }
func (s *recoveryTokensStub) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (s *recoveryTokensStub) WithTxFromContext(context.Context) domain.TwoFactorTokenRepository {
	return s
}

// recoveryOTPStub accepts one code, so a test can choose whether the challenge
// passes.
type recoveryOTPStub struct{}

func (s *recoveryOTPStub) Generate() (domain.OTPToken, error)            { return domain.OTPToken{}, nil }
func (s *recoveryOTPStub) Verify(code, _, _ string) bool                 { return code == recoveryStoredCode }
func (s *recoveryOTPStub) Send(context.Context, domain.OTPMessage) error { return nil }

// recoveryPasswordHelperStub reports the new password as not a reuse of the old.
type recoveryPasswordHelperStub struct{}

func (s *recoveryPasswordHelperStub) Hash(string) (string, error) { return "hash-of-new", nil }
func (s *recoveryPasswordHelperStub) Verify(password, _ string) (bool, error) {
	return password == "the-old-password", nil
}
func (s *recoveryPasswordHelperStub) Algorithm() domain.CredentialAlgorithm {
	return domain.CredentialAlgorithmBcrypt
}

type recoveryFixture struct {
	ctrl        PasswordRecoveryCtrl
	credentials *passwordChangeCredentialsStub
	changeLogs  *passwordChangeLogsStub
	sessions    *sessionRepoStub
	revoked     *revokedSessionRepoStub
	cache       *cacheRepoStub
	tx          *txManagerStub
}

func newRecoveryFixture(userID domain.ID, stored []domain.Session) recoveryFixture {
	credentials := &passwordChangeCredentialsStub{
		credential: domain.Credential{UserID: userID, PasswordHash: recoveryOldHash},
	}
	changeLogs := &passwordChangeLogsStub{}
	sessions := &sessionRepoStub{list: stored}
	revoked := &revokedSessionRepoStub{}
	cacheRepo := &cacheRepoStub{}
	tx := &txManagerStub{}

	return recoveryFixture{
		ctrl: PasswordRecoveryCtrl{
			credentials:        credentials,
			passwordChangeLogs: changeLogs,
			twoFaTokens: &recoveryTokensStub{token: domain.TwoFactorToken{
				UUID:      recoveryTokenUUID,
				UserID:    userID,
				Type:      domain.TwoFactorTokenTypePasswordReset,
				Status:    domain.TwoFactorTokenStatusActive,
				ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
			}},
			otpCtrl:        &recoveryOTPStub{},
			passwordHelper: &recoveryPasswordHelperStub{},
			sessionCtrl: SessionCtrl{
				sessions:        sessions,
				revokedSessions: revoked,
				authLogs:        &authLogRepoStub{},
				revocationCache: cacheRepo,
			},
			transactionManager: tx,
		},
		credentials: credentials,
		changeLogs:  changeLogs,
		sessions:    sessions,
		revoked:     revoked,
		cache:       cacheRepo,
		tx:          tx,
	}
}

func recoveryParams() domain.PasswordResetConfirmParams {
	return domain.PasswordResetConfirmParams{
		TokenUUID:   recoveryTokenUUID,
		Code:        recoveryStoredCode,
		NewPassword: recoveryNewPass,
	}
}

// A reset is what someone does because they believe another party is holding a
// session. Every one of them has to go, and go together with the new password.
func TestPasswordResetConfirm_EndsEverySessionInTheSameTransaction(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(21)
	f := newRecoveryFixture(userID, []domain.Session{
		{UUID: domain.SessionID("victims-laptop"), UserID: userID},
		{UUID: domain.SessionID("attackers-session"), UserID: userID},
	})

	if err := f.ctrl.Confirm(context.Background(), recoveryParams()); err != nil {
		t.Fatalf("expected the reset to succeed, got %v", err)
	}

	// Nothing is spared: the caller answered an emailed code and has no session
	// of their own.
	if len(f.revoked.created) != 2 {
		t.Fatalf("expected both sessions revoked, got %+v", f.revoked.created)
	}
	for id, reason := range f.revoked.reasons {
		if reason != domain.SessionRevocationReasonPasswordChange {
			t.Fatalf("expected reason password_change for %s, got %s", id, reason)
		}
	}

	if len(f.credentials.updated) != 1 {
		t.Fatalf("expected the password to be rotated once, got %+v", f.credentials.updated)
	}

	// A reset is a password change and belongs in the same history; without it
	// Me reported the date of the previous change to a user who had just reset.
	if f.changeLogs.created != 1 {
		t.Fatalf("expected one password change log, got %d", f.changeLogs.created)
	}
	if f.tx.beginCalls != 1 || f.tx.commitCalls != 1 || f.tx.rollbackCalls != 0 {
		t.Fatalf("expected one committed transaction: begin=%d commit=%d rollback=%d",
			f.tx.beginCalls, f.tx.commitCalls, f.tx.rollbackCalls)
	}
}

// The whole point of moving this inside the transaction: a revocation that
// cannot be carried out must take the new password with it. Committing one
// without the other leaves the reset looking successful while the session it
// was meant to end keeps working.
func TestPasswordResetConfirm_RevocationFailureAbortsTheReset(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(21)
	f := newRecoveryFixture(userID, []domain.Session{
		{UUID: domain.SessionID("attackers-session"), UserID: userID},
	})
	f.cache.updateErr = errors.New("hazelcast unavailable")

	err := f.ctrl.Confirm(context.Background(), recoveryParams())
	if err == nil {
		t.Fatal("expected the reset to fail when sessions cannot be revoked")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.CacheError {
		t.Fatalf("expected the revocation failure to surface, got %d", er.Code)
	}

	if f.tx.commitCalls != 0 {
		t.Fatalf("the new password must not commit on its own, got commit=%d", f.tx.commitCalls)
	}
	if f.tx.rollbackCalls != 1 {
		t.Fatalf("expected exactly one rollback, got %d", f.tx.rollbackCalls)
	}
}

// The audit row goes in the same transaction as the new hash, so a reset can
// never be recorded without its history entry or the other way round.
func TestPasswordResetConfirm_AuditRowSharesTheTransaction(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(21)
	f := newRecoveryFixture(userID, nil)
	f.credentials.findErr = domain.ErrRecordNotFound

	if err := f.ctrl.Confirm(context.Background(), recoveryParams()); err == nil {
		t.Fatal("expected the reset to fail when the credential is missing")
	}

	if f.changeLogs.created != 0 {
		t.Fatalf("a reset that did not happen must leave no history, got %d", f.changeLogs.created)
	}
	if f.tx.commitCalls != 0 || f.tx.rollbackCalls != 1 {
		t.Fatalf("expected a rollback and no commit: commit=%d rollback=%d",
			f.tx.commitCalls, f.tx.rollbackCalls)
	}
}
