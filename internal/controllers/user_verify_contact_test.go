package controllers

import (
	"context"
	"testing"
	"time"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
)

type userRepoVerifyContactStub struct {
	activateCalls int
	activateErr   error
}

func (s *userRepoVerifyContactStub) Create(context.Context, *domain.User) error { return nil }

func (s *userRepoVerifyContactStub) SetPrimaryContact(context.Context, domain.ID, domain.ID) error {
	return nil
}

func (s *userRepoVerifyContactStub) FindByID(context.Context, domain.ID) (domain.User, error) {
	return domain.User{}, domain.ErrRecordNotFound
}

func (s *userRepoVerifyContactStub) FindByNumber(context.Context, int64) (domain.User, error) {
	return domain.User{}, domain.ErrRecordNotFound
}

func (s *userRepoVerifyContactStub) ActivateIfPendingByUserID(context.Context, domain.ID) error {
	s.activateCalls++
	return s.activateErr
}

func (s *userRepoVerifyContactStub) UpdateStatus(context.Context, domain.ID, domain.UserStatus) error {
	return nil
}

func (s *userRepoVerifyContactStub) SetVerificationLevel(context.Context, domain.ID, domain.VerificationLevel) error {
	return nil
}

func (s *userRepoVerifyContactStub) WithTxFromContext(context.Context) domain.UserRepository {
	return s
}

type contactRepoVerifyContactStub struct {
	markCalls int
	markErr   error
}

func (s *contactRepoVerifyContactStub) ExistsForTypeAndValue(context.Context, domain.ContactType, string) (bool, error) {
	return false, nil
}

func (s *contactRepoVerifyContactStub) Create(context.Context, *domain.ContactMethod) error {
	return nil
}

func (s *contactRepoVerifyContactStub) FindByID(context.Context, domain.ID) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoVerifyContactStub) FindByValue(context.Context, string) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoVerifyContactStub) FindPrimaryByValue(context.Context, string) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoVerifyContactStub) FindPrimaryByUser(context.Context, domain.ID) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoVerifyContactStub) FindPrimaryByUserAndType(context.Context, domain.ID, domain.ContactType) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoVerifyContactStub) MarkVerified(context.Context, domain.ID, time.Time) error {
	s.markCalls++
	return s.markErr
}

func (s *contactRepoVerifyContactStub) WithTxFromContext(context.Context) domain.ContactRepository {
	return s
}

type twoFaRepoVerifyContactStub struct {
	clearedDispatchUUIDs []string
	clearDispatchErr     error
	token                domain.TwoFactorToken

	findErr       error
	consumeCalls  int
	consumeErr    error
	incrementErr  error
	incrementCall int
}

func (s *twoFaRepoVerifyContactStub) Create(context.Context, *domain.TwoFactorToken) error {
	return nil
}

func (s *twoFaRepoVerifyContactStub) FindLatestByContactForUpdate(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}

func (s *twoFaRepoVerifyContactStub) FindByUUIDAndTypeForUpdate(context.Context, string, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	if s.findErr != nil {
		return domain.TwoFactorToken{}, s.findErr
	}
	return s.token, nil
}

func (s *twoFaRepoVerifyContactStub) FindActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}

func (s *twoFaRepoVerifyContactStub) HasActiveForContact(context.Context, domain.ID, domain.TwoFactorTokenType) (bool, error) {
	return false, nil
}

func (s *twoFaRepoVerifyContactStub) InvalidateActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) error {
	return nil
}

func (s *twoFaRepoVerifyContactStub) IncrementAttempts(context.Context, string) error {
	s.incrementCall++
	return s.incrementErr
}

func (s *twoFaRepoVerifyContactStub) Consume(context.Context, string, bool) error {
	s.consumeCalls++
	return s.consumeErr
}

func (s *twoFaRepoVerifyContactStub) Refresh(context.Context, *domain.TwoFactorToken) error {
	return nil
}

// clearDispatchedAtCalls records ClearDispatchedAt calls so a test can assert the
// resend cooldown was released after a failed send.
func (s *twoFaRepoVerifyContactStub) ClearDispatchedAt(_ context.Context, uuid string) error {
	s.clearedDispatchUUIDs = append(s.clearedDispatchUUIDs, uuid)
	return s.clearDispatchErr
}

func (s *twoFaRepoVerifyContactStub) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (s *twoFaRepoVerifyContactStub) WithTxFromContext(context.Context) domain.TwoFactorTokenRepository {
	return s
}

type otpCtrlVerifyContactStub struct {
	verifyResult bool
}

func (s *otpCtrlVerifyContactStub) Generate() (domain.OTPToken, error) {
	return domain.OTPToken{}, nil
}

func (s *otpCtrlVerifyContactStub) Verify(string, string, string) bool { return s.verifyResult }

func (s *otpCtrlVerifyContactStub) Send(context.Context, domain.OTPMessage) error { return nil }

func TestUserCtrlVerifyContact_NilContactIDReturnsInternalAndRollsBack(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}
	userID := domain.NewIDFromUint64(77)

	twoFaRepo := &twoFaRepoVerifyContactStub{
		token: domain.TwoFactorToken{
			UUID:      "verify-token",
			UserID:    userID,
			Type:      domain.TwoFactorTokenTypeVerifyContact,
			Method:    domain.TwoFactorMethodEmail,
			Status:    domain.TwoFactorTokenStatusActive,
			CodeSalt:  "salt",
			CodeHash:  "hash",
			ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		},
	}
	usersRepo := &userRepoVerifyContactStub{}
	contactsRepo := &contactRepoVerifyContactStub{}

	ctrl := UserCtrl{
		users:              usersRepo,
		contacts:           contactsRepo,
		twoFaTokens:        twoFaRepo,
		otpCtrl:            &otpCtrlVerifyContactStub{verifyResult: true},
		transactionManager: tm,
	}

	err := ctrl.VerifyContact(context.Background(), domain.ContactVerifyParams{
		TokenUUID: "verify-token",
		Code:      "123456",
	})
	if err == nil {
		t.Fatalf("expected error")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.InternalServerError {
		t.Fatalf("expected InternalServerError code, got %d", er.Code)
	}
	if tm.rollbackCalls != 1 || tm.commitCalls != 0 {
		t.Fatalf("unexpected tx calls: commit=%d rollback=%d", tm.commitCalls, tm.rollbackCalls)
	}
	if twoFaRepo.consumeCalls != 0 {
		t.Fatalf("expected token not consumed on nil contact id, got %d", twoFaRepo.consumeCalls)
	}
	if contactsRepo.markCalls != 0 {
		t.Fatalf("expected no contact verification update, got %d", contactsRepo.markCalls)
	}
	if usersRepo.activateCalls != 0 {
		t.Fatalf("expected no user activation, got %d", usersRepo.activateCalls)
	}
}

func TestUserCtrlVerifyContact_ContactMissingReturnsNotFoundAndRollsBack(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}
	userID := domain.NewIDFromUint64(77)
	contactID := domain.NewIDFromUint64(88)

	twoFaRepo := &twoFaRepoVerifyContactStub{
		token: domain.TwoFactorToken{
			UUID:      "verify-token",
			UserID:    userID,
			ContactID: &contactID,
			Type:      domain.TwoFactorTokenTypeVerifyContact,
			Method:    domain.TwoFactorMethodEmail,
			Status:    domain.TwoFactorTokenStatusActive,
			CodeSalt:  "salt",
			CodeHash:  "hash",
			ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		},
	}
	usersRepo := &userRepoVerifyContactStub{}
	contactsRepo := &contactRepoVerifyContactStub{markErr: domain.ErrRecordNotFound}

	ctrl := UserCtrl{
		users:              usersRepo,
		contacts:           contactsRepo,
		twoFaTokens:        twoFaRepo,
		otpCtrl:            &otpCtrlVerifyContactStub{verifyResult: true},
		transactionManager: tm,
	}

	err := ctrl.VerifyContact(context.Background(), domain.ContactVerifyParams{
		TokenUUID: "verify-token",
		Code:      "123456",
	})
	if err == nil {
		t.Fatalf("expected error")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.RecordNotFoundError {
		t.Fatalf("expected RecordNotFoundError code, got %d", er.Code)
	}
	if tm.rollbackCalls != 1 || tm.commitCalls != 0 {
		t.Fatalf("unexpected tx calls: commit=%d rollback=%d", tm.commitCalls, tm.rollbackCalls)
	}
	if twoFaRepo.consumeCalls != 1 {
		t.Fatalf("expected token consume attempted before contact check, got %d", twoFaRepo.consumeCalls)
	}
	if contactsRepo.markCalls != 1 {
		t.Fatalf("expected one contact verification update attempt, got %d", contactsRepo.markCalls)
	}
	if usersRepo.activateCalls != 0 {
		t.Fatalf("expected no user activation on contact missing, got %d", usersRepo.activateCalls)
	}
}
