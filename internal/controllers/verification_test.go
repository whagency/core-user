package controllers

import (
	"context"
	"fmt"
	"testing"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
	outboxtestkit "github.com/whagency/core-common/outbox/testkit"
)

type verificationRepoProcessStub struct {
	errFindForUpdate error
}

func (s *verificationRepoProcessStub) Create(context.Context, *domain.Verification) error { return nil }

func (s *verificationRepoProcessStub) GetLast(context.Context, domain.ID) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoProcessStub) GetLastPendingByUserIDAndProvider(context.Context, domain.ID, domain.VerificationProvider) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoProcessStub) GetByProviderAndExternalIDForUpdate(context.Context, domain.VerificationProvider, string) (domain.Verification, error) {
	if s.errFindForUpdate != nil {
		return domain.Verification{}, s.errFindForUpdate
	}
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoProcessStub) Update(context.Context, domain.VerificationUpdateParams) error {
	return nil
}

func (s *verificationRepoProcessStub) SetProviderData(context.Context, domain.ID, any) error {
	return nil
}

func (s *verificationRepoProcessStub) WithTxFromContext(context.Context) domain.VerificationRepository {
	return s
}

func TestVerificationCtrlProcess_ConcurrencyConflictMapped(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}

	ctrl := VerificationCtrl{
		verifications:      &verificationRepoProcessStub{errFindForUpdate: domain.ErrConcurrencyConflict},
		transactionManager: tm,
	}

	err := ctrl.Process(context.Background(), domain.VerificationProcessParams{
		Provider:   domain.VerificationProvidersAmlBot,
		ExternalID: "ext-id",
	})
	if err == nil {
		t.Fatalf("expected error")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.ConcurrencyConflictError {
		t.Fatalf("expected ConcurrencyConflictError code, got %d", er.Code)
	}
	if tm.beginCalls != 1 || tm.commitCalls != 0 || tm.rollbackCalls != 1 {
		t.Fatalf("unexpected tx calls: begin=%d commit=%d rollback=%d", tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
	}
}

// verificationRepoFoundStub returns a pending verification, so Process runs its
// success path instead of bailing at the lookup.
type verificationRepoFoundStub struct {
	verification domain.Verification
}

func (s *verificationRepoFoundStub) Create(context.Context, *domain.Verification) error { return nil }

func (s *verificationRepoFoundStub) GetLast(context.Context, domain.ID) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoFoundStub) GetLastPendingByUserIDAndProvider(context.Context, domain.ID, domain.VerificationProvider) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoFoundStub) GetByProviderAndExternalIDForUpdate(context.Context, domain.VerificationProvider, string) (domain.Verification, error) {
	return s.verification, nil
}

func (s *verificationRepoFoundStub) Update(context.Context, domain.VerificationUpdateParams) error {
	return nil
}

func (s *verificationRepoFoundStub) SetProviderData(context.Context, domain.ID, any) error {
	return nil
}

func (s *verificationRepoFoundStub) WithTxFromContext(context.Context) domain.VerificationRepository {
	return s
}

type userRepoVerificationStub struct{}

func (s *userRepoVerificationStub) Create(context.Context, *domain.User) error { return nil }
func (s *userRepoVerificationStub) SetPrimaryContact(context.Context, domain.ID, domain.ID) error {
	return nil
}

func (s *userRepoVerificationStub) FindByID(context.Context, domain.ID) (domain.User, error) {
	return domain.User{}, domain.ErrRecordNotFound
}

func (s *userRepoVerificationStub) FindByNumber(context.Context, int64) (domain.User, error) {
	return domain.User{}, domain.ErrRecordNotFound
}
func (s *userRepoVerificationStub) ActivateIfPendingByUserID(context.Context, domain.ID) error {
	return nil
}

func (s *userRepoVerificationStub) UpdateStatus(context.Context, domain.ID, domain.UserStatus) error {
	return nil
}

func (s *userRepoVerificationStub) SetVerificationLevel(context.Context, domain.ID, domain.VerificationLevel) error {
	return nil
}
func (s *userRepoVerificationStub) WithTxFromContext(context.Context) domain.UserRepository { return s }

// userCtrlVerificationStub satisfies domain.UserController; Process only calls
// UpdateProfile, so the rest are unreachable and say so.
type userCtrlVerificationStub struct{}

func (s *userCtrlVerificationStub) UpdateProfile(context.Context, domain.UpdateProfileParams) error {
	return nil
}

func (s *userCtrlVerificationStub) Register(context.Context, domain.UserRegisterParams) (domain.UserRegistrationResult, error) {
	panic("unexpected: Register")
}

func (s *userCtrlVerificationStub) VerifyContact(context.Context, domain.ContactVerifyParams) error {
	panic("unexpected: VerifyContact")
}

func (s *userCtrlVerificationStub) GetProfile(context.Context, domain.ID) (domain.UserProfile, error) {
	panic("unexpected: GetProfile")
}

func (s *userCtrlVerificationStub) GetByNumber(context.Context, int64) (domain.User, error) {
	panic("unexpected: GetByNumber")
}

func (s *userCtrlVerificationStub) ChangePassword(context.Context, domain.PasswordChangeParams) error {
	panic("unexpected: ChangePassword")
}

func (s *userCtrlVerificationStub) Block(context.Context, domain.ID) error {
	panic("unexpected: Block")
}

// TestVerificationCtrlProcess_EnqueuesVerifyLevelOnPass covers the success path.
//
// It exists because there was none: the only Process test bailed at the lookup,
// so a nil outboxRepo — the field was declared and taken as a constructor
// parameter but never assigned — went unnoticed. Any test that reached the
// enqueue would have panicked immediately.
func TestVerificationCtrlProcess_EnqueuesVerifyLevelOnPass(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}
	outboxRepo := outboxtestkit.NewFakeRepository()
	userID := domain.NewIDFromUint64(77)

	ctrl := NewVerificationController(
		nil,
		nil,
		outboxRepo,
		&verificationRepoFoundStub{verification: domain.Verification{
			ID:                domain.NewIDFromUint64(5),
			UserID:            userID,
			VerificationLevel: domain.VerificationLevelBasic,
		}},
		&userRepoVerificationStub{},
		tm,
		&userCtrlVerificationStub{},
	)

	if err := ctrl.Process(context.Background(), domain.VerificationProcessParams{
		Provider:   domain.VerificationProvidersAmlBot,
		ExternalID: "ext-id",
		Status:     domain.VerificationStatusCompleteYes,
	}); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	rows := outboxRepo.All()
	if len(rows) != 1 {
		t.Fatalf("expected one outbox row, got %d", len(rows))
	}
	if rows[0].EventType != domain.OutboxEventUserVerifyLevelUpdated {
		t.Fatalf("unexpected event type %q", rows[0].EventType)
	}
	expectedKey := fmt.Sprintf("verify-level:%d:%d", userID.Uint64(), domain.VerificationLevelBasic.Uint8())
	if rows[0].DedupeKey != expectedKey {
		t.Fatalf("expected dedupe key %q, got %q", expectedKey, rows[0].DedupeKey)
	}
	if tm.commitCalls != 1 {
		t.Fatalf("expected one commit, got %d", tm.commitCalls)
	}
}

// TestVerificationCtrlProcess_FailedVerificationEnqueuesNothing pins the other
// half: only a passed verification changes the user's tier, so only that emits an
// event.
func TestVerificationCtrlProcess_FailedVerificationEnqueuesNothing(t *testing.T) {
	initTestLogger(t)

	outboxRepo := outboxtestkit.NewFakeRepository()

	ctrl := NewVerificationController(
		nil,
		nil,
		outboxRepo,
		&verificationRepoFoundStub{verification: domain.Verification{
			ID:                domain.NewIDFromUint64(5),
			UserID:            domain.NewIDFromUint64(77),
			VerificationLevel: domain.VerificationLevelBasic,
		}},
		&userRepoVerificationStub{},
		&txManagerStub{},
		&userCtrlVerificationStub{},
	)

	if err := ctrl.Process(context.Background(), domain.VerificationProcessParams{
		Provider:   domain.VerificationProvidersAmlBot,
		ExternalID: "ext-id",
		Status:     domain.VerificationStatusCompleteNo,
	}); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if rows := outboxRepo.All(); len(rows) != 0 {
		t.Fatalf("expected no outbox rows for a failed verification, got %d", len(rows))
	}
}
