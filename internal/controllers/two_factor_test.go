package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
)

type twoFactorTokenRepoResendStub struct {
	clearedDispatchUUIDs []string
	clearDispatchErr     error
	token                domain.TwoFactorToken
	findErr              error
	refreshes            int
	createErr            error
	createCalls          int
	invalidateErr        error
	invalidates          int
}

func (s *twoFactorTokenRepoResendStub) Create(context.Context, *domain.TwoFactorToken) error {
	s.createCalls++
	return s.createErr
}

func (s *twoFactorTokenRepoResendStub) FindLatestByContactForUpdate(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}

func (s *twoFactorTokenRepoResendStub) FindByUUIDAndTypeForUpdate(context.Context, string, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	if s.findErr != nil {
		return domain.TwoFactorToken{}, s.findErr
	}
	return s.token, nil
}

func (s *twoFactorTokenRepoResendStub) FindActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) (domain.TwoFactorToken, error) {
	return domain.TwoFactorToken{}, domain.ErrRecordNotFound
}

func (s *twoFactorTokenRepoResendStub) HasActiveForContact(context.Context, domain.ID, domain.TwoFactorTokenType) (bool, error) {
	return false, nil
}

func (s *twoFactorTokenRepoResendStub) InvalidateActiveByUserAndType(context.Context, domain.ID, domain.TwoFactorTokenType) error {
	s.invalidates++
	return s.invalidateErr
}

func (s *twoFactorTokenRepoResendStub) IncrementAttempts(context.Context, string) error { return nil }

func (s *twoFactorTokenRepoResendStub) Consume(context.Context, string, bool) error { return nil }

func (s *twoFactorTokenRepoResendStub) Refresh(context.Context, *domain.TwoFactorToken) error {
	s.refreshes++
	return nil
}

// clearDispatchedAtCalls records ClearDispatchedAt calls so a test can assert the
// resend cooldown was released after a failed send.
func (s *twoFactorTokenRepoResendStub) ClearDispatchedAt(_ context.Context, uuid string) error {
	s.clearedDispatchUUIDs = append(s.clearedDispatchUUIDs, uuid)
	return s.clearDispatchErr
}

func (s *twoFactorTokenRepoResendStub) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (s *twoFactorTokenRepoResendStub) WithTxFromContext(context.Context) domain.TwoFactorTokenRepository {
	return s
}

type contactRepoResendStub struct {
	contact                   domain.ContactMethod
	findErr                   error
	primaryByUserAndType      domain.ContactMethod
	primaryByUserAndTypeErr   error
	primaryByUserAndTypeCalls int
}

func (s *contactRepoResendStub) ExistsForTypeAndValue(context.Context, domain.ContactType, string) (bool, error) {
	return false, nil
}

func (s *contactRepoResendStub) Create(context.Context, *domain.ContactMethod) error { return nil }

func (s *contactRepoResendStub) FindByID(context.Context, domain.ID) (domain.ContactMethod, error) {
	if s.findErr != nil {
		return domain.ContactMethod{}, s.findErr
	}
	return s.contact, nil
}

func (s *contactRepoResendStub) FindByValue(context.Context, string) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoResendStub) FindPrimaryByValue(context.Context, string) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoResendStub) FindPrimaryByUser(context.Context, domain.ID) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoResendStub) FindPrimaryByUserAndType(context.Context, domain.ID, domain.ContactType) (domain.ContactMethod, error) {
	s.primaryByUserAndTypeCalls++
	if s.primaryByUserAndTypeErr != nil {
		return domain.ContactMethod{}, s.primaryByUserAndTypeErr
	}
	return s.primaryByUserAndType, nil
}

func (s *contactRepoResendStub) MarkVerified(context.Context, domain.ID, time.Time) error { return nil }

func (s *contactRepoResendStub) WithTxFromContext(context.Context) domain.ContactRepository { return s }

type otpCtrlResendStub struct {
	generateCalls int
	generateErr   error
	sendCalls     int
}

func (s *otpCtrlResendStub) Generate() (domain.OTPToken, error) {
	s.generateCalls++
	if s.generateErr != nil {
		return domain.OTPToken{}, s.generateErr
	}
	return domain.OTPToken{
		Code:      "111111",
		Hash:      "hash",
		Salt:      "salt",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}, nil
}

func (s *otpCtrlResendStub) Verify(code, salt, hash string) bool {
	return code == "111111" && salt == "salt" && hash == "hash"
}

func (s *otpCtrlResendStub) Send(context.Context, domain.OTPMessage) error {
	s.sendCalls++
	return nil
}

type settingsRepoTwoFactorStub struct {
	settings domain.TwoFactorSettings
	findErr  error
}

func (s *settingsRepoTwoFactorStub) FindByUserID(context.Context, domain.ID) (domain.TwoFactorSettings, error) {
	if s.findErr != nil {
		return domain.TwoFactorSettings{}, s.findErr
	}
	return s.settings, nil
}

func (s *settingsRepoTwoFactorStub) Create(context.Context, *domain.TwoFactorSettings) error {
	return nil
}

func (s *settingsRepoTwoFactorStub) Delete(context.Context, domain.ID) error { return nil }

func (s *settingsRepoTwoFactorStub) AdvanceTOTPCounter(context.Context, domain.ID, int64) (bool, error) {
	return true, nil
}

func (s *settingsRepoTwoFactorStub) WithTxFromContext(context.Context) domain.TwoFactorSettingsRepository {
	return s
}

func TestTwoFactorCtrlResendChallenge_GenerateErrorRollsBack(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}

	userID := domain.NewIDFromUint64(42)
	contactID := domain.NewIDFromUint64(99)

	tokenRepo := &twoFactorTokenRepoResendStub{
		token: domain.TwoFactorToken{
			UUID:         "token-uuid",
			UserID:       userID,
			ContactID:    &contactID,
			Type:         domain.TwoFactorTokenTypeTwoFactorAuth,
			Method:       domain.TwoFactorMethodEmail,
			Status:       domain.TwoFactorTokenStatusActive,
			DispatchedAt: time.Now().UTC().Add(-2 * time.Minute),
		},
	}

	contacts := &contactRepoResendStub{
		contact: domain.ContactMethod{
			ID:     contactID,
			UserID: userID,
			Type:   domain.ContactTypeEmail,
			Value:  "user@example.com",
			Status: domain.ContactStatusVerified,
		},
	}

	otp := &otpCtrlResendStub{generateErr: errors.New("generate failed")}

	ctrl := TwoFactorCtrl{
		tokens:             tokenRepo,
		contacts:           contacts,
		otpCtrl:            otp,
		transactionManager: tm,
	}

	_, err := ctrl.ResendChallenge(context.Background(), domain.TwoFactorChallengeResendParams{
		UserID:    userID,
		Type:      domain.TwoFactorTokenTypeTwoFactorAuth,
		TokenUUID: "token-uuid",
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
	if tokenRepo.refreshes != 0 {
		t.Fatalf("expected no token refresh when OTP generation fails, got %d", tokenRepo.refreshes)
	}
	if otp.sendCalls != 0 {
		t.Fatalf("expected no OTP send when generation fails, got %d", otp.sendCalls)
	}
}

func TestTwoFactorCtrlResendChallenge_NilContactIDReturnsInternalAndRollsBack(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}

	userID := domain.NewIDFromUint64(42)

	tokenRepo := &twoFactorTokenRepoResendStub{
		token: domain.TwoFactorToken{
			UUID:         "token-uuid",
			UserID:       userID,
			Type:         domain.TwoFactorTokenTypeTwoFactorAuth,
			Method:       domain.TwoFactorMethodEmail,
			Status:       domain.TwoFactorTokenStatusActive,
			DispatchedAt: time.Now().UTC().Add(-2 * time.Minute),
		},
	}

	otp := &otpCtrlResendStub{}

	ctrl := TwoFactorCtrl{
		tokens:             tokenRepo,
		contacts:           &contactRepoResendStub{},
		otpCtrl:            otp,
		transactionManager: tm,
	}

	_, err := ctrl.ResendChallenge(context.Background(), domain.TwoFactorChallengeResendParams{
		UserID:    userID,
		Type:      domain.TwoFactorTokenTypeTwoFactorAuth,
		TokenUUID: "token-uuid",
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
	if tokenRepo.refreshes != 0 {
		t.Fatalf("expected no token refresh when contact_id is nil, got %d", tokenRepo.refreshes)
	}
	if otp.generateCalls != 0 || otp.sendCalls != 0 {
		t.Fatalf("expected no OTP generation/sending when contact_id is nil, got generateCalls=%d sendCalls=%d", otp.generateCalls, otp.sendCalls)
	}
}

func TestTwoFactorCtrlActivate_CreateErrorDoesNotSendOTP(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	contactID := domain.NewIDFromUint64(99)

	tokenRepo := &twoFactorTokenRepoResendStub{createErr: errors.New("insert failed")}
	contacts := &contactRepoResendStub{
		primaryByUserAndType: domain.ContactMethod{
			ID:     contactID,
			UserID: userID,
			Type:   domain.ContactTypeEmail,
			Value:  "user@example.com",
			Status: domain.ContactStatusVerified,
		},
	}
	otp := &otpCtrlResendStub{}
	tm := &txManagerStub{}

	ctrl := TwoFactorCtrl{
		tokens:             tokenRepo,
		settings:           &settingsRepoTwoFactorStub{findErr: domain.ErrRecordNotFound},
		contacts:           contacts,
		otpCtrl:            otp,
		transactionManager: tm,
	}

	_, err := ctrl.Activate(context.Background(), domain.TwoFactorActivateParams{
		UserID: userID,
		Method: domain.TwoFactorMethodEmail,
	})
	if err == nil {
		t.Fatalf("expected error")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.DatabaseError {
		t.Fatalf("expected DatabaseError code, got %d", er.Code)
	}
	if tokenRepo.createCalls != 1 {
		t.Fatalf("expected one token create attempt, got %d", tokenRepo.createCalls)
	}
	if otp.generateCalls != 1 {
		t.Fatalf("expected one OTP generation, got %d", otp.generateCalls)
	}
	if otp.sendCalls != 0 {
		t.Fatalf("expected OTP not sent when token create fails, got %d", otp.sendCalls)
	}
}

func TestTwoFactorCtrlIssueChallenge_CreateErrorDoesNotSendOTP(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	contactID := domain.NewIDFromUint64(99)

	tokenRepo := &twoFactorTokenRepoResendStub{createErr: errors.New("insert failed")}
	contacts := &contactRepoResendStub{
		contact: domain.ContactMethod{
			ID:     contactID,
			UserID: userID,
			Type:   domain.ContactTypeEmail,
			Value:  "user@example.com",
			Status: domain.ContactStatusVerified,
		},
	}
	otp := &otpCtrlResendStub{}

	ctrl := TwoFactorCtrl{
		tokens: tokenRepo,
		settings: &settingsRepoTwoFactorStub{
			settings: domain.TwoFactorSettings{
				UserID:    userID,
				ContactID: &contactID,
				Method:    domain.TwoFactorMethodEmail,
			},
		},
		contacts:           contacts,
		otpCtrl:            otp,
		transactionManager: &txManagerStub{},
	}

	_, err := ctrl.IssueChallenge(context.Background(), domain.TwoFactorIssueChallengeParams{
		UserID: userID,
		Type:   domain.TwoFactorTokenTypeTwoFactorAuth,
	})
	if err == nil {
		t.Fatalf("expected error")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.DatabaseError {
		t.Fatalf("expected DatabaseError code, got %d", er.Code)
	}
	if tokenRepo.createCalls != 1 {
		t.Fatalf("expected one token create attempt, got %d", tokenRepo.createCalls)
	}
	if tokenRepo.invalidates != 1 {
		t.Fatalf("expected one invalidate call, got %d", tokenRepo.invalidates)
	}
	if otp.generateCalls != 1 {
		t.Fatalf("expected one OTP generation, got %d", otp.generateCalls)
	}
	if otp.sendCalls != 0 {
		t.Fatalf("expected OTP not sent when token create fails, got %d", otp.sendCalls)
	}
}

// TestTwoFactorCtrlActivate_WritesShareOneTransaction pins the pairing.
//
// The invalidate and the create are one change: without a transaction a failure
// between them leaves the user with no active setup token at all — the previous
// one already dead, the replacement never written — and nothing recording it.
func TestTwoFactorCtrlActivate_WritesShareOneTransaction(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	contactID := domain.NewIDFromUint64(99)

	contacts := &contactRepoResendStub{
		primaryByUserAndType: domain.ContactMethod{
			ID:     contactID,
			UserID: userID,
			Type:   domain.ContactTypeEmail,
			Value:  "user@example.com",
			Status: domain.ContactStatusVerified,
		},
	}

	t.Run("success commits once", func(t *testing.T) {
		tokenRepo := &twoFactorTokenRepoResendStub{}
		tm := &txManagerStub{}

		ctrl := TwoFactorCtrl{
			tokens:             tokenRepo,
			settings:           &settingsRepoTwoFactorStub{findErr: domain.ErrRecordNotFound},
			contacts:           contacts,
			otpCtrl:            &otpCtrlResendStub{},
			transactionManager: tm,
		}

		if _, err := ctrl.Activate(context.Background(), domain.TwoFactorActivateParams{
			UserID: userID,
			Method: domain.TwoFactorMethodEmail,
		}); err != nil {
			t.Fatalf("Activate returned error: %v", err)
		}

		if tokenRepo.invalidates != 1 || tokenRepo.createCalls != 1 {
			t.Fatalf("expected one invalidate and one create, got %d/%d", tokenRepo.invalidates, tokenRepo.createCalls)
		}
		if tm.beginCalls != 1 || tm.commitCalls != 1 || tm.rollbackCalls != 0 {
			t.Fatalf("unexpected tx calls: begin=%d commit=%d rollback=%d", tm.beginCalls, tm.commitCalls, tm.rollbackCalls)
		}
	})

	t.Run("create failure rolls back the invalidate", func(t *testing.T) {
		tokenRepo := &twoFactorTokenRepoResendStub{createErr: errors.New("insert failed")}
		tm := &txManagerStub{}
		otp := &otpCtrlResendStub{}

		ctrl := TwoFactorCtrl{
			tokens:             tokenRepo,
			settings:           &settingsRepoTwoFactorStub{findErr: domain.ErrRecordNotFound},
			contacts:           contacts,
			otpCtrl:            otp,
			transactionManager: tm,
		}

		if _, err := ctrl.Activate(context.Background(), domain.TwoFactorActivateParams{
			UserID: userID,
			Method: domain.TwoFactorMethodEmail,
		}); err == nil {
			t.Fatal("expected an error")
		}

		if tm.commitCalls != 0 {
			t.Fatalf("expected no commit, got %d", tm.commitCalls)
		}
		if tm.rollbackCalls != 1 {
			t.Fatalf("expected one rollback, got %d", tm.rollbackCalls)
		}
		if otp.sendCalls != 0 {
			t.Fatal("expected no OTP send when the transaction failed")
		}
	})
}

// TestTwoFactorCtrlIssueChallenge_WritesShareOneTransaction covers the same
// pairing on the other path that has it.
func TestTwoFactorCtrlIssueChallenge_WritesShareOneTransaction(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(42)
	contactID := domain.NewIDFromUint64(99)

	tokenRepo := &twoFactorTokenRepoResendStub{createErr: errors.New("insert failed")}
	tm := &txManagerStub{}
	otp := &otpCtrlResendStub{}

	ctrl := TwoFactorCtrl{
		tokens: tokenRepo,
		settings: &settingsRepoTwoFactorStub{
			settings: domain.TwoFactorSettings{
				UserID:    userID,
				ContactID: &contactID,
				Method:    domain.TwoFactorMethodEmail,
			},
		},
		contacts: &contactRepoResendStub{
			contact: domain.ContactMethod{
				ID:     contactID,
				UserID: userID,
				Type:   domain.ContactTypeEmail,
				Value:  "user@example.com",
				Status: domain.ContactStatusVerified,
			},
		},
		otpCtrl:            otp,
		transactionManager: tm,
	}

	if _, err := ctrl.IssueChallenge(context.Background(), domain.TwoFactorIssueChallengeParams{
		UserID: userID,
		Type:   domain.TwoFactorTokenTypeTwoFactorAuth,
	}); err == nil {
		t.Fatal("expected an error")
	}

	if tm.commitCalls != 0 || tm.rollbackCalls != 1 {
		t.Fatalf("unexpected tx calls: commit=%d rollback=%d", tm.commitCalls, tm.rollbackCalls)
	}
	if otp.sendCalls != 0 {
		t.Fatal("expected no OTP send when the transaction failed")
	}
}
