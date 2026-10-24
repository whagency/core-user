package controllers

import (
	"context"
	"testing"
	"time"

	"user-service/internal/domain"

	outboxtestkit "github.com/whagency/core-common/outbox/testkit"
)

// dedupeKeys returns the dedupe key of every row the fake recorded, in order.
func dedupeKeys(repo *outboxtestkit.FakeRepository) []string {
	rows := repo.All()
	keys := make([]string, 0, len(rows))
	for i := range rows {
		keys = append(keys, rows[i].DedupeKey)
	}
	return keys
}

// TestUserCtrlVerifyContact_EnqueuesUserCreatedInsideTransaction covers the happy
// path of contact verification.
//
// The lifecycle event used to be published after the commit with the error logged
// and dropped. Losing it left the user activated here while restriction-service
// never learned they existed and never assigned a tier — a gap with no local
// symptom at all.
func TestUserCtrlVerifyContact_EnqueuesUserCreatedInsideTransaction(t *testing.T) {
	initTestLogger(t)

	tm := &txManagerStub{}
	userID := domain.NewIDFromUint64(77)
	contactID := domain.NewIDFromUint64(5)

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
	contactsRepo := &contactRepoVerifyContactStub{}
	outboxRepo := outboxtestkit.NewFakeRepository()

	ctrl := UserCtrl{
		users:              usersRepo,
		contacts:           contactsRepo,
		twoFaTokens:        twoFaRepo,
		otpCtrl:            &otpCtrlVerifyContactStub{verifyResult: true},
		outboxRepo:         outboxRepo,
		transactionManager: tm,
	}

	if err := ctrl.VerifyContact(context.Background(), domain.ContactVerifyParams{
		TokenUUID: "verify-token",
		Code:      "123456",
	}); err != nil {
		t.Fatalf("VerifyContact returned error: %v", err)
	}

	if got := dedupeKeys(outboxRepo); len(got) != 1 || got[0] != "user-created:77" {
		t.Fatalf("expected one user-created row keyed on the user, got %#v", got)
	}
	if tm.commitCalls != 1 {
		t.Fatalf("expected one commit, got %d", tm.commitCalls)
	}
	if tm.rollbackCalls != 0 {
		t.Fatalf("expected no rollback, got %d", tm.rollbackCalls)
	}
}
