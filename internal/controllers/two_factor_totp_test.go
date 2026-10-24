package controllers

import (
	"context"
	"testing"
	"time"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
)

const totpTestSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// totpCodeFor produces the code an authenticator app would show for a step, so a
// test can present the same six digits twice the way an attacker would.
//
// It goes through the production hotpFromKey rather than repeating the
// derivation: what is under test is that a step is spent once, not the HOTP
// arithmetic.
func totpCodeFor(t *testing.T, counter int64) string {
	t.Helper()

	if counter < 0 {
		t.Fatalf("a time step cannot be negative, got %d", counter)
		return ""
	}

	key, err := _base32NoPadding.DecodeString(totpTestSecret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	return hotpFromKey(key, uint64(counter))
}

func currentTOTPStep() int64 {
	return time.Now().UTC().Unix() / _totpStepSeconds
}

// totpSettingsStub records the accepted step the way the real conditional UPDATE
// does: the move only happens when the new step is strictly greater.
type totpSettingsStub struct {
	lastCounter int64
	advances    int
	err         error
}

func (s *totpSettingsStub) FindByUserID(context.Context, domain.ID) (domain.TwoFactorSettings, error) {
	return domain.TwoFactorSettings{}, domain.ErrRecordNotFound
}
func (s *totpSettingsStub) Create(context.Context, *domain.TwoFactorSettings) error { return nil }
func (s *totpSettingsStub) Delete(context.Context, domain.ID) error                 { return nil }

func (s *totpSettingsStub) AdvanceTOTPCounter(_ context.Context, _ domain.ID, counter int64) (bool, error) {
	s.advances++
	if s.err != nil {
		return false, s.err
	}
	if counter <= s.lastCounter {
		return false, nil
	}
	s.lastCounter = counter
	return true, nil
}

func (s *totpSettingsStub) WithTxFromContext(context.Context) domain.TwoFactorSettingsRepository {
	return s
}

func googleToken(tokenType domain.TwoFactorTokenType) domain.TwoFactorToken {
	return domain.TwoFactorToken{
		UUID:      "token-uuid",
		UserID:    domain.NewIDFromUint64(3),
		Type:      tokenType,
		Method:    domain.TwoFactorMethodGoogle,
		Secret:    totpTestSecret,
		Status:    domain.TwoFactorTokenStatusActive,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
}

// The defect: consuming the token stopped a replay against that same challenge,
// but the same six digits stayed good against a different one for the whole
// window. Someone who saw the code the victim had just typed could start their
// own sign-in and enter it.
func TestVerifyTokenCode_TOTPCodeIsAcceptedOnlyOnce(t *testing.T) {
	initTestLogger(t)

	settings := &totpSettingsStub{}
	ctrl := TwoFactorCtrl{settings: settings}

	step := currentTOTPStep()
	code := totpCodeFor(t, step)

	// First challenge: accepted.
	counter, ok, er := ctrl.verifyTokenCode(context.Background(), googleToken(domain.TwoFactorTokenTypeTwoFactorAuth), code)
	if er != nil {
		t.Fatalf("unexpected error: %v", er)
	}
	if !ok {
		t.Fatal("a fresh code must be accepted")
	}
	if counter != step {
		t.Fatalf("expected the matched step %d, got %d", step, counter)
	}

	// A second challenge, same code, inside the window it stays valid.
	_, ok, er = ctrl.verifyTokenCode(context.Background(), googleToken(domain.TwoFactorTokenTypeTwoFactorAuth), code)
	if er != nil {
		t.Fatalf("unexpected error: %v", er)
	}
	if ok {
		t.Fatal("the same code must not open a second challenge")
	}
}

// The step before the current one is inside the accepted window, so a code the
// user typed a moment ago must not become usable again after a newer one.
func TestVerifyTokenCode_TOTPWillNotGoBackwards(t *testing.T) {
	initTestLogger(t)

	step := currentTOTPStep()
	settings := &totpSettingsStub{lastCounter: step}
	ctrl := TwoFactorCtrl{settings: settings}

	previous := totpCodeFor(t, step-1)

	_, ok, er := ctrl.verifyTokenCode(context.Background(), googleToken(domain.TwoFactorTokenTypeTwoFactorAuth), previous)
	if er != nil {
		t.Fatalf("unexpected error: %v", er)
	}
	if ok {
		t.Fatal("a step at or below the last accepted one must be refused")
	}
}

// Enrolment has no settings row to record against yet, so it reports the step
// for Confirm to seed instead of trying to spend it.
func TestVerifyTokenCode_SetupReportsTheStepWithoutSpendingIt(t *testing.T) {
	initTestLogger(t)

	settings := &totpSettingsStub{}
	ctrl := TwoFactorCtrl{settings: settings}

	step := currentTOTPStep()
	counter, ok, er := ctrl.verifyTokenCode(
		context.Background(),
		googleToken(domain.TwoFactorTokenTypeTwoFactorSetup),
		totpCodeFor(t, step),
	)
	if er != nil {
		t.Fatalf("unexpected error: %v", er)
	}
	if !ok || counter != step {
		t.Fatalf("expected the enrolment code accepted at step %d, got ok=%t counter=%d", step, ok, counter)
	}
	if settings.advances != 0 {
		t.Fatalf("enrolment has no settings row to advance, got %d attempts", settings.advances)
	}
}

// An OTP delivered by mail or SMS has no time step; the counter machinery must
// not touch those.
func TestVerifyTokenCode_EmailCodeDoesNotTouchTheCounter(t *testing.T) {
	initTestLogger(t)

	settings := &totpSettingsStub{}
	otp := &otpCtrlResendStub{}
	ctrl := TwoFactorCtrl{settings: settings, otpCtrl: otp}

	token := domain.TwoFactorToken{
		UserID:   domain.NewIDFromUint64(3),
		Type:     domain.TwoFactorTokenTypeTwoFactorAuth,
		Method:   domain.TwoFactorMethodEmail,
		CodeHash: "hash",
		CodeSalt: "salt",
	}

	if _, _, er := ctrl.verifyTokenCode(context.Background(), token, "123456"); er != nil {
		t.Fatalf("unexpected error: %v", er)
	}
	if settings.advances != 0 {
		t.Fatalf("an email code has no step to spend, got %d attempts", settings.advances)
	}
}

// A database failure while spending the step must not read as a wrong code: the
// user would lose an attempt for an outage they had no part in.
func TestVerifyTokenCode_CounterFailureSurfaces(t *testing.T) {
	initTestLogger(t)

	settings := &totpSettingsStub{err: context.DeadlineExceeded}
	ctrl := TwoFactorCtrl{settings: settings}

	_, ok, er := ctrl.verifyTokenCode(
		context.Background(),
		googleToken(domain.TwoFactorTokenTypeTwoFactorAuth),
		totpCodeFor(t, currentTOTPStep()),
	)
	if ok {
		t.Fatal("a failed counter update must not count as a pass")
	}
	switch {
	case er == nil:
		t.Fatal("expected the failure to surface rather than look like a wrong code")
	case er.Code != appErrors.DatabaseError:
		t.Fatalf("expected DatabaseError, got %d", er.Code)
	}
}
