package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"

	restrictionsvc "github.com/whagency/core-common/services/restriction"
)

// --- stubs -------------------------------------------------------------------

type registerUsersStub struct{ userRepoVerifyContactStub }

func (s *registerUsersStub) Create(_ context.Context, u *domain.User) error {
	u.ID = domain.NewIDFromUint64(1)
	return nil
}

type registerContactsStub struct {
	contactRepoVerifyContactStub
	exists bool
}

func (s *registerContactsStub) ExistsForTypeAndValue(context.Context, domain.ContactType, string) (bool, error) {
	return s.exists, nil
}

func (s *registerContactsStub) Create(_ context.Context, c *domain.ContactMethod) error {
	c.ID = domain.NewIDFromUint64(2)
	return nil
}

type registerProfilesStub struct{}

func (s *registerProfilesStub) Create(context.Context, *domain.Profile) error            { return nil }
func (s *registerProfilesStub) Update(context.Context, domain.UpdateProfileParams) error { return nil }
func (s *registerProfilesStub) Exists(context.Context, domain.ID) (bool, error)          { return false, nil }
func (s *registerProfilesStub) FindByUserID(context.Context, domain.ID) (domain.ProfileDetails, error) {
	return domain.ProfileDetails{}, domain.ErrRecordNotFound
}
func (s *registerProfilesStub) WithTxFromContext(context.Context) domain.ProfileRepository { return s }

type registerCredentialsStub struct{}

func (s *registerCredentialsStub) Create(context.Context, *domain.Credential) error { return nil }
func (s *registerCredentialsStub) FindByUserID(context.Context, domain.ID) (domain.Credential, error) {
	return domain.Credential{}, domain.ErrRecordNotFound
}

func (s *registerCredentialsStub) FindByUserIDForUpdate(context.Context, domain.ID) (domain.Credential, error) {
	return domain.Credential{}, domain.ErrRecordNotFound
}
func (s *registerCredentialsStub) Update(context.Context, *domain.Credential) error { return nil }
func (s *registerCredentialsStub) RegisterFailedLogin(context.Context, domain.ID, domain.LoginLockPolicy) (domain.Credential, error) {
	return domain.Credential{}, nil
}

func (s *registerCredentialsStub) ClearLoginFailures(context.Context, domain.ID) error { return nil }

func (s *registerCredentialsStub) WithTxFromContext(context.Context) domain.CredentialRepository {
	return s
}

type registerPasswordHelperStub struct{}

func (s *registerPasswordHelperStub) Hash(string) (string, error)         { return "hashed", nil }
func (s *registerPasswordHelperStub) Verify(string, string) (bool, error) { return true, nil }
func (s *registerPasswordHelperStub) Algorithm() domain.CredentialAlgorithm {
	return domain.CredentialAlgorithmBcrypt
}

// registerGeoStub reports no geo data, which is the tolerated path: registration
// falls back to defaults rather than failing.
type registerGeoStub struct{}

func (s *registerGeoStub) GetGeoInfo(string) (*domain.GeoInfo, error) {
	return nil, errors.New("no geo data")
}

func (s *registerGeoStub) GetAnonymousInfo(string) (*domain.AnonymousInfo, error) {
	return nil, errors.New("no anonymous data")
}

// registerOTPStub fails the send when sendErr is set.
type registerOTPStub struct {
	sendErr   error
	sendCalls int
}

func (s *registerOTPStub) Generate() (domain.OTPToken, error) {
	return domain.OTPToken{Code: "123456", Hash: "hash", Salt: "salt"}, nil
}
func (s *registerOTPStub) Verify(string, string, string) bool { return true }
func (s *registerOTPStub) Send(context.Context, domain.OTPMessage) error {
	s.sendCalls++
	return s.sendErr
}

// registerRestrictionStub allows registration from any country.
type registerRestrictionStub struct{}

func (s *registerRestrictionStub) IsGeoAllow(context.Context, string, restrictionsvc.GeoFilterOperationType) (bool, error) {
	return true, nil
}

func newRegisterCtrl(t *testing.T, otp *registerOTPStub, tokens *twoFaRepoVerifyContactStub) UserCtrl {
	t.Helper()

	return UserCtrl{
		users:              &registerUsersStub{},
		contacts:           &registerContactsStub{},
		profiles:           &registerProfilesStub{},
		credentials:        &registerCredentialsStub{},
		twoFaTokens:        tokens,
		otpCtrl:            otp,
		geoCtrl:            &registerGeoStub{},
		passwordHelper:     &registerPasswordHelperStub{},
		restriction:        &registerRestrictionStub{},
		transactionManager: &txManagerStub{},
	}
}

func registerParams() domain.UserRegisterParams {
	return domain.UserRegisterParams{
		Contact: domain.ContactInput{
			Type:  domain.ContactTypeEmail,
			Value: "user@example.com",
		},
		Password: "Sup3rSecret!",
	}
}

// --- tests -------------------------------------------------------------------

// TestUserCtrlRegister_ReportsDeliveryOutcome pins the honesty of the response.
//
// Registration deliberately succeeds even when the code cannot be sent — the
// account and token are already committed, and erroring would discard the
// TokenUUID the client needs to resend while the contact-already-used guard
// blocks registering again. CodeDelivered is what stops that from silently
// leaving the user watching an empty inbox.
func TestUserCtrlRegister_ReportsDeliveryOutcome(t *testing.T) {
	initTestLogger(t)

	tests := []struct {
		name              string
		sendErr           error
		wantDelivered     bool
		wantDispatchClear bool
	}{
		{name: "delivered", wantDelivered: true},
		{
			name:              "send failed",
			sendErr:           errors.New("queue unavailable"),
			wantDelivered:     false,
			wantDispatchClear: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otp := &registerOTPStub{sendErr: tt.sendErr}
			tokens := &twoFaRepoVerifyContactStub{}

			ctrl := newRegisterCtrl(t, otp, tokens)

			res, err := ctrl.Register(context.Background(), registerParams())
			if err != nil {
				t.Fatalf("Register returned error: %v", err)
			}

			if res.CodeDelivered != tt.wantDelivered {
				t.Fatalf("expected CodeDelivered=%t, got %t", tt.wantDelivered, res.CodeDelivered)
			}
			if res.TokenUUID == "" {
				t.Fatal("the token must be returned even when delivery failed; the client needs it to resend")
			}

			// The cooldown is stamped at token creation, before the send. Leaving it
			// in place after a failed send would make the user wait out an interval
			// for a dispatch that never happened.
			cleared := len(tokens.clearedDispatchUUIDs) > 0
			if cleared != tt.wantDispatchClear {
				t.Fatalf("expected dispatch cleared=%t, got %t", tt.wantDispatchClear, cleared)
			}
		})
	}
}

// TestTwoFactorToken_ClearedDispatchAllowsImmediateResend checks the other half of
// that mechanism: a cleared timestamp puts RetryAfter in the past, which is what
// the resend endpoint already reads as "allowed".
func TestTwoFactorToken_ClearedDispatchAllowsImmediateResend(t *testing.T) {
	t.Parallel()

	// The cooldown the resend endpoint runs with in production comes from
	// OTP_REFRESH_INTERVAL. It is passed in explicitly here so the contrast below
	// tests the cooldown rather than clock granularity.
	const refreshInterval = time.Minute

	// The state ClearDispatchedAt leaves behind: an active, unconsumed token whose
	// dispatch timestamp is zero because the send never happened.
	cleared := domain.TwoFactorToken{Status: domain.TwoFactorTokenStatusActive}
	if !cleared.IsRefreshable(refreshInterval) {
		t.Fatal("a token with no recorded dispatch must be resendable immediately")
	}

	// And the contrast: a token dispatched just now is still inside its cooldown,
	// so the reset is doing real work rather than being a no-op.
	justSent := domain.TwoFactorToken{
		Status:       domain.TwoFactorTokenStatusActive,
		DispatchedAt: time.Now().UTC(),
	}
	if justSent.IsRefreshable(refreshInterval) {
		t.Fatal("a token dispatched just now must still be inside its resend cooldown")
	}
}
