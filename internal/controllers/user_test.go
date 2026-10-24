package controllers

import (
	"context"
	"testing"
	"time"

	"user-service/internal/domain"
)

type userRepoGetProfileStub struct {
	user    domain.User
	findErr error
}

func (s *userRepoGetProfileStub) Create(context.Context, *domain.User) error { return nil }

func (s *userRepoGetProfileStub) SetPrimaryContact(context.Context, domain.ID, domain.ID) error {
	return nil
}

func (s *userRepoGetProfileStub) FindByID(context.Context, domain.ID) (domain.User, error) {
	if s.findErr != nil {
		return domain.User{}, s.findErr
	}
	return s.user, nil
}

func (s *userRepoGetProfileStub) FindByNumber(context.Context, int64) (domain.User, error) {
	return domain.User{}, domain.ErrRecordNotFound
}

func (s *userRepoGetProfileStub) ActivateIfPendingByUserID(context.Context, domain.ID) error {
	return nil
}

func (s *userRepoGetProfileStub) UpdateStatus(context.Context, domain.ID, domain.UserStatus) error {
	return nil
}

func (s *userRepoGetProfileStub) SetVerificationLevel(context.Context, domain.ID, domain.VerificationLevel) error {
	return nil
}

func (s *userRepoGetProfileStub) WithTxFromContext(context.Context) domain.UserRepository { return s }

type profileRepoGetProfileStub struct {
	profile domain.ProfileDetails
	findErr error
}

func (s *profileRepoGetProfileStub) Create(context.Context, *domain.Profile) error { return nil }

func (s *profileRepoGetProfileStub) Update(context.Context, domain.UpdateProfileParams) error {
	return nil
}

func (s *profileRepoGetProfileStub) Exists(context.Context, domain.ID) (bool, error) {
	return true, nil
}

func (s *profileRepoGetProfileStub) FindByUserID(context.Context, domain.ID) (domain.ProfileDetails, error) {
	if s.findErr != nil {
		return domain.ProfileDetails{}, s.findErr
	}
	return s.profile, nil
}

func (s *profileRepoGetProfileStub) WithTxFromContext(context.Context) domain.ProfileRepository {
	return s
}

type verificationRepoGetProfileStub struct {
	last    domain.Verification
	lastErr error
}

func (s *verificationRepoGetProfileStub) Create(context.Context, *domain.Verification) error {
	return nil
}

func (s *verificationRepoGetProfileStub) GetLast(context.Context, domain.ID) (domain.Verification, error) {
	if s.lastErr != nil {
		return domain.Verification{}, s.lastErr
	}
	return s.last, nil
}

func (s *verificationRepoGetProfileStub) GetLastPendingByUserIDAndProvider(context.Context, domain.ID, domain.VerificationProvider) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoGetProfileStub) GetByProviderAndExternalIDForUpdate(context.Context, domain.VerificationProvider, string) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *verificationRepoGetProfileStub) Update(context.Context, domain.VerificationUpdateParams) error {
	return nil
}

func (s *verificationRepoGetProfileStub) SetProviderData(context.Context, domain.ID, any) error {
	return nil
}

func (s *verificationRepoGetProfileStub) WithTxFromContext(context.Context) domain.VerificationRepository {
	return s
}

type contactRepoGetProfileStub struct {
	primary    domain.ContactMethod
	primaryErr error
}

func (s *contactRepoGetProfileStub) ExistsForTypeAndValue(context.Context, domain.ContactType, string) (bool, error) {
	return false, nil
}

func (s *contactRepoGetProfileStub) Create(context.Context, *domain.ContactMethod) error { return nil }

func (s *contactRepoGetProfileStub) FindByID(context.Context, domain.ID) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoGetProfileStub) FindByValue(context.Context, string) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoGetProfileStub) FindPrimaryByValue(context.Context, string) (domain.ContactMethod, error) {
	return domain.ContactMethod{}, domain.ErrRecordNotFound
}

func (s *contactRepoGetProfileStub) FindPrimaryByUser(context.Context, domain.ID) (domain.ContactMethod, error) {
	if s.primaryErr != nil {
		return domain.ContactMethod{}, s.primaryErr
	}
	return s.primary, nil
}

func (s *contactRepoGetProfileStub) FindPrimaryByUserAndType(context.Context, domain.ID, domain.ContactType) (domain.ContactMethod, error) {
	if s.primaryErr != nil {
		return domain.ContactMethod{}, s.primaryErr
	}
	return s.primary, nil
}

func (s *contactRepoGetProfileStub) MarkVerified(context.Context, domain.ID, time.Time) error {
	return nil
}

func (s *contactRepoGetProfileStub) WithTxFromContext(context.Context) domain.ContactRepository {
	return s
}

func TestUserCtrlGetProfile_NoLastVerification_ReturnsNilLastRequest(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(37)
	locale := "en_US"
	timezone := "UTC"

	ctrl := UserCtrl{
		users: &userRepoGetProfileStub{
			user: domain.User{
				ID:                userID,
				Number:            1001,
				Status:            domain.UserStatusActive,
				VerificationLevel: domain.VerificationLevelBasic,
			},
		},
		profiles: &profileRepoGetProfileStub{
			profile: domain.ProfileDetails{
				Country:  "US",
				Locale:   &locale,
				Timezone: &timezone,
			},
		},
		verifications: &verificationRepoGetProfileStub{
			lastErr: domain.ErrRecordNotFound,
		},
		contacts: &contactRepoGetProfileStub{
			primary: domain.ContactMethod{
				Type:   domain.ContactTypeEmail,
				Value:  "user@example.com",
				Status: domain.ContactStatusVerified,
			},
		},
	}

	result, err := ctrl.GetProfile(context.Background(), userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.LastUserVerificationRequest != nil {
		t.Fatalf("expected LastUserVerificationRequest to be nil when no verification exists, got %+v", result.LastUserVerificationRequest)
	}
}

func TestUserCtrlGetProfile_WithLastVerification_ReturnsLastRequest(t *testing.T) {
	initTestLogger(t)

	userID := domain.NewIDFromUint64(37)
	locale := "en_US"
	timezone := "UTC"
	createdAt := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)

	ctrl := UserCtrl{
		users: &userRepoGetProfileStub{
			user: domain.User{
				ID:                userID,
				Number:            1001,
				Status:            domain.UserStatusActive,
				VerificationLevel: domain.VerificationLevelBasic,
			},
		},
		profiles: &profileRepoGetProfileStub{
			profile: domain.ProfileDetails{
				Country:  "US",
				Locale:   &locale,
				Timezone: &timezone,
			},
		},
		verifications: &verificationRepoGetProfileStub{
			last: domain.Verification{
				Status:    domain.VerificationStatusPending,
				CreatedAt: createdAt,
			},
		},
		contacts: &contactRepoGetProfileStub{
			primary: domain.ContactMethod{
				Type:   domain.ContactTypeEmail,
				Value:  "user@example.com",
				Status: domain.ContactStatusVerified,
			},
		},
	}

	result, err := ctrl.GetProfile(context.Background(), userID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.LastUserVerificationRequest == nil {
		t.Fatalf("expected LastUserVerificationRequest to be present")
	}
	if result.LastUserVerificationRequest.Status != domain.VerificationStatusPending {
		t.Fatalf("expected pending status, got %s", result.LastUserVerificationRequest.Status.String())
	}
	if !result.LastUserVerificationRequest.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected createdAt %s, got %s", createdAt, result.LastUserVerificationRequest.CreatedAt)
	}
}
