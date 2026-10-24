package controllers

import (
	"context"
	"errors"
	"testing"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
)

// initVerificationsStub models the reserve step: what an existing lookup returns,
// and whether the insert wins or loses the unique index.
type initVerificationsStub struct {
	existing    domain.Verification
	existingErr error

	createErr error

	// afterCreate is what a lookup returns once the row exists -- either the one
	// this call wrote or, on a lost race, the winner's.
	afterCreate *domain.Verification

	createCalls  int
	lookupCalls  int
	setDataCalls int
	setData      any
}

func (s *initVerificationsStub) Create(_ context.Context, v *domain.Verification) error {
	s.createCalls++
	if s.createErr != nil {
		return s.createErr
	}
	v.ID = domain.NewIDFromUint64(500)
	return nil
}

func (s *initVerificationsStub) GetLast(context.Context, domain.ID) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *initVerificationsStub) GetLastPendingByUserIDAndProvider(context.Context, domain.ID, domain.VerificationProvider) (domain.Verification, error) {
	s.lookupCalls++
	if s.lookupCalls > 1 && s.afterCreate != nil {
		return *s.afterCreate, nil
	}
	if s.existingErr != nil {
		return domain.Verification{}, s.existingErr
	}
	return s.existing, nil
}

func (s *initVerificationsStub) GetByProviderAndExternalIDForUpdate(context.Context, domain.VerificationProvider, string) (domain.Verification, error) {
	return domain.Verification{}, domain.ErrRecordNotFound
}

func (s *initVerificationsStub) Update(context.Context, domain.VerificationUpdateParams) error {
	return nil
}

func (s *initVerificationsStub) SetProviderData(_ context.Context, _ domain.ID, data any) error {
	s.setDataCalls++
	s.setData = data
	return nil
}

func (s *initVerificationsStub) WithTxFromContext(context.Context) domain.VerificationRepository {
	return s
}

// initProviderStub counts how often the KYC provider was actually paid.
type initProviderStub struct {
	calls      int
	err        error
	externalID string
}

func (s *initProviderStub) InitRequest(_ context.Context, v *domain.Verification, _ domain.VerificationLevel) (domain.ProviderInitRequestResult, error) {
	s.calls++
	s.externalID = v.ExternalID
	if s.err != nil {
		return domain.ProviderInitRequestResult{}, s.err
	}
	return domain.ProviderInitRequestResult{ProviderData: "form-url"}, nil
}

func newInitFixture(verifications *initVerificationsStub, provider *initProviderStub) VerificationCtrl {
	return VerificationCtrl{
		providers: map[domain.VerificationProvider]domain.VerificationProviderController{
			domain.VerificationProvidersAmlBot: provider,
		},
		verifications: verifications,
		users: &userRepoGetProfileStub{user: domain.User{
			ID:                domain.NewIDFromUint64(7),
			Status:            domain.UserStatusActive,
			VerificationLevel: domain.VerificationLevelNon,
		}},
	}
}

func initParams() domain.VerificationInitParams {
	return domain.VerificationInitParams{
		UserID:   domain.NewIDFromUint64(7),
		Provider: domain.VerificationProvidersAmlBot,
	}
}

func TestVerificationInit_ReservesBeforeCallingTheProvider(t *testing.T) {
	initTestLogger(t)

	verifications := &initVerificationsStub{existingErr: domain.ErrRecordNotFound}
	provider := &initProviderStub{}
	ctrl := newInitFixture(verifications, provider)

	res, err := ctrl.Init(context.Background(), initParams())
	if err != nil {
		t.Fatalf("expected the init to succeed, got %v", err)
	}
	if res.ProviderData != "form-url" {
		t.Fatalf("expected the provider data back, got %v", res.ProviderData)
	}

	if verifications.createCalls != 1 {
		t.Fatalf("expected one row reserved, got %d", verifications.createCalls)
	}
	if provider.calls != 1 {
		t.Fatalf("expected exactly one provider call, got %d", provider.calls)
	}
	if verifications.setDataCalls != 1 || verifications.setData != "form-url" {
		t.Fatalf("expected the form to be stored once, got calls=%d data=%v",
			verifications.setDataCalls, verifications.setData)
	}
}

// The point of the whole change: whoever loses the unique index must not pay for
// a second applicant form.
func TestVerificationInit_LosingTheRaceCostsNoProviderCall(t *testing.T) {
	initTestLogger(t)

	winner := domain.Verification{
		ID:           domain.NewIDFromUint64(900),
		Status:       domain.VerificationStatusNew,
		ExternalID:   "winner-external-id",
		ProviderData: "winners-form-url",
	}

	verifications := &initVerificationsStub{
		existingErr: domain.ErrRecordNotFound,
		createErr:   domain.ErrRecordExists,
		afterCreate: &winner,
	}
	provider := &initProviderStub{}
	ctrl := newInitFixture(verifications, provider)

	res, err := ctrl.Init(context.Background(), initParams())
	if err != nil {
		t.Fatalf("losing the race is not a failure, got %v", err)
	}

	if provider.calls != 0 {
		t.Fatalf("the loser must not call the provider, got %d calls", provider.calls)
	}
	if res.ProviderData != "winners-form-url" {
		t.Fatalf("expected the winner's form, got %v", res.ProviderData)
	}
}

// A provider call that failed leaves a reserved row with no form. The next
// attempt finishes it rather than starting over, so the external id -- which the
// webhook matches on -- stays the same.
func TestVerificationInit_ResumesAReservationWithNoForm(t *testing.T) {
	initTestLogger(t)

	halfBuilt := domain.Verification{
		ID:         domain.NewIDFromUint64(901),
		Status:     domain.VerificationStatusNew,
		ExternalID: "already-reserved-id",
	}

	verifications := &initVerificationsStub{existing: halfBuilt}
	provider := &initProviderStub{}
	ctrl := newInitFixture(verifications, provider)

	if _, err := ctrl.Init(context.Background(), initParams()); err != nil {
		t.Fatalf("expected the resume to succeed, got %v", err)
	}

	if verifications.createCalls != 0 {
		t.Fatalf("a reserved row must be reused, not duplicated, got %d creates", verifications.createCalls)
	}
	if provider.externalID != halfBuilt.ExternalID {
		t.Fatalf("expected the reserved external id to be reused, got %q", provider.externalID)
	}
}

func TestVerificationInit_FailedProviderCallLeavesTheRowToBeResumed(t *testing.T) {
	initTestLogger(t)

	verifications := &initVerificationsStub{existingErr: domain.ErrRecordNotFound}
	provider := &initProviderStub{err: errors.New("amlbot unavailable")}
	ctrl := newInitFixture(verifications, provider)

	_, err := ctrl.Init(context.Background(), initParams())
	if err == nil {
		t.Fatal("expected the provider failure to surface")
	}

	er, ok := appErrors.AsErrorResponse(err)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
	if er.Code != appErrors.ExternalServiceError {
		t.Fatalf("expected ExternalServiceError, got %d", er.Code)
	}

	// The row stays, empty, for the next attempt to finish.
	if verifications.createCalls != 1 {
		t.Fatalf("expected the reservation to stand, got %d creates", verifications.createCalls)
	}
	if verifications.setDataCalls != 0 {
		t.Fatalf("nothing to store when the provider failed, got %d", verifications.setDataCalls)
	}
}

func TestVerificationInit_PendingVerificationIsRefused(t *testing.T) {
	initTestLogger(t)

	verifications := &initVerificationsStub{existing: domain.Verification{
		ID:     domain.NewIDFromUint64(902),
		Status: domain.VerificationStatusPending,
	}}
	provider := &initProviderStub{}
	ctrl := newInitFixture(verifications, provider)

	_, err := ctrl.Init(context.Background(), initParams())
	if err == nil {
		t.Fatal("expected a pending verification to block a new one")
	}

	er, _ := appErrors.AsErrorResponse(err)
	if er.Code != svcErrors.VerificationUserHasPendingError {
		t.Fatalf("expected VerificationUserHasPendingError, got %d", er.Code)
	}
	if provider.calls != 0 {
		t.Fatalf("a refused request must not call the provider, got %d", provider.calls)
	}
}
