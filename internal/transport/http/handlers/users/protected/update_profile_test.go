package protected

import (
	"testing"

	"user-service/internal/domain"

	appErrors "github.com/whagency/core-common/errorsx"
)

func TestUpdateProfileRequestDecode_NormalizesPayload(t *testing.T) {
	session := domain.AuthenticatedSession{UserID: domain.NewIDFromUint64(42)}
	firstName := "  Robert  "
	lastName := "  Vex  "
	address := "  Kyiv, UA  "
	locale := "en-US"
	timezone := "UTC"
	dob := "1986-01-02"

	params, errResponse := updateProfileRequest{
		FirstName:   &firstName,
		LastName:    &lastName,
		Address:     &address,
		Locale:      &locale,
		Timezone:    &timezone,
		DateOfBirth: &dob,
	}.decode("[UpdateProfileHandler:Handle]", session)
	if errResponse != nil {
		t.Fatalf("expected nil error, got %+v", errResponse)
	}

	if params.UserID != session.UserID {
		t.Fatalf("unexpected user id: %v", params.UserID)
	}
	if params.FirstName == nil || *params.FirstName != "Robert" {
		t.Fatalf("expected normalized firstName, got %#v", params.FirstName)
	}
	if params.LastName == nil || *params.LastName != "Vex" {
		t.Fatalf("expected normalized lastName, got %#v", params.LastName)
	}
	if params.Address == nil || *params.Address != "Kyiv, UA" {
		t.Fatalf("expected normalized address, got %#v", params.Address)
	}
	if params.Locale == nil || *params.Locale != "en_US" {
		t.Fatalf("expected normalized locale, got %#v", params.Locale)
	}
	if params.Timezone == nil || *params.Timezone != "UTC" {
		t.Fatalf("expected timezone, got %#v", params.Timezone)
	}
	if params.DateOfBirth == nil || *params.DateOfBirth != "1986-01-02" {
		t.Fatalf("expected dob, got %#v", params.DateOfBirth)
	}
}

func TestUpdateProfileRequestDecode_ReturnsValidationErrors(t *testing.T) {
	session := domain.AuthenticatedSession{UserID: domain.NewIDFromUint64(42)}
	firstName := " "
	locale := "bad_locale"
	timezone := "Mars/Base"
	dob := "2026-99-01"

	_, errResponse := updateProfileRequest{
		FirstName:   &firstName,
		Locale:      &locale,
		Timezone:    &timezone,
		DateOfBirth: &dob,
	}.decode("[UpdateProfileHandler:Handle]", session)
	if errResponse == nil {
		t.Fatal("expected validation error")
	}
	if errResponse.Code != appErrors.ValidationError {
		t.Fatalf("expected validation error code, got %d", errResponse.Code)
	}

	errorsData, ok := errResponse.Data["errors"].([]map[string]any)
	if !ok {
		t.Fatalf("expected validation errors payload, got %#v", errResponse.Data["errors"])
	}
	if len(errorsData) != 4 {
		t.Fatalf("expected 4 validation errors, got %d", len(errorsData))
	}
}
