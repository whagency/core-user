package webhooks

import (
	"testing"

	"user-service/internal/domain"
)

func TestAmlBotWebhookRequestDecode_CompletedVerified(t *testing.T) {
	req := amlBotWebhookRequest{
		Type:     amlBotTypeCompleted,
		Status:   amlBotStatusCompleted,
		Verified: true,
		Applicant: amlBotApplicantWebhookRequest{
			ExternalApplicantID: "external-id",
			FirstName:           strPtr("  Robert  "),
			LastName:            strPtr("  Vex  "),
		},
	}

	params, shouldProcess, errResponse := req.decode()
	if errResponse != nil {
		t.Fatalf("expected nil error, got %+v", errResponse)
	}
	if !shouldProcess {
		t.Fatal("expected supported webhook event")
	}
	if params.Status != domain.VerificationStatusCompleteYes {
		t.Fatalf("expected complete yes, got %s", params.Status.String())
	}
	if params.Profile.FirstName == nil || *params.Profile.FirstName != "Robert" {
		t.Fatalf("expected normalized first name, got %#v", params.Profile.FirstName)
	}
	if params.Profile.LastName == nil || *params.Profile.LastName != "Vex" {
		t.Fatalf("expected normalized last name, got %#v", params.Profile.LastName)
	}
}

func TestAmlBotWebhookRequestDecode_UnsupportedStatusCombinationIgnored(t *testing.T) {
	req := amlBotWebhookRequest{
		Type:     amlBotTypeStatusChanged,
		Status:   amlBotStatusCompleted,
		Verified: false,
		Applicant: amlBotApplicantWebhookRequest{
			ExternalApplicantID: "external-id",
		},
	}

	params, shouldProcess, errResponse := req.decode()
	if errResponse != nil {
		t.Fatalf("expected nil error, got %+v", errResponse)
	}
	if shouldProcess {
		t.Fatal("expected unsupported webhook event to be ignored")
	}
	if params != (domain.VerificationProcessParams{}) {
		t.Fatalf("expected zero params, got %+v", params)
	}
}

func TestAmlBotWebhookRequestDecode_UnknownTypeIgnored(t *testing.T) {
	req := amlBotWebhookRequest{
		Type:     "VERIFICATION_REJECTED",
		Status:   amlBotStatusCompleted,
		Verified: false,
		Applicant: amlBotApplicantWebhookRequest{
			ExternalApplicantID: "external-id",
		},
	}

	_, shouldProcess, errResponse := req.decode()
	if errResponse != nil {
		t.Fatalf("expected nil error, got %+v", errResponse)
	}
	if shouldProcess {
		t.Fatal("expected unknown webhook event to be ignored")
	}
}

func strPtr(value string) *string {
	return &value
}
