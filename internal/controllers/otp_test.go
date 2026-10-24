package controllers

import "testing"

func TestOTPCtrlGenerateUsesFixedCode(t *testing.T) {
	t.Parallel()

	ctrl, err := NewOTPController(nil, []byte("test-pepper"), WithFixedOTPCode("111111"))
	if err != nil {
		t.Fatalf("expected controller to be created, got error: %v", err)
	}

	token, err := ctrl.Generate()
	if err != nil {
		t.Fatalf("expected fixed OTP generation to succeed, got error: %v", err)
	}

	if token.Code != "111111" {
		t.Fatalf("expected fixed code to be used, got %q", token.Code)
	}

	if !ctrl.Verify("111111", token.Salt, token.Hash) {
		t.Fatal("expected fixed code to verify against generated hash")
	}
}

func TestOTPCtrlRejectsInvalidFixedCode(t *testing.T) {
	t.Parallel()

	_, err := NewOTPController(nil, []byte("test-pepper"), WithFixedOTPCode("12ab"))
	if err == nil {
		t.Fatal("expected invalid fixed OTP code to be rejected")
	}
}
