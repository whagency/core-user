package domain

import (
	"context"
	"time"
)

// OTPToken represents a one-time password token.
type OTPToken struct {
	Code      string
	Hash      string
	Salt      string
	ExpiresAt time.Time
}

// OTPMessage represents the message sent to the user containing the OTP code.
type OTPMessage struct {
	Purpose      NotificationPurpose `json:"purpose"`
	ContactType  string              `json:"contact_type"`
	ContactValue string              `json:"contact_value"`
	Code         string              `json:"code"`
	Locale       string              `json:"locale"`
}

// OTPController generates and verifies OTP tokens.
type OTPController interface {
	Generate() (OTPToken, error)
	Verify(code, salt, hash string) bool
	Send(ctx context.Context, message OTPMessage) error
}
