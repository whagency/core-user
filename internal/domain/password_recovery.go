package domain

import (
	"context"
	"time"
)

// PasswordResetRequestParams captures the fields required to initiate password recovery.
type PasswordResetRequestParams struct {
	Identifier string
	Recaptcha  string
}

// PasswordResetRequestResult describes the metadata returned after issuing a challenge.
type PasswordResetRequestResult struct {
	ContactMethod ContactMethod
	ExpiresAt     time.Time
	TokenUUID     string
}

// PasswordResetConfirmParams captures the data required to confirm a password reset.
type PasswordResetConfirmParams struct {
	TokenUUID   string
	Code        string
	NewPassword string
	SessionClientDeviceData
}

// PasswordRecoveryController orchestrates the password recovery flow.
type PasswordRecoveryController interface {
	Request(ctx context.Context, in PasswordResetRequestParams) (PasswordResetRequestResult, error)
	Confirm(ctx context.Context, in PasswordResetConfirmParams) error
}
