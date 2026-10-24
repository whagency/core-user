package domain

import (
	"context"
	"time"
)

// LoginParams represents the credentials submitted during authentication.
type LoginParams struct {
	Identifier string
	Password   string
	Recaptcha  string
	SessionClientDeviceData
}

// LoginResult encapsulates the outcome of the authentication flow.
type LoginResult struct {
	UserID                   ID
	Session                  *SessionToken
	Requires2FA              bool
	TwoFactorChallengeResult *TwoFactorChallengeResult
}

// LoginChallengeVerifyParams captures the fields required to finalize a login guarded by 2FA.
type LoginChallengeVerifyParams struct {
	TokenUUID string
	Code      string
	SessionClientDeviceData
}

type LoginChallengeConfirmResult struct {
	Session SessionToken
}

// MeResult encapsulates the data returned for the authenticated user.
type MeResult struct {
	UserNumber                  uint64
	Status                      string
	VerificationLevel           VerificationLevel
	Contact                     *ContactMethod
	Profile                     ProfileDetails
	LastPasswordChangeAt        *time.Time
	LastUserVerificationRequest *LastUserVerificationRequest
}

// AuthController exposes the authentication application services focused on login.
type AuthController interface {
	Login(context.Context, LoginParams) (LoginResult, error)
	CompleteLoginChallenge(context.Context, LoginChallengeVerifyParams) (LoginChallengeConfirmResult, error)
	Me(context.Context, ID) (MeResult, error)
}
