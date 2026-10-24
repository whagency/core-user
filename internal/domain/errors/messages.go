package errors

const (
	CodeInvalidErrMessage                  = "code is invalid."
	CodeExpiredErrMessage                  = "code has expired."
	CodeConsumedErrMessage                 = "code has already been used."
	CodeAttemptsExceededErrMessage         = "code attempts exceeded."
	CodeResendRateLimitedErrMessage        = "code resend rate limited."
	AccountLoginAttemptsExceededErrMessage = "too many failed sign-in attempts."

	AccountInvalidCredentialsErrMessage       = "invalid credentials."
	AccountPendingVerificationErrMessage      = "account is pending verification."
	AccountBlockedErrMessage                  = "account is blocked."
	AccountPasswordRequiredRotationErrMessage = "password rotation required."
	AccountContactUnverifiedErrMessage        = "account contact is unverified."

	ContactAlreadyVerifiedErrMessage = "contact already verified."

	PasswordChangeCurrentPasswordInvalidErrMessage = "current password is invalid."
	PasswordChangeReuseNotAllowedErrMessage        = "password reuse is not allowed."

	TwoFactorAlreadyEnabledErrMessage = "two-factor authentication is already enabled."

	VerificationUserAlreadyVerifiedErrMessage  = "user has already been verified."
	VerificationUserHasPendingErrMessage       = "pending verification already exists."
	VerificationUserAlreadyCompletedErrMessage = "user has already completed the verification process."

	InvalidSignatureErrMessage = "invalid signature."

	UserSessionRefreshTokenExpiredErrMessage = "user session refresh token has expired."
	UserSessionRefreshTokenInvalidErrMessage = "user session refresh token is invalid."

	UserRegistrationCountryNotAllowedErrMessage  = "registrations from this country are not allowed."
	UserRegistrationVPNDetectedErrMessage        = "registrations via VPN are not allowed."
	UserRegistrationContactAlreadyUsedErrMessage = "contact is already in use."

	RecaptchaValidationErrMessage = "recaptcha token is invalid."
)
