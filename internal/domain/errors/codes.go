package errors

const _serviceCode = 100000

const (
	CodeInvalidError = _serviceCode + iota + 1
	CodeExpiredError
	CodeConsumedError
	CodeAttemptsExceededError
	CodeResendRateLimitedError

	AccountInvalidCredentialsError
	AccountPendingVerificationError
	AccountBlockedError
	AccountPasswordRequiredRotation
	AccountContactUnverifiedError

	ContactAlreadyVerifiedError

	PasswordChangeCurrentPasswordInvalidError
	PasswordChangeReuseNotAllowedError

	TwoFactorAlreadyEnabledError

	VerificationUserAlreadyVerifiedError
	VerificationUserHasPendingError
	VerificationUserAlreadyCompletedError

	InvalidSignatureError

	UserSessionRefreshTokenExpiredError
	UserSessionRefreshTokenInvalidError

	UserRegistrationCountryNotAllowedError
	UserRegistrationVPNDetectedError
	UserRegistrationContactAlreadyUsedError

	RecaptchaValidationError

	// AccountLoginAttemptsExceededError sits at the end rather than beside the
	// other Account* codes: the block is numbered by iota, so inserting into a
	// group would shift every code below it and break the contract the frontend
	// is written against. New codes go last.
	AccountLoginAttemptsExceededError
)
