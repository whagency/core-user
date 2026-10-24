package errors

import (
	"net/http"

	"github.com/whagency/core-common/errorsx"
)

// Templates returns a map of error codes to their corresponding error templates for the account domain.
func Templates() map[int]errorsx.Template {
	return map[int]errorsx.Template{
		CodeInvalidError: {
			Code:       CodeInvalidError,
			Message:    CodeInvalidErrMessage,
			HTTPStatus: http.StatusNotFound,
		},
		CodeExpiredError: {
			Code:       CodeExpiredError,
			Message:    CodeExpiredErrMessage,
			HTTPStatus: http.StatusNotFound,
		},
		CodeConsumedError: {
			Code:       CodeConsumedError,
			Message:    CodeConsumedErrMessage,
			HTTPStatus: http.StatusNotFound,
		},
		CodeAttemptsExceededError: {
			Code:       CodeAttemptsExceededError,
			Message:    CodeAttemptsExceededErrMessage,
			HTTPStatus: http.StatusTooManyRequests,
		},
		CodeResendRateLimitedError: {
			Code:       CodeResendRateLimitedError,
			Message:    CodeResendRateLimitedErrMessage,
			HTTPStatus: http.StatusTooManyRequests,
		},

		AccountInvalidCredentialsError: {
			Code:       AccountInvalidCredentialsError,
			Message:    AccountInvalidCredentialsErrMessage,
			HTTPStatus: http.StatusUnauthorized,
		},
		AccountPendingVerificationError: {
			Code:       AccountPendingVerificationError,
			Message:    AccountPendingVerificationErrMessage,
			HTTPStatus: http.StatusForbidden,
		},
		AccountBlockedError: {
			Code:       AccountBlockedError,
			Message:    AccountBlockedErrMessage,
			HTTPStatus: http.StatusForbidden,
		},
		AccountPasswordRequiredRotation: {
			Code:       AccountPasswordRequiredRotation,
			Message:    AccountPasswordRequiredRotationErrMessage,
			HTTPStatus: http.StatusForbidden,
		},
		AccountContactUnverifiedError: {
			Code:       AccountContactUnverifiedError,
			Message:    AccountContactUnverifiedErrMessage,
			HTTPStatus: http.StatusForbidden,
		},

		ContactAlreadyVerifiedError: {
			Code:       ContactAlreadyVerifiedError,
			Message:    ContactAlreadyVerifiedErrMessage,
			HTTPStatus: http.StatusConflict,
		},

		PasswordChangeCurrentPasswordInvalidError: {
			Code:       PasswordChangeCurrentPasswordInvalidError,
			Message:    PasswordChangeCurrentPasswordInvalidErrMessage,
			HTTPStatus: http.StatusNotFound,
		},
		PasswordChangeReuseNotAllowedError: {
			Code:       PasswordChangeReuseNotAllowedError,
			Message:    PasswordChangeReuseNotAllowedErrMessage,
			HTTPStatus: http.StatusForbidden,
		},

		TwoFactorAlreadyEnabledError: {
			Code:       TwoFactorAlreadyEnabledError,
			Message:    TwoFactorAlreadyEnabledErrMessage,
			HTTPStatus: http.StatusConflict,
		},

		VerificationUserAlreadyVerifiedError: {
			Code:       VerificationUserAlreadyVerifiedError,
			Message:    VerificationUserAlreadyVerifiedErrMessage,
			HTTPStatus: http.StatusConflict,
		},
		VerificationUserHasPendingError: {
			Code:       VerificationUserHasPendingError,
			Message:    VerificationUserHasPendingErrMessage,
			HTTPStatus: http.StatusConflict,
		},
		VerificationUserAlreadyCompletedError: {
			Code:       VerificationUserAlreadyCompletedError,
			Message:    VerificationUserAlreadyCompletedErrMessage,
			HTTPStatus: http.StatusConflict,
		},

		InvalidSignatureError: {
			Code:       InvalidSignatureError,
			Message:    InvalidSignatureErrMessage,
			HTTPStatus: http.StatusForbidden,
		},
		UserSessionRefreshTokenExpiredError: {
			Code:       UserSessionRefreshTokenExpiredError,
			Message:    UserSessionRefreshTokenExpiredErrMessage,
			HTTPStatus: http.StatusUnauthorized,
		},
		UserSessionRefreshTokenInvalidError: {
			Code:       UserSessionRefreshTokenInvalidError,
			Message:    UserSessionRefreshTokenInvalidErrMessage,
			HTTPStatus: http.StatusUnauthorized,
		},

		UserRegistrationCountryNotAllowedError: {
			Code:       UserRegistrationCountryNotAllowedError,
			Message:    UserRegistrationCountryNotAllowedErrMessage,
			HTTPStatus: http.StatusForbidden,
		},
		UserRegistrationVPNDetectedError: {
			Code:       UserRegistrationVPNDetectedError,
			Message:    UserRegistrationVPNDetectedErrMessage,
			HTTPStatus: http.StatusForbidden,
		},
		UserRegistrationContactAlreadyUsedError: {
			Code:       UserRegistrationContactAlreadyUsedError,
			Message:    UserRegistrationContactAlreadyUsedErrMessage,
			HTTPStatus: http.StatusConflict,
		},
		RecaptchaValidationError: {
			Code:       RecaptchaValidationError,
			Message:    RecaptchaValidationErrMessage,
			HTTPStatus: http.StatusUnprocessableEntity,
		},
		AccountLoginAttemptsExceededError: {
			Code:       AccountLoginAttemptsExceededError,
			Message:    AccountLoginAttemptsExceededErrMessage,
			HTTPStatus: http.StatusTooManyRequests,
		},
	}
}
