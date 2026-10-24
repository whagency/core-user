# errors: Service Error Specification for Frontend

This document describes only internal service error codes from `internal/domain/errors` (`100001+`).

## 1) Standard Error Response Structure

Errors are returned in a unified response format:

```json
{
  "code": 100006,
  "message": "invalid credentials.",
  "data": {},
  "meta": {
    "requestId": "010a0998-4b1a-4e70-a951-d27a40b49c0c",
    "timestamp": "2025-10-07T12:00:45Z"
  }
}
```

### Response Fields

- `code` (`number`) - service error code (`> 0` means error).
- `message` (`string`) - backend message (English).
- `data` (`object`) - additional details; if none, backend returns `{}`.
- `meta.requestId` (`string`) - request identifier for tracing/support.
- `meta.timestamp` (`string`, RFC3339) - response timestamp.

## 2) Service Error Codes (`internal/domain/errors`)

| Code | Constant | HTTP | Message | `data` payload |
|---:|---|---:|---|---|
| 100001 | `CodeInvalidError` | 404 | `code is invalid.` | `{}` |
| 100002 | `CodeExpiredError` | 404 | `code has expired.` | `{}` |
| 100003 | `CodeConsumedError` | 404 | `code has already been used.` | `{}` |
| 100004 | `CodeAttemptsExceededError` | 429 | `code attempts exceeded.` | `{}` |
| 100005 | `CodeResendRateLimitedError` | 429 | `code resend rate limited.` | `{"retryAfter":"<RFC3339>"}` |
| 100006 | `AccountInvalidCredentialsError` | 401 | `invalid credentials.` | `{}` |
| 100007 | `AccountPendingVerificationError` | 403 | `account is pending verification.` | `{}` |
| 100008 | `AccountBlockedError` | 403 | `account is blocked.` | `{}` |
| 100009 | `AccountPasswordRequiredRotation` | 403 | `password rotation required.` | `{}` |
| 100010 | `AccountContactUnverifiedError` | 403 | `account contact is unverified.` | `{}` |
| 100011 | `ContactAlreadyVerifiedError` | 409 | `contact already verified.` | `{}` |
| 100012 | `PasswordChangeCurrentPasswordInvalidError` | 404 | `current password is invalid.` | `{}` |
| 100013 | `PasswordChangeReuseNotAllowedError` | 403 | `password reuse is not allowed.` | `{}` |
| 100014 | `TwoFactorAlreadyEnabledError` | 409 | `two-factor authentication is already enabled.` | `{}` |
| 100015 | `VerificationUserAlreadyVerifiedError` | 409 | `user has already been verified.` | `{}` |
| 100016 | `VerificationUserHasPendingError` | 409 | `pending verification already exists.` | `{}` |
| 100017 | `VerificationUserAlreadyCompletedError` | 409 | `user has already completed the verification process.` | `{}` |
| 100018 | `InvalidSignatureError` | 403 | `invalid signature.` | `{}` |
| 100019 | `UserSessionRefreshTokenExpiredError` | 401 | `user session refresh token has expired.` | `{}` |
| 100020 | `UserSessionRefreshTokenInvalidError` | 401 | `user session refresh token is invalid.` | `{}` |
| 100021 | `UserRegistrationCountryNotAllowedError` | 403 | `registrations from this country are not allowed.` | `{}` |
| 100022 | `UserRegistrationVPNDetectedError` | 403 | `registrations via VPN are not allowed.` | `{}` |
| 100023 | `UserRegistrationContactAlreadyUsedError` | 409 | `contact is already in use.` | `{}` |
| 100024 | `RecaptchaValidationError` | 422 | `recaptcha token is invalid.` | `{}` |
| 100025 | `AccountLoginAttemptsExceededError` | 429 | `too many failed sign-in attempts.` | `{"retryAfter":"<RFC3339>"}` |

## 3) Specific `data` Payloads from Controllers/Handlers

### 3.1 Service code with extra `data`

`CodeResendRateLimitedError` (`100005`) is returned in `TwoFactorCtrl.ResendChallenge` with:

```json
{
  "code": 100005,
  "message": "code resend rate limited.",
  "data": {
    "retryAfter": "2025-10-07T12:10:45Z"
  }
}
```

- `retryAfter` - RFC3339 timestamp when resend is allowed again.

### 3.2 Handler validation `data` (not service codes, but used in handlers)

Handlers build structured validation payload via `WithData` / `WithValidationData`:

```json
{
  "code": 11,
  "message": "data validation error.",
  "data": {
    "errors": [
      {
        "field": "tokenType",
        "tag": "oneof",
        "params": ["verify_contact", "password_reset", "two_factor_auth"]
      }
    ]
  }
}
```

Observed explicit `WithValidationData` cases:
- `POST /api/v1/2fa/activate` -> `field=method`, `params=[google,email]`
- `POST /api/v1/2fa/otp/resend` -> `field=tokenType`, `params=[verify_contact,password_reset,two_factor_auth]`
- `POST /api/v1/2fa/challenge/resend` -> `field=tokenType`, `params=[two_factor_setup,two_factor_disable]`

## 4) Where Service Codes Are Emitted (Controllers/Handlers)

- Auth flow: `AuthCtrl.Login`, `AuthCtrl.CompleteLoginChallenge`, `User.ValidateStatus`
- User flow: `UserCtrl.Register`, `UserCtrl.VerifyContact`, `UserCtrl.ChangePassword`
- Password recovery: `PasswordRecoveryCtrl.Request`, `PasswordRecoveryCtrl.Confirm`
- 2FA flow: `TwoFactorCtrl.Activate`, `TwoFactorCtrl.ResendChallenge`, `TwoFactorCtrl.Confirm`
- Session refresh: `SessionCtrl.RefreshSession`
- Verification flow: `VerificationCtrl.Init`, `VerificationCtrl.Process`
- Webhook validation: `AmlBotWebhookHandler.Handle` (`InvalidSignatureError`)

Current codebase note:
- `ContactAlreadyVerifiedError` (`100011`) is registered but not emitted in controllers/handlers at this moment.

## 5) Fallback Behavior

If an unknown code is requested from the registry, backend falls back to common `InternalServerError` (HTTP `500`).

## Source of Truth

- `internal/domain/errors/codes.go`
- `internal/domain/errors/messages.go`
- `internal/domain/errors/templates.go`
- `internal/controllers/auth.go`
- `internal/controllers/user.go`
- `internal/controllers/password_recovery.go`
- `internal/controllers/two_factor.go`
- `internal/controllers/session.go`
- `internal/controllers/verification.go`
- `internal/domain/user.go`
- `internal/transport/http/handlers/verifications/webhooks/aml_bot.go`
