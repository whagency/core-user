package domain

type NotificationPurpose string

// Supported notification purposes.
const (
	NotificationPurposeUnknown NotificationPurpose = "unknown"

	NotificationPurposeOTPRegistration  NotificationPurpose = "registrationOtp"
	NotificationPurposeOTPPasswordReset NotificationPurpose = "passwordResetOtp"
	NotificationPurposeOTP2FA           NotificationPurpose = "twoFactorOtp"
)
