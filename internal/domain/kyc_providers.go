package domain

import "context"

type VerificationProvider uint8

const VerificationProvidersAmlBot VerificationProvider = iota + 1

var _verificationProviderToString = map[VerificationProvider]string{
	VerificationProvidersAmlBot: "amlBot",
}

// NewVerificationProvider creates a new VerificationProvider from a uint8 value.
func NewVerificationProvider(val uint8) VerificationProvider {
	return VerificationProvider(val)
}

// Uint8 returns the uint8 representation of the verification provider.
func (s VerificationProvider) Uint8() uint8 {
	return uint8(s)
}

// String returns the string representation of the VerificationProvider.
func (s VerificationProvider) String() string {
	if val, ok := _verificationProviderToString[s]; ok {
		return val
	}
	return "unknown"
}

// AmlBotService defines the interface for managing AML BOT service in the data layer.
type AmlBotService interface {
	GetFormUrl(context.Context, string, VerificationLevel) (ProviderInitRequestResult, error)
}
