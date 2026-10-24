package domain

import (
	"context"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/tools"
	"gorm.io/datatypes"
)

const _externalIDLength = 24

type VerificationStatus uint8

type VerificationLevel uint8

const (
	VerificationStatusNew VerificationStatus = iota + 1
	VerificationStatusPending
	VerificationStatusCompleteYes
	VerificationStatusCompleteNo
)

var _verificationStatusToString = map[VerificationStatus]string{
	VerificationStatusNew:         "new_request",
	VerificationStatusPending:     "pending",
	VerificationStatusCompleteYes: "complete_yes",
	VerificationStatusCompleteNo:  "complete_no",
}

const (
	VerificationLevelNon VerificationLevel = iota
	VerificationLevelBasic
	VerificationLevelAdvanced
	VerificationLevelPro
)

var _verificationLevelToString = map[VerificationLevel]string{
	VerificationLevelNon:      "non_verified",
	VerificationLevelBasic:    "basic",
	VerificationLevelAdvanced: "advanced",
	VerificationLevelPro:      "pro",
}

// NewVerificationStatus creates a new VerificationStatus from a uint8 value.
func NewVerificationStatus(val uint8) VerificationStatus {
	return VerificationStatus(val)
}

// NewVerificationLevel creates a new VerificationLevel from a uint8 value.
func NewVerificationLevel(val uint8) VerificationLevel {
	return VerificationLevel(val)
}

// Uint8 returns the uint8 representation of the verification status.
func (s VerificationStatus) Uint8() uint8 {
	return uint8(s)
}

// Uint8 returns the uint8 representation of the verification level.
func (s VerificationLevel) Uint8() uint8 {
	return uint8(s)
}

func (s VerificationLevel) IsMax() bool {
	var maxValue VerificationLevel
	for level := range _verificationLevelToString {
		if level > maxValue {
			maxValue = level
		}
	}
	return s == maxValue
}

// String returns the string representation of the VerificationStatus.
func (s VerificationStatus) String() string {
	if val, ok := _verificationStatusToString[s]; ok {
		return val
	}
	return "unknown"
}

// String returns the string representation of the VerificationLevel.
func (s VerificationLevel) String() string {
	if val, ok := _verificationLevelToString[s]; ok {
		return val
	}
	return "unknown"
}

type VerificationInitParams struct {
	UserID   ID
	Provider VerificationProvider
}
type VerificationInitResult struct {
	ProviderData any
}

// Verification represents a verification record.
type Verification struct {
	ID                ID
	UserID            ID
	Provider          VerificationProvider
	Status            VerificationStatus
	VerificationLevel VerificationLevel
	ExternalID        string
	ProviderData      any
	CreatedAt         time.Time
	UpdatedAt         *time.Time
}

type ProviderAmlBotDataPayload struct {
	FormURL string `json:"form_url"`
}

// GetFormUrl extracts the form URL from the ProviderData based on the provider type.
func (v *Verification) GetFormUrl() string {
	switch v.Provider {
	case VerificationProvidersAmlBot:
		var payload ProviderAmlBotDataPayload
		if err := jsoniter.Unmarshal(v.ProviderData.(datatypes.JSON), &payload); err == nil {
			return payload.FormURL
		}
	default:
		return ""
	}
	return ""
}

// MarshalProviderDataJSON marshals the ProviderData field to JSON.
func (v *Verification) MarshalProviderDataJSON() ([]byte, error) {
	return jsoniter.Marshal(v.ProviderData)
}

// IsComplete checks if the verification process is complete.
func (v *Verification) IsComplete() bool {
	return v.Status == VerificationStatusCompleteYes || v.Status == VerificationStatusCompleteNo
}

type VerificationUpdateParams struct {
	VerificationID ID
	Status         VerificationStatus
}

// NewVerification builds a new verification with the received attributes from provider.
func NewVerification(userID ID, provider VerificationProvider, level VerificationLevel) *Verification {
	return &Verification{
		UserID:            userID,
		Provider:          provider,
		Status:            VerificationStatusNew,
		VerificationLevel: level,
		ExternalID:        tools.GenerateTimeBasedString(_externalIDLength),
	}
}

type VerificationProcessParams struct {
	ExternalID string
	Provider   VerificationProvider
	Status     VerificationStatus
	Profile    UpdateProfileParams
}

type ProviderInitRequestResult struct {
	ProviderData any // This is a placeholder for any additional data that may be returned by the kyc provider.
}

// VerificationController provides KYC verification management operations.
type VerificationController interface {
	Init(context.Context, VerificationInitParams) (VerificationInitResult, error)
	Process(context.Context, VerificationProcessParams) error
}

// VerificationProviderController defines the interface for KYC verification providers.
type VerificationProviderController interface {
	InitRequest(context.Context, *Verification, VerificationLevel) (ProviderInitRequestResult, error)
}

// VerificationRepository defines the interface for managing verification entities in the data layer.
type VerificationRepository interface {
	Create(context.Context, *Verification) error
	GetLast(context.Context, ID) (Verification, error)
	GetLastPendingByUserIDAndProvider(context.Context, ID, VerificationProvider) (Verification, error)
	GetByProviderAndExternalIDForUpdate(context.Context, VerificationProvider, string) (Verification, error)
	Update(context.Context, VerificationUpdateParams) error

	// SetProviderData fills in what the provider returned for a verification that
	// was reserved before the call was made.
	SetProviderData(context.Context, ID, any) error

	WithTxFromContext(context.Context) VerificationRepository
}
