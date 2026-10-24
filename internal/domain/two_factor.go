package domain

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	appErrors "github.com/whagency/core-common/errorsx"
)

const _twoFactorMaxAttempts uint16 = 5

type TwoFactorTokenType uint8

const (
	TwoFactorTokenTypeVerifyContact TwoFactorTokenType = iota + 1
	TwoFactorTokenTypePasswordReset
	TwoFactorTokenTypeTwoFactorSetup
	TwoFactorTokenTypeTwoFactorDisable
	TwoFactorTokenTypeTwoFactorAuth
)

var twoFactorTokenTypeToString = map[TwoFactorTokenType]string{
	TwoFactorTokenTypeVerifyContact:    "verify_contact",
	TwoFactorTokenTypePasswordReset:    "password_reset",
	TwoFactorTokenTypeTwoFactorSetup:   "two_factor_setup",
	TwoFactorTokenTypeTwoFactorDisable: "two_factor_disable",
	TwoFactorTokenTypeTwoFactorAuth:    "two_factor_auth",
}

var _twoFactorTokenTypeByString = map[string]TwoFactorTokenType{
	"verify_contact":     TwoFactorTokenTypeVerifyContact,
	"password_reset":     TwoFactorTokenTypePasswordReset,
	"two_factor_setup":   TwoFactorTokenTypeTwoFactorSetup,
	"two_factor_disable": TwoFactorTokenTypeTwoFactorDisable,
	"two_factor_auth":    TwoFactorTokenTypeTwoFactorAuth,
}

// String returns the string representation of the token type.
func (t TwoFactorTokenType) String() string {
	if val, ok := twoFactorTokenTypeToString[t]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation of the token type.
func (t TwoFactorTokenType) Uint8() uint8 {
	return uint8(t)
}

// NewTwoFactorTokenTypeFromString converts a transport string to TwoFactorTokenType.
func NewTwoFactorTokenTypeFromString(value string) (TwoFactorTokenType, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	tokenType, ok := _twoFactorTokenTypeByString[normalized]
	if ok {
		return tokenType, nil
	}

	return 0, fmt.Errorf("[domain][NewTwoFactorTokenTypeFromString][err: unsupported two-factor token type %q]", value)
}

// IsSupportedTwoFactorTokenType reports whether the two-factor token type is supported.
func IsSupportedTwoFactorTokenType(tokenType TwoFactorTokenType) bool {
	_, ok := twoFactorTokenTypeToString[tokenType]
	return ok
}

// SupportedTwoFactorTokenTypeStrings returns transport strings for supported two-factor token types.
func SupportedTwoFactorTokenTypeStrings() []string {
	return slices.Sorted(maps.Keys(_twoFactorTokenTypeByString))
}

// IsTwoFactorAction returns true if the token type is related to two-factor actions.
func (t TwoFactorTokenType) IsTwoFactorAction() bool {
	return t == TwoFactorTokenTypeTwoFactorSetup || t == TwoFactorTokenTypeTwoFactorDisable
}

// IsChallenge returns true if the token type is used for challenges.
func (t TwoFactorTokenType) IsChallenge() bool {
	return t == TwoFactorTokenTypeTwoFactorAuth || t == TwoFactorTokenTypePasswordReset || t == TwoFactorTokenTypeVerifyContact
}

// GetNotificationPurpose maps the token type to the corresponding notification purpose.
func (t TwoFactorTokenType) GetNotificationPurpose() NotificationPurpose {
	switch t {
	case TwoFactorTokenTypeVerifyContact:
		return NotificationPurposeOTPRegistration
	case TwoFactorTokenTypePasswordReset:
		return NotificationPurposeOTPPasswordReset
	case TwoFactorTokenTypeTwoFactorSetup,
		TwoFactorTokenTypeTwoFactorDisable,
		TwoFactorTokenTypeTwoFactorAuth:
		return NotificationPurposeOTP2FA
	default:
		return NotificationPurposeUnknown
	}
}

type TwoFactorTokenStatus uint8

const (
	TwoFactorTokenStatusActive TwoFactorTokenStatus = iota + 1
	TwoFactorTokenStatusUsed
	TwoFactorTokenStatusExpired
)

var twoFactorTokenStatusToString = map[TwoFactorTokenStatus]string{
	TwoFactorTokenStatusActive:  "active",
	TwoFactorTokenStatusUsed:    "used",
	TwoFactorTokenStatusExpired: "expired",
}

// String returns the string representation of the token status.
func (s TwoFactorTokenStatus) String() string {
	if val, ok := twoFactorTokenStatusToString[s]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation of the token status.
func (s TwoFactorTokenStatus) Uint8() uint8 {
	return uint8(s)
}

// TwoFactorToken represents a generic verification or recovery token issued to a user.
type TwoFactorToken struct {
	UUID         string
	UserID       ID
	ContactID    *ID
	Type         TwoFactorTokenType
	Method       TwoFactorMethod
	Secret       string
	CodeHash     string
	CodeSalt     string
	Status       TwoFactorTokenStatus
	Attempts     uint16
	ConsumedAt   *time.Time
	ExpiresAt    time.Time
	CreatedAt    time.Time
	DispatchedAt time.Time
}

// NewTwoFactorToken builds a new token with the provided attributes.
func NewTwoFactorToken(userID ID, method TwoFactorMethod, tokenType TwoFactorTokenType, contactID *ID, secret, codeHash, codeSalt string, expiresAt time.Time) TwoFactorToken {
	return TwoFactorToken{
		UUID:      uuid.NewString(),
		UserID:    userID,
		ContactID: contactID,
		Method:    method,
		Type:      tokenType,
		Secret:    secret,
		CodeHash:  codeHash,
		CodeSalt:  codeSalt,
		Status:    TwoFactorTokenStatusActive,
		ExpiresAt: expiresAt,
	}
}

// NewContactVerificationToken builds a token for contact verification challenges.
func NewContactVerificationToken(userID, contactID ID, method TwoFactorMethod, codeHash, codeSalt string, expiresAt time.Time) TwoFactorToken {
	return NewTwoFactorToken(userID, method, TwoFactorTokenTypeVerifyContact, &contactID, "", codeHash, codeSalt, expiresAt)
}

// NewPasswordResetToken builds a token for password reset flows.
func NewPasswordResetToken(userID, contactID ID, method TwoFactorMethod, codeHash, codeSalt string, expiresAt time.Time) TwoFactorToken {
	return NewTwoFactorToken(userID, method, TwoFactorTokenTypePasswordReset, &contactID, "", codeHash, codeSalt, expiresAt)
}

// NewTwoFactorSetupToken builds a token for enabling a two-factor method.
func NewTwoFactorSetupToken(userID ID, method TwoFactorMethod, contactID *ID, secret, codeHash, codeSalt string, expiresAt time.Time) TwoFactorToken {
	return NewTwoFactorToken(userID, method, TwoFactorTokenTypeTwoFactorSetup, contactID, secret, codeHash, codeSalt, expiresAt)
}

// IsExpired returns true when the token has passed its time to live.
func (t *TwoFactorToken) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

// IsConsumed returns true when the token is no longer active.
func (t *TwoFactorToken) IsConsumed() bool {
	return t.Status != TwoFactorTokenStatusActive || t.ConsumedAt != nil
}

// AttemptsLeft returns the remaining attempts before the token is locked.
func (t *TwoFactorToken) AttemptsLeft() uint16 {
	if t.Attempts >= _twoFactorMaxAttempts {
		return 0
	}
	return _twoFactorMaxAttempts - t.Attempts
}

// IsRefreshable returns true if the token can be refreshed, given the resend
// cooldown the caller enforces.
func (t *TwoFactorToken) IsRefreshable(refreshInterval time.Duration) bool {
	return time.Now().UTC().After(t.RetryAfter(refreshInterval)) && !t.IsConsumed()
}

// RetryAfter calculates when the token can be retried or refreshed. The cooldown
// is passed in rather than read from config so the domain stays independent of
// process-global service settings.
func (t *TwoFactorToken) RetryAfter(refreshInterval time.Duration) time.Time {
	return t.DispatchedAt.Add(refreshInterval)
}

type TwoFactorMethod uint8

const (
	TwoFactorMethodGoogle TwoFactorMethod = iota + 1
	TwoFactorMethodEmail
	TwoFactorMethodSMS
)

var twoFactorMethodToString = map[TwoFactorMethod]string{
	TwoFactorMethodGoogle: "google",
	TwoFactorMethodEmail:  "email",
	TwoFactorMethodSMS:    "sms",
}

var _twoFactorMethodByString = map[string]TwoFactorMethod{
	"google": TwoFactorMethodGoogle,
	"email":  TwoFactorMethodEmail,
	"sms":    TwoFactorMethodSMS,
}

// String returns the string representation of the method.
func (m TwoFactorMethod) String() string {
	if val, ok := twoFactorMethodToString[m]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation of the method.
func (m TwoFactorMethod) Uint8() uint8 {
	return uint8(m)
}

// NewTwoFactorMethodFromString converts a transport string to TwoFactorMethod.
func NewTwoFactorMethodFromString(value string) (TwoFactorMethod, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	method, ok := _twoFactorMethodByString[normalized]
	if ok {
		return method, nil
	}

	return 0, fmt.Errorf("[domain][NewTwoFactorMethodFromString][err: unsupported two-factor method %q]", value)
}

// IsSupportedTwoFactorMethod reports whether the two-factor method is supported.
func IsSupportedTwoFactorMethod(method TwoFactorMethod) bool {
	_, ok := twoFactorMethodToString[method]
	return ok
}

// SupportedTwoFactorMethodStrings returns transport strings for supported two-factor methods.
func SupportedTwoFactorMethodStrings() []string {
	return slices.Sorted(maps.Keys(_twoFactorMethodByString))
}

// TwoFactorSettings stores the user's current 2FA configuration.
type TwoFactorSettings struct {
	UserID    ID
	ContactID *ID
	Method    TwoFactorMethod
	Secret    string
	// LastTOTPCounter is the last time step accepted for this user. A code is
	// only good once, so the next one has to sit strictly above it.
	LastTOTPCounter int64
	CreatedAt       time.Time
}

type TwoFactorGetSettingsResult struct {
	Contact   *ContactMethod
	Method    TwoFactorMethod
	CreatedAt time.Time
}

type TwoFactorActivateParams struct {
	UserID ID
	Method TwoFactorMethod
}

type TwoFactorDeactivateParams struct {
	UserID ID
}

type TwoFactorChallengeResult struct {
	TokenUUID     string
	Secret        string
	ExpiresAt     time.Time
	Method        TwoFactorMethod
	ContactMethod *ContactMethod
}

type TwoFactorIssueChallengeParams struct {
	UserID ID
	Type   TwoFactorTokenType
}

type TwoFactorChallengeVerifyParams struct {
	UserID    *ID
	Type      TwoFactorTokenType
	TokenUUID string
	Code      string
}

type TwoFactorChallengeResendParams struct {
	UserID    ID
	Type      TwoFactorTokenType
	TokenUUID string
}

type TwoFactorAction uint8

const (
	TwoFactorActionActivate TwoFactorAction = iota + 1
	TwoFactorActionDeactivate
)

var twoFactorActionToString = map[TwoFactorAction]string{
	TwoFactorActionActivate:   "activate",
	TwoFactorActionDeactivate: "deactivate",
}

var _twoFactorActionByString = map[string]TwoFactorAction{
	"activate":   TwoFactorActionActivate,
	"deactivate": TwoFactorActionDeactivate,
}

// String returns the string representation of the action.
func (a TwoFactorAction) String() string {
	if value, ok := twoFactorActionToString[a]; ok {
		return value
	}

	return "unknown"
}

// NewTwoFactorActionFromString converts a transport string to TwoFactorAction.
func NewTwoFactorActionFromString(value string) (TwoFactorAction, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	action, ok := _twoFactorActionByString[normalized]
	if ok {
		return action, nil
	}

	return 0, fmt.Errorf("[domain][NewTwoFactorActionFromString][err: unsupported two-factor action %q]", value)
}

// IsSupportedTwoFactorAction reports whether the two-factor action is supported.
func IsSupportedTwoFactorAction(action TwoFactorAction) bool {
	_, ok := twoFactorActionToString[action]
	return ok
}

// SupportedTwoFactorActionStrings returns transport strings for supported two-factor actions.
func SupportedTwoFactorActionStrings() []string {
	return slices.Sorted(maps.Keys(_twoFactorActionByString))
}

type TwoFactorConfirmParams struct {
	UserID    ID
	Action    TwoFactorAction
	TokenUUID string
	Code      string
}

// TwoFactorTokenRepository describes the persistence operations available for tokens.
type TwoFactorTokenRepository interface {
	Create(context.Context, *TwoFactorToken) error
	FindLatestByContactForUpdate(context.Context, ID, TwoFactorTokenType) (TwoFactorToken, error)
	FindByUUIDAndTypeForUpdate(context.Context, string, TwoFactorTokenType) (TwoFactorToken, error)
	FindActiveByUserAndType(context.Context, ID, TwoFactorTokenType) (TwoFactorToken, error)
	HasActiveForContact(context.Context, ID, TwoFactorTokenType) (bool, error)
	InvalidateActiveByUserAndType(context.Context, ID, TwoFactorTokenType) error
	IncrementAttempts(context.Context, string) error
	Consume(context.Context, string, bool) error
	ClearDispatchedAt(context.Context, string) error
	Refresh(context.Context, *TwoFactorToken) error

	// DeleteExpiredBefore removes tokens that expired before the cutoff,
	// returning how many went. Expiry is the safe predicate rather than creation:
	// ResendChallenge pushes expires_at forward, so a token someone is still
	// using is never past it.
	DeleteExpiredBefore(context.Context, time.Time) (int64, error)

	WithTxFromContext(context.Context) TwoFactorTokenRepository
}

// TwoFactorSettingsRepository persists the user 2FA settings.
type TwoFactorSettingsRepository interface {
	FindByUserID(context.Context, ID) (TwoFactorSettings, error)
	Create(context.Context, *TwoFactorSettings) error
	Delete(context.Context, ID) error

	// AdvanceTOTPCounter moves the accepted step forward, reporting whether it
	// actually moved. False means the step was already used -- either a replay or
	// two requests racing with the same code, and only one of them may win.
	//
	// One conditional statement, so the losing side of that race is decided by
	// the database rather than by whichever request read first.
	AdvanceTOTPCounter(context.Context, ID, int64) (bool, error)

	WithTxFromContext(context.Context) TwoFactorSettingsRepository
}

// TwoFactorController exposes user-facing operations for managing 2FA enrollment settings.
type TwoFactorController interface {
	Activate(context.Context, TwoFactorActivateParams) (TwoFactorChallengeResult, error)
	Deactivate(context.Context, TwoFactorDeactivateParams) (TwoFactorChallengeResult, error)
	IssueChallenge(context.Context, TwoFactorIssueChallengeParams) (TwoFactorChallengeResult, error)
	VerifyChallenge(context.Context, TwoFactorChallengeVerifyParams) (TwoFactorToken, *appErrors.ErrorResponse)
	Confirm(context.Context, TwoFactorConfirmParams) error
	GetSettings(context.Context, ID) (TwoFactorGetSettingsResult, error)
	ResendChallenge(context.Context, TwoFactorChallengeResendParams) (TwoFactorChallengeResult, error)
}

// TwoFactorMethodFromContactType maps a contact type to the preferred two-factor delivery method.
func TwoFactorMethodFromContactType(contactType ContactType) TwoFactorMethod {
	switch contactType {
	case ContactTypePhone:
		return TwoFactorMethodSMS
	case ContactTypeEmail:
		fallthrough
	default:
		return TwoFactorMethodEmail
	}
}

// ContactTypeForTwoFactorMethod resolves the backing contact type required by the method.
func ContactTypeForTwoFactorMethod(method TwoFactorMethod) (ContactType, bool) {
	switch method {
	case TwoFactorMethodEmail:
		return ContactTypeEmail, true
	case TwoFactorMethodSMS:
		return ContactTypePhone, true
	default:
		return 0, false
	}
}
