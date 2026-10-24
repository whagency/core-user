package domain

import (
	"context"
	"fmt"
	"time"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
)

const (
	UserStatusPendingContactVerification UserStatus = iota + 1
	UserStatusActive
	UserStatusBlockedUser
	UserStatusBlockedSystem
	UserStatusBlockedAdmin
	UserStatusDeleted
)

var userStatusToString = map[UserStatus]string{
	UserStatusPendingContactVerification: "pending_contact_verification",
	UserStatusActive:                     "active",
	UserStatusBlockedUser:                "blocked_user",
	UserStatusBlockedSystem:              "blocked_system",
	UserStatusBlockedAdmin:               "blocked_admin",
	UserStatusDeleted:                    "deleted",
}

type User struct {
	ID                ID
	Number            uint64
	Status            UserStatus
	PrimaryContactID  *ID
	VerificationLevel VerificationLevel
	CreatedAt         time.Time
	UpdatedAt         *time.Time
}

// NewUserForRegistration creates a new user aggregate for registration.
func NewUserForRegistration() *User {
	return &User{
		Status:            UserStatusPendingContactVerification,
		VerificationLevel: VerificationLevelNon,
	}
}

// SetPrimaryContact associates the user with a primary contact identifier.
func (u *User) SetPrimaryContact(contactID ID) {
	u.PrimaryContactID = &contactID
}

// ValidateStatus checks if the user status allows action.
func (u *User) ValidateStatus() *appErrors.ErrorResponse {
	switch u.Status {
	case UserStatusPendingContactVerification:
		return svcErrors.New(
			svcErrors.AccountPendingVerificationError,
			appErrors.WithCause(fmt.Errorf("[validateStatus][err: user pending verification]")),
		)
	case UserStatusBlockedUser, UserStatusBlockedSystem, UserStatusBlockedAdmin:
		return svcErrors.New(
			svcErrors.AccountBlockedError,
			appErrors.WithCause(fmt.Errorf("[validateStatus][err: user blocked]")),
		)
	case UserStatusDeleted:
		return svcErrors.New(
			svcErrors.AccountInvalidCredentialsError,
			appErrors.WithCause(fmt.Errorf("[validateStatus][err: user deleted]")),
		)
	default:
		return nil
	}
}

type UserStatus uint8

// NewUserStatus converts a stored uint8 to a UserStatus.
func NewUserStatus(status uint8) UserStatus {
	return UserStatus(status)
}

// String returns the string representation of the UserStatus.
func (s UserStatus) String() string {
	if val, ok := userStatusToString[s]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation of the UserStatus.
func (s UserStatus) Uint8() uint8 {
	return uint8(s)
}

// UserRegisterParams represents the intent of the user registration command.
type UserRegisterParams struct {
	Contact   ContactInput
	Password  string
	Recaptcha string
	SessionClientDeviceData
}

// ContactInput describes the primary contact provided during registration.
type ContactInput struct {
	Type  ContactType
	Value string
}

// ProfileInput describes the profile data provided during registration.
type ProfileInput struct {
	Country string
}

// UserRegistrationResult conveys the state of the registration command.
type UserRegistrationResult struct {
	ContactMethod ContactMethod
	TokenUUID     string
	ExpiresAt     time.Time

	// CodeDelivered reports whether the verification code actually reached the
	// delivery pipeline.
	//
	// Registration deliberately succeeds even when the send fails — the user and
	// their token are already committed, and returning an error would discard the
	// TokenUUID the client needs to resend, while the contact-already-used guard
	// blocks registering again. This flag is how the client learns to prompt for a
	// resend instead of leaving the user watching an empty inbox.
	CodeDelivered bool
}

// PasswordChangeParams represents the details required to rotate a user's password.
type PasswordChangeParams struct {
	UserID ID
	// SessionID is the session performing the change. Rotating the password
	// revokes every other session of the user, and this one is the exception:
	// the caller already proved knowledge of the current password, so logging
	// out the client that just succeeded buys nothing.
	SessionID       SessionID
	CurrentPassword string
	NewPassword     string
	SessionClientDeviceData
}

// ContactVerifyParams represents the input for the contact verification command.
type ContactVerifyParams struct {
	TokenUUID string
	Code      string
}

// UserProfile represents the user's profile information.
type UserProfile struct {
	UserID                      ID
	UserNumber                  uint64
	VerificationLevel           VerificationLevel
	Status                      UserStatus
	LastUserVerificationRequest *LastUserVerificationRequest
	PrimaryContact              PrimaryContact
	ProfileDetails              ProfileDetails
}

// LastUserVerificationRequest holds information about the last verification request made by the user.
type LastUserVerificationRequest struct {
	FormUrl   string
	Status    VerificationStatus
	CreatedAt time.Time
	UpdatedAt *time.Time
}

// PrimaryContact holds information about the primary contact of the user.
type PrimaryContact struct {
	Type   ContactType
	Value  string
	Status ContactStatus
}

// UserController provides user management operations such as registration, contact verification, and profile updates.
type UserController interface {
	Register(context.Context, UserRegisterParams) (UserRegistrationResult, error)
	VerifyContact(context.Context, ContactVerifyParams) error
	UpdateProfile(context.Context, UpdateProfileParams) error
	GetProfile(context.Context, ID) (UserProfile, error)
	GetByNumber(context.Context, int64) (User, error)
	ChangePassword(context.Context, PasswordChangeParams) error
	Block(context.Context, ID) error
}

// UserRepository defines the interface for managing user entities in the data layer.
type UserRepository interface {
	Create(context.Context, *User) error
	SetPrimaryContact(context.Context, ID, ID) error
	FindByID(context.Context, ID) (User, error)
	FindByNumber(context.Context, int64) (User, error)
	ActivateIfPendingByUserID(context.Context, ID) error
	UpdateStatus(context.Context, ID, UserStatus) error
	SetVerificationLevel(context.Context, ID, VerificationLevel) error

	WithTxFromContext(context.Context) UserRepository
}
