package domain

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

type ContactType uint8

const (
	ContactTypeEmail ContactType = iota + 1
	ContactTypePhone
)

var contactTypeToString = map[ContactType]string{
	ContactTypeEmail: "email",
	ContactTypePhone: "phone",
}

var _contactTypeByString = map[string]ContactType{
	"email": ContactTypeEmail,
	"phone": ContactTypePhone,
}

// NewContactType converts a stored uint8 to a ContactType.
func NewContactType(t uint8) ContactType {
	return ContactType(t)
}

// NewContactTypeFromString converts a transport string to ContactType.
func NewContactTypeFromString(value string) (ContactType, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	contactType, ok := _contactTypeByString[normalized]
	if ok {
		return contactType, nil
	}

	return 0, fmt.Errorf("[domain][NewContactTypeFromString][err: unsupported contact type %q]", value)
}

// IsSupportedContactType reports whether the contact type is supported.
func IsSupportedContactType(contactType ContactType) bool {
	_, ok := contactTypeToString[contactType]
	return ok
}

// SupportedContactTypeStrings returns transport strings for supported contact types.
func SupportedContactTypeStrings() []string {
	return slices.Sorted(maps.Keys(_contactTypeByString))
}

// String returns the string representation of the ContactType.
func (ct ContactType) String() string {
	if val, ok := contactTypeToString[ct]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation of the ContactType.
func (ct ContactType) Uint8() uint8 {
	return uint8(ct)
}

type ContactStatus uint8

const (
	ContactStatusUnverified ContactStatus = iota + 1
	ContactStatusVerified
)

var contactStatusToString = map[ContactStatus]string{
	ContactStatusUnverified: "unverified",
	ContactStatusVerified:   "verified",
}

// NewContactStatus converts a stored uint8 to a ContactStatus.
func NewContactStatus(cs uint8) ContactStatus {
	return ContactStatus(cs)
}

// String returns the string representation of the ContactStatus.
func (cs ContactStatus) String() string {
	if val, ok := contactStatusToString[cs]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation of the ContactStatus.
func (cs ContactStatus) Uint8() uint8 {
	return uint8(cs)
}

// NormalizeContactValue puts a contact value into the single form the database
// stores and matches on.
//
// Both existing types are case-insensitive in practice -- no mail provider
// treats the local part as case-sensitive, and an e164 number has no case at all
// -- while the column compares byte for byte. Without this, Alice@Example.com
// and alice@example.com are two accounts on one mailbox, and a user who
// capitalizes differently than they did at registration is told their account
// does not exist.
//
// Apply it wherever a value enters a use case, both for storage and for lookup;
// the two must agree or the lookup silently stops matching. The database carries
// a CHECK constraint for email as the backstop, because admin-service writes
// this column too.
func NormalizeContactValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// ContactMethod represents an email or phone contact.
type ContactMethod struct {
	ID         ID
	UserID     ID
	Type       ContactType
	Value      string
	Status     ContactStatus
	IsPrimary  bool
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  *time.Time
}

// IsVerified returns true if the contact method has been verified.
func (ce ContactMethod) IsVerified() bool {
	return ce.Status == ContactStatusVerified
}

// GetMaskedContactValue returns the masked version of the contact value.
func (ce ContactMethod) GetMaskedContactValue() string {
	switch ce.Type {
	case ContactTypeEmail:
		parts := strings.SplitN(ce.Value, "@", 2)
		if len(parts) != 2 {
			return "***"
		}
		local := []rune(parts[0])
		domainPart := parts[1]
		switch len(local) {
		case 0:
			return "***@" + domainPart
		case 1:
			return string(local[0]) + "***@" + domainPart
		case 2:
			return string(local[0]) + "*" + string(local[1]) + "@" + domainPart
		default:
			masked := string(local[0]) + strings.Repeat("*", len(local)-2) + string(local[len(local)-1])
			return masked + "@" + domainPart
		}
	case ContactTypePhone:
		digits := ce.Value
		if len(digits) <= 4 {
			return strings.Repeat("*", len(digits))
		}
		prefix := digits[:2]
		suffix := digits[len(digits)-2:]
		return prefix + strings.Repeat("*", len(digits)-4) + suffix
	default:
		return "***"
	}
}

// NewContactForUser creates a new ContactMethod aggregate for registration
func NewContactForUser(userID ID, in ContactInput) *ContactMethod {
	return &ContactMethod{
		UserID:    userID,
		Type:      in.Type,
		Value:     in.Value,
		Status:    ContactStatusUnverified,
		IsPrimary: true,
	}
}

// ContactRepository stores the contact methods attached to an account.
type ContactRepository interface {
	ExistsForTypeAndValue(context.Context, ContactType, string) (bool, error)
	Create(context.Context, *ContactMethod) error
	FindByID(context.Context, ID) (ContactMethod, error)
	FindByValue(context.Context, string) (ContactMethod, error)
	FindPrimaryByValue(context.Context, string) (ContactMethod, error)
	FindPrimaryByUser(context.Context, ID) (ContactMethod, error)
	FindPrimaryByUserAndType(context.Context, ID, ContactType) (ContactMethod, error)
	MarkVerified(context.Context, ID, time.Time) error

	WithTxFromContext(context.Context) ContactRepository
}
