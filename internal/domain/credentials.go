package domain

import (
	"context"
	"time"
)

// CredentialAlgorithm is the algorithm used to hash the password.
type CredentialAlgorithm string

// String returns the string representation of the CredentialAlgorithm.
func (c CredentialAlgorithm) String() string {
	return string(c)
}

const CredentialAlgorithmBcrypt CredentialAlgorithm = "bcrypt"

// Credential represents the authentication credentials for an account.
type Credential struct {
	UserID            ID
	PasswordHash      string
	Algorithm         CredentialAlgorithm
	PasswordUpdatedAt *time.Time
	MustRotate        bool
	// FailedLoginAttempts counts consecutive failures. Any successful sign-in or
	// password rotation puts it back to zero.
	FailedLoginAttempts uint16
	// LoginLockedUntil is a deadline, not a flag, so a lock releases itself and
	// needs no job to clear it. Nil means not locked.
	LoginLockedUntil *time.Time
}

// IsLoginLocked reports whether sign-in is currently refused for this account.
func (c Credential) IsLoginLocked(now time.Time) bool {
	return c.LoginLockedUntil != nil && now.Before(*c.LoginLockedUntil)
}

// NewCredential constructs a credential entity for persistence.
func NewCredential(userID ID, hash string, algorithm CredentialAlgorithm) Credential {
	return Credential{
		UserID:       userID,
		PasswordHash: hash,
		Algorithm:    algorithm,
	}
}

// LoginLockPolicy is how many consecutive failures are tolerated and for how
// long sign-in is refused once that is passed.
type LoginLockPolicy struct {
	MaxFailedAttempts uint16
	LockFor           time.Duration
}

// CredentialRepository stores the authentication credentials for an account.
type CredentialRepository interface {
	Create(context.Context, *Credential) error
	FindByUserID(context.Context, ID) (Credential, error)
	FindByUserIDForUpdate(context.Context, ID) (Credential, error)
	Update(context.Context, *Credential) error

	// RegisterFailedLogin increments the counter and, when the policy is passed,
	// stamps the lock deadline. It returns the resulting state.
	//
	// One statement, because two concurrent wrong guesses must both count. A
	// read-modify-write would let them read the same value and store the same
	// increment, and the attacker gets an extra attempt for every request they
	// manage to run in parallel.
	RegisterFailedLogin(context.Context, ID, LoginLockPolicy) (Credential, error)

	// ClearLoginFailures resets the counter and releases any lock. It is a no-op
	// when there is nothing to clear, so an ordinary sign-in does not write.
	ClearLoginFailures(context.Context, ID) error

	WithTxFromContext(context.Context) CredentialRepository
}
