package domain

// PasswordHelper defines the capabilities required to hash and verify passwords.
type PasswordHelper interface {
	Hash(password string) (string, error)
	Verify(password, hashed string) (bool, error)
	Algorithm() CredentialAlgorithm
}

// PasswordPolicy validates a password according to the configured rules.
type PasswordPolicy interface {
	Validate(password string) error
}
