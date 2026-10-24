package passwords

import (
	"errors"
	"fmt"

	"user-service/internal/domain"

	"golang.org/x/crypto/bcrypt"
)

type BcryptPasswordHelper struct {
	cost int
}

// NewBcryptPasswordHelper creates a new BcryptPasswordHelper with the given cost.
func NewBcryptPasswordHelper(opts ...func(*BcryptPasswordHelper)) *BcryptPasswordHelper {
	h := &BcryptPasswordHelper{cost: bcrypt.DefaultCost}
	for _, o := range opts {
		o(h)
	}
	return h
}

// WithCost sets the cost for bcrypt hashing.
func WithCost(c int) func(*BcryptPasswordHelper) { return func(h *BcryptPasswordHelper) { h.cost = c } }

// Hash hashes the given password using bcrypt.
func (h BcryptPasswordHelper) Hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("[security][BcryptPasswordHelper:Hash]%w", err)
	}
	return string(hashed), nil
}

// Verify compares a hashed password with its possible plaintext equivalent.
func (BcryptPasswordHelper) Verify(password, hashed string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return false, fmt.Errorf("[security][BcryptPasswordHelper:Verify]%w", err)
}

// Algorithm returns the algorithm type.
func (BcryptPasswordHelper) Algorithm() domain.CredentialAlgorithm {
	return domain.CredentialAlgorithmBcrypt
}
