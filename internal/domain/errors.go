package domain

import "errors"

var (
	ErrRecordNotFound      = errors.New("record not found")
	ErrRecordExists        = errors.New("record already exists")
	ErrConcurrencyConflict = errors.New("concurrency conflict")

	// ErrTokenAlreadyConsumed is returned when a consume affects no rows because
	// the token was already consumed. It is a business outcome, not a DB failure:
	// the caller should report "code already used", never "database error".
	ErrTokenAlreadyConsumed = errors.New("two-factor token already consumed")
)
