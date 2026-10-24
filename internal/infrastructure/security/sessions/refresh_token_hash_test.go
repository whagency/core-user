package sessions

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func newHashHelper(t *testing.T) *JWTSessionHelper {
	t.Helper()

	h, err := NewJWTSessionHelper([]byte("test-signing-key"), nil)
	if err != nil {
		t.Fatalf("NewJWTSessionHelper: %v", err)
	}

	return h
}

func TestHashRefreshTokenMatchesSHA256(t *testing.T) {
	t.Parallel()

	h := newHashHelper(t)

	const token = "some-opaque-refresh-token"
	want := sha256.Sum256([]byte(token))

	got := h.HashRefreshToken(token)
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("HashRefreshToken = %q, want the hex SHA-256 of the token", got)
	}
	if len(got) != 64 {
		t.Fatalf("expected 64 hex characters, got %d", len(got))
	}
	if got == token {
		t.Fatal("the hash must not be the token itself")
	}
}

func TestHashRefreshTokenIsDeterministicAndDistinct(t *testing.T) {
	t.Parallel()

	h := newHashHelper(t)

	// Deterministic, or a stored hash could never be matched again.
	first, second := h.HashRefreshToken("a"), h.HashRefreshToken("a")
	if first != second {
		t.Fatalf("the same token must always hash to the same value: %q vs %q", first, second)
	}

	// Distinct, or one session's token would open another's.
	if h.HashRefreshToken("a") == h.HashRefreshToken("b") {
		t.Fatal("different tokens must hash to different values")
	}
}

// The issuing and verifying paths both go through this one function; a token
// straight from Issue must hash to what a later lookup computes for it.
func TestHashRefreshTokenRoundTripsAnIssuedToken(t *testing.T) {
	t.Parallel()

	h := newHashHelper(t)

	issued, err := h.generateOpaque(_defaultTokenRefreshBytes)
	if err != nil {
		t.Fatalf("generateOpaque: %v", err)
	}

	stored, again := h.HashRefreshToken(issued), h.HashRefreshToken(issued)
	if stored != again {
		t.Fatalf("an issued token must hash consistently: %q vs %q", stored, again)
	}
	if stored == issued {
		t.Fatal("the stored value must differ from the issued token")
	}
}
