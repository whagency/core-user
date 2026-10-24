package user

import (
	"testing"

	"user-service/internal/transport/grpc/pb/userv1"
)

// The cross-service contract may waive expiry and nothing else.
//
// is_expired_validation_skip used to be passed straight through to a helper that
// read it as "skip expiry and revocation", so any consumer of this RPC could
// validate a session that had been signed out, revoked by a password change, or
// blocked by an admin. Mapping it to AllowExpired alone is what closes that; the
// test is here so the mapping cannot quietly widen again.
func TestDecodeValidateSessionRequest_NeverWaivesRevocation(t *testing.T) {
	t.Parallel()

	for _, skip := range []bool{false, true} {
		got, err := decodeValidateSessionRequest(&userv1.ValidateSessionRequest{
			Token:                   "a.b.c",
			IsExpiredValidationSkip: skip,
		})
		if err != nil {
			t.Fatalf("decode with skip=%t: %v", skip, err)
		}
		if got.AllowExpired != skip {
			t.Fatalf("skip=%t: AllowExpired = %t, want %t", skip, got.AllowExpired, skip)
		}
		if got.AllowRevoked {
			t.Fatalf("skip=%t: AllowRevoked must never be set from the wire", skip)
		}
	}
}
