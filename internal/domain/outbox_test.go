package domain

import (
	"context"
	"testing"
	"time"

	outboxtestkit "github.com/whagency/core-common/outbox/testkit"
)

// dedupeKeys returns the dedupe key of every row the fake recorded, in order.
func dedupeKeys(repo *outboxtestkit.FakeRepository) []string {
	rows := repo.All()
	keys := make([]string, 0, len(rows))
	for i := range rows {
		keys = append(keys, rows[i].DedupeKey)
	}
	return keys
}

// TestNewUserVerifyLevelOutboxParams_KeyDistinguishesLevels pins the dedupe key.
//
// A user moves through verification levels over time and each step is its own
// event. Keying on the user alone would make the second promotion look like a
// duplicate of the first and drop it silently, leaving their limits one tier
// behind with nothing to show why.
func TestNewUserVerifyLevelOutboxParams_KeyDistinguishesLevels(t *testing.T) {
	t.Parallel()

	userID := NewIDFromUint64(42)
	now := time.Now().UTC()

	first := NewUserVerifyLevelUpdatedOutboxParams(userID, 1, now)
	second := NewUserVerifyLevelUpdatedOutboxParams(userID, 2, now)

	if first.DedupeKey != "verify-level:42:1" {
		t.Fatalf("unexpected dedupe key %q", first.DedupeKey)
	}
	if first.DedupeKey == second.DedupeKey {
		t.Fatal("two verification levels for one user must not share a dedupe key")
	}

	// The fake enforces the same uniqueness the table does, so this is the
	// behaviour that actually matters: both promotions survive.
	repo := outboxtestkit.NewFakeRepository()
	ctx := context.Background()
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("first Create failed: %v", err)
	}
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("second Create failed: %v", err)
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("replay of the first Create failed: %v", err)
	}

	if got := dedupeKeys(repo); len(got) != 2 {
		t.Fatalf("expected two rows and one suppressed replay, got %#v", got)
	}
}

// TestNewUserCreatedOutboxParams_ReplaySuppressed checks the other side: a user
// is created once, so a repeated enqueue for the same user is a duplicate.
func TestNewUserCreatedOutboxParams_ReplaySuppressed(t *testing.T) {
	t.Parallel()

	repo := outboxtestkit.NewFakeRepository()
	ctx := context.Background()
	params := NewUserCreatedOutboxParams(NewIDFromUint64(42), time.Now().UTC())

	if err := repo.Create(ctx, params); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := repo.Create(ctx, params); err != nil {
		t.Fatalf("replay Create failed: %v", err)
	}

	if got := dedupeKeys(repo); len(got) != 1 {
		t.Fatalf("expected the replay to be suppressed, got %#v", got)
	}
}
