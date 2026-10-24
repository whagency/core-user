package domain

import (
	"fmt"
	"time"

	"github.com/whagency/core-common/outbox"
)

// OutboxRepository is the user-service binding for the shared outbox.Repository.
// Create joins the ambient business transaction from ctx, so the outbox row and
// the state change it describes commit together or not at all.
type OutboxRepository interface {
	outbox.Repository
}

// Outbox event_type constants for user-service.
const (
	OutboxEventUserCreated            = "user.created"
	OutboxEventUserVerifyLevelUpdated = "user.verify_level.updated"
)

// OutboxAggregateUser is the aggregate_type for user lifecycle rows.
const OutboxAggregateUser = "user"

// UserCreatedPayload is the JSON payload stored in outbox_messages for
// event_type = "user.created".
//
// The worker republishes it to the user lifecycle queue, where restriction-service
// assigns the default tier. Delivery is at-least-once, which is safe because that
// consumer is an upsert (CreateOrUpdateUserTier).
type UserCreatedPayload struct {
	UserID     uint64    `json:"userId"`
	OccurredAt time.Time `json:"occurredAt"`
}

// UserVerifyLevelUpdatedPayload is the JSON payload stored in outbox_messages for
// event_type = "user.verify_level.updated".
//
// Losing this event used to mean a user passed KYC while their limits stayed at
// the unverified tier, with only a log line to show for it.
type UserVerifyLevelUpdatedPayload struct {
	UserID      uint64    `json:"userId"`
	VerifyLevel uint8     `json:"verifyLevel"`
	OccurredAt  time.Time `json:"occurredAt"`
}

// NewUserCreatedOutboxParams builds the outbox row for a user lifecycle creation
// event.
//
// A user is created once, so the id alone is a stable key.
func NewUserCreatedOutboxParams(userID ID, occurredAt time.Time) outbox.CreateParams {
	return outbox.CreateParams{
		AggregateType: OutboxAggregateUser,
		AggregateID:   fmt.Sprintf("%d", userID.Uint64()),
		EventType:     OutboxEventUserCreated,
		DedupeKey:     fmt.Sprintf("user-created:%d", userID.Uint64()),
		Payload: UserCreatedPayload{
			UserID:     userID.Uint64(),
			OccurredAt: occurredAt,
		},
	}
}

// NewUserVerifyLevelUpdatedOutboxParams builds the outbox row for a verification
// level change.
//
// The level belongs in the dedupe key. A user moves 1 -> 2 -> 3 over time and each
// step is a distinct event; keying on the user alone would make the second
// promotion look like a duplicate of the first and drop it silently, leaving the
// user's limits one tier behind forever.
func NewUserVerifyLevelUpdatedOutboxParams(
	userID ID,
	verifyLevel uint8,
	occurredAt time.Time,
) outbox.CreateParams {
	return outbox.CreateParams{
		AggregateType: OutboxAggregateUser,
		AggregateID:   fmt.Sprintf("%d", userID.Uint64()),
		EventType:     OutboxEventUserVerifyLevelUpdated,
		DedupeKey:     fmt.Sprintf("verify-level:%d:%d", userID.Uint64(), verifyLevel),
		Payload: UserVerifyLevelUpdatedPayload{
			UserID:      userID.Uint64(),
			VerifyLevel: verifyLevel,
			OccurredAt:  occurredAt,
		},
	}
}
