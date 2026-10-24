package domain

import (
	"context"
	"time"
)

type UserCreatedEvent struct {
	UserID     ID        `json:"userId"`
	OccurredAt time.Time `json:"occurredAt"`
}

type UserVerifyLevelUpdatedEvent struct {
	UserID      ID        `json:"userId"`
	VerifyLevel uint8     `json:"verifyLevel"`
	OccurredAt  time.Time `json:"occurredAt"`
}

// UserEventController is responsible for publishing user-related events to the message queue.
type UserEventController interface {
	PublishEventUserCreated(context.Context, UserCreatedEvent) error
	PublishEventUserVerifyLevelUpdated(context.Context, UserVerifyLevelUpdatedEvent) error
}
