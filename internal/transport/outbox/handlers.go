// Package outbox contains the transport adapters that deliver user-service
// outbox messages to their destinations.
//
// These are transport, not use-case logic: each handler deserialises a payload
// and delegates. The business decision about what to emit lives in the
// controllers that write the outbox rows.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"user-service/internal/domain"

	"github.com/whagency/core-common/outbox"
)

// UserCreatedHandler delivers "user.created" messages by republishing them to the
// user lifecycle queue.
type UserCreatedHandler struct {
	eventCtrl domain.UserEventController
}

// NewUserCreatedHandler creates a UserCreatedHandler.
func NewUserCreatedHandler(eventCtrl domain.UserEventController) *UserCreatedHandler {
	return &UserCreatedHandler{eventCtrl: eventCtrl}
}

// EventType returns the event_type string this handler processes.
func (h *UserCreatedHandler) EventType() string {
	return domain.OutboxEventUserCreated
}

// Handle republishes the event. Payload unmarshal errors are non-retryable;
// publish errors are retryable.
func (h *UserCreatedHandler) Handle(ctx context.Context, msg outbox.Message) error {
	var p domain.UserCreatedPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return outbox.MarkNonRetryable(fmt.Errorf("[UserCreatedHandler:Handle][err: %w]", err))
	}
	if p.UserID == 0 {
		return outbox.MarkNonRetryable(fmt.Errorf("[UserCreatedHandler:Handle][err: user id is required]"))
	}

	return h.eventCtrl.PublishEventUserCreated(ctx, domain.UserCreatedEvent{
		UserID:     domain.NewIDFromUint64(p.UserID),
		OccurredAt: p.OccurredAt,
	})
}

// UserVerifyLevelUpdatedHandler delivers "user.verify_level.updated" messages.
type UserVerifyLevelUpdatedHandler struct {
	eventCtrl domain.UserEventController
}

// NewUserVerifyLevelUpdatedHandler creates a UserVerifyLevelUpdatedHandler.
func NewUserVerifyLevelUpdatedHandler(eventCtrl domain.UserEventController) *UserVerifyLevelUpdatedHandler {
	return &UserVerifyLevelUpdatedHandler{eventCtrl: eventCtrl}
}

// EventType returns the event_type string this handler processes.
func (h *UserVerifyLevelUpdatedHandler) EventType() string {
	return domain.OutboxEventUserVerifyLevelUpdated
}

// Handle republishes the event. Payload unmarshal errors are non-retryable;
// publish errors are retryable.
func (h *UserVerifyLevelUpdatedHandler) Handle(ctx context.Context, msg outbox.Message) error {
	var p domain.UserVerifyLevelUpdatedPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return outbox.MarkNonRetryable(fmt.Errorf("[UserVerifyLevelUpdatedHandler:Handle][err: %w]", err))
	}
	if p.UserID == 0 {
		return outbox.MarkNonRetryable(fmt.Errorf("[UserVerifyLevelUpdatedHandler:Handle][err: user id is required]"))
	}

	return h.eventCtrl.PublishEventUserVerifyLevelUpdated(ctx, domain.UserVerifyLevelUpdatedEvent{
		UserID:      domain.NewIDFromUint64(p.UserID),
		VerifyLevel: p.VerifyLevel,
		OccurredAt:  p.OccurredAt,
	})
}
