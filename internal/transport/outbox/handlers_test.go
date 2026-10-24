package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"user-service/internal/domain"

	"github.com/whagency/core-common/outbox"
)

// eventCtrlStub records what the handlers republished.
type eventCtrlStub struct {
	created     domain.UserCreatedEvent
	verifyLevel domain.UserVerifyLevelUpdatedEvent
	calls       int
	err         error
}

func (s *eventCtrlStub) PublishEventUserCreated(_ context.Context, e domain.UserCreatedEvent) error {
	s.calls++
	s.created = e
	return s.err
}

func (s *eventCtrlStub) PublishEventUserVerifyLevelUpdated(
	_ context.Context,
	e domain.UserVerifyLevelUpdatedEvent,
) error {
	s.calls++
	s.verifyLevel = e
	return s.err
}

// TestHandlers_EventTypesMatchTheRowsControllersWrite pins the registry keys. A
// typo here silently routes nothing, and the rows pile up until the lag alert
// fires.
func TestHandlers_EventTypesMatchTheRowsControllersWrite(t *testing.T) {
	t.Parallel()

	if got := NewUserCreatedHandler(nil).EventType(); got != domain.OutboxEventUserCreated {
		t.Fatalf("expected %q, got %q", domain.OutboxEventUserCreated, got)
	}
	if got := NewUserVerifyLevelUpdatedHandler(nil).EventType(); got != domain.OutboxEventUserVerifyLevelUpdated {
		t.Fatalf("expected %q, got %q", domain.OutboxEventUserVerifyLevelUpdated, got)
	}
}

func TestUserCreatedHandler_Handle(t *testing.T) {
	t.Parallel()

	occurredAt := time.Date(2030, time.April, 2, 9, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(domain.UserCreatedPayload{UserID: 42, OccurredAt: occurredAt})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	eventCtrl := &eventCtrlStub{}
	if errHandle := NewUserCreatedHandler(eventCtrl).
		Handle(context.Background(), outbox.Message{Payload: payload}); errHandle != nil {
		t.Fatalf("Handle returned error: %v", errHandle)
	}

	if eventCtrl.created.UserID.Uint64() != 42 {
		t.Fatalf("expected user id 42, got %d", eventCtrl.created.UserID.Uint64())
	}
	if !eventCtrl.created.OccurredAt.Equal(occurredAt) {
		t.Fatalf("expected occurredAt %s, got %s", occurredAt, eventCtrl.created.OccurredAt)
	}
}

func TestUserVerifyLevelUpdatedHandler_Handle(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(domain.UserVerifyLevelUpdatedPayload{
		UserID:      42,
		VerifyLevel: 2,
		OccurredAt:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	eventCtrl := &eventCtrlStub{}
	if errHandle := NewUserVerifyLevelUpdatedHandler(eventCtrl).
		Handle(context.Background(), outbox.Message{Payload: payload}); errHandle != nil {
		t.Fatalf("Handle returned error: %v", errHandle)
	}

	if eventCtrl.verifyLevel.VerifyLevel != 2 {
		t.Fatalf("expected verify level 2, got %d", eventCtrl.verifyLevel.VerifyLevel)
	}
}

// TestHandlers_UndeliverablePayloadsAreNonRetryable checks the dead-letter path.
// A payload that cannot be acted on will never become actionable, so retrying
// only burns the budget before it dead-letters anyway.
func TestHandlers_UndeliverablePayloadsAreNonRetryable(t *testing.T) {
	t.Parallel()

	handlers := map[string]outbox.Handler{
		"user.created":              NewUserCreatedHandler(&eventCtrlStub{}),
		"user.verify_level.updated": NewUserVerifyLevelUpdatedHandler(&eventCtrlStub{}),
	}

	payloads := map[string][]byte{
		"malformed json":  []byte("{not json"),
		"missing user id": []byte(`{"userId":0}`),
	}

	for handlerName, handler := range handlers {
		for payloadName, payload := range payloads {
			t.Run(handlerName+"/"+payloadName, func(t *testing.T) {
				t.Parallel()

				err := handler.Handle(context.Background(), outbox.Message{Payload: payload})
				if err == nil {
					t.Fatal("expected an error")
				}
				if !errors.Is(err, outbox.ErrNonRetryable) {
					t.Fatalf("expected ErrNonRetryable, got %v", err)
				}
			})
		}
	}
}

// TestHandlers_TransportFailuresStayRetryable keeps a broker blip from
// dead-lettering an event that is still perfectly deliverable.
func TestHandlers_TransportFailuresStayRetryable(t *testing.T) {
	t.Parallel()

	payload, _ := json.Marshal(domain.UserCreatedPayload{UserID: 42})
	eventCtrl := &eventCtrlStub{err: errors.New("queue unavailable")}

	err := NewUserCreatedHandler(eventCtrl).
		Handle(context.Background(), outbox.Message{Payload: payload})
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, outbox.ErrNonRetryable) {
		t.Fatalf("expected a retryable error, got %v", err)
	}
}
