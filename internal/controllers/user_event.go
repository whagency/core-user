package controllers

import (
	"context"
	"fmt"

	"user-service/config"
	"user-service/internal/domain"

	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/queue"
	commonUserQueue "github.com/whagency/core-common/services/user/queue"
)

type UserEventCtrl struct {
	userEventPublisher queue.Publisher
}

// NewUserEventController creates a new instance of UserEventController.
func NewUserEventController(userEventPublisher queue.Publisher) *UserEventCtrl {
	return &UserEventCtrl{userEventPublisher: userEventPublisher}
}

// PublishEventUserCreated publishes a domain.UserCreatedEvent to the message queue.
func (c *UserEventCtrl) PublishEventUserCreated(ctx context.Context, event domain.UserCreatedEvent) error {
	logger.LogCtx(ctx).Debugf("[UserEventCtrl:PublishUserEvent][event: %+v]", event)

	payload, err := jsoniter.Marshal(commonUserQueue.UserCreatedEvent{
		UserID:     event.UserID.Uint64(),
		OccurredAt: event.OccurredAt,
	})
	if err != nil {
		return fmt.Errorf("[UserEventCtrl:PublishUserCreated][err: %w]", err)
	}

	if err = c.userEventPublisher.Publish(ctx, queue.Message{
		MessageType: commonUserQueue.MessageTypeUserCreated,
		Data:        payload,
		RoutingKeys: []string{config.Queue().UserCreatedLifecycleRoutingKey},
	}); err != nil {
		return fmt.Errorf("[UserEventCtrl:PublishUserCreated]%w", err)
	}

	return nil
}

// PublishEventUserVerifyLevelUpdated publishes a domain.UserVerifyLevelUpdatedEvent to the message queue.
func (c *UserEventCtrl) PublishEventUserVerifyLevelUpdated(ctx context.Context, event domain.UserVerifyLevelUpdatedEvent) error {
	logger.LogCtx(ctx).Debugf("[UserEventCtrl:PublishEventUserVerifyLevelUpdated][event: %+v]", event)

	payload, err := jsoniter.Marshal(commonUserQueue.UserVerifyLevelUpdatedEvent{
		UserID:      event.UserID.Uint64(),
		VerifyLevel: event.VerifyLevel,
		OccurredAt:  event.OccurredAt,
	})
	if err != nil {
		return fmt.Errorf("[UserEventCtrl:PublishEventUserVerifyLevelUpdated][err: %w]", err)
	}

	if err = c.userEventPublisher.Publish(ctx, queue.Message{
		MessageType: commonUserQueue.MessageTypeUserVerifyLevelUpdated,
		Data:        payload,
		RoutingKeys: []string{config.Queue().UserVerifyLevelUpdatedRoutingKey},
	}); err != nil {
		return fmt.Errorf("[UserEventCtrl:PublishEventUserVerifyLevelUpdated]%w", err)
	}

	return nil
}
