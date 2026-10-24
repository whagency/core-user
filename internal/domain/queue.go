package domain

import "github.com/whagency/core-common/queue"

const (
	OTPQueuePublisherType queue.PublisherType = iota + 1
	PushQueuePublisherType
	UserLifecycleQueuePublisherType
)

const DefaultQueueConnectionType queue.ConnectionType = iota + 1

// QueueManager defines the interface for managing queue consumers and publishers
type QueueManager interface {
	AddConsumer(queue.Consumer) error
	AddPublisher(queue.Publisher) error
	GetPublisher(queue.PublisherType) (queue.Publisher, error)
	RunConsumers() error
	CloseConsumers() error
	ClosePublishers() error
}
