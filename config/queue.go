package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

var queueSettings QueueSettings

type QueueSettings struct {
	Host              string        `envconfig:"QUEUE_HOST" required:"true"`
	Port              string        `envconfig:"QUEUE_PORT" required:"true"`
	User              string        `envconfig:"QUEUE_USER" required:"true"`
	Password          string        `envconfig:"QUEUE_PASSWORD" required:"true"`
	ReconnectInterval time.Duration `envconfig:"QUEUE_RECONNECT_INTERVAL" default:"30s"`

	OTPExchangeName       string `envconfig:"QUEUE_OTP_EXCHANGE_NAME" default:"account.otp"`
	OTPExchangeType       string `envconfig:"QUEUE_OTP_EXCHANGE_TYPE" default:"direct"`
	OTPExchangePersistent bool   `envconfig:"QUEUE_OTP_EXCHANGE_PERSISTENT" default:"true"`
	OTPExchangeMandatory  bool   `envconfig:"QUEUE_OTP_EXCHANGE_MANDATORY" default:"true"`
	OTPDefaultRoutingKey  string `envconfig:"QUEUE_OTP_ROUTING_KEY" default:"otp.dispatch"`

	PushExchangeName       string `envconfig:"QUEUE_PUSH_EXCHANGE_NAME" default:"account.push"`
	PushExchangeType       string `envconfig:"QUEUE_PUSH_EXCHANGE_TYPE" default:"direct"`
	PushExchangePersistent bool   `envconfig:"QUEUE_PUSH_EXCHANGE_PERSISTENT" default:"true"`
	PushExchangeMandatory  bool   `envconfig:"QUEUE_PUSH_EXCHANGE_MANDATORY" default:"true"`
	PushDefaultRoutingKey  string `envconfig:"QUEUE_PUSH_ROUTING_KEY" default:"push.dispatch"`

	UserLifecycleExchangeName       string `envconfig:"QUEUE_USER_LIFECYCLE_EXCHANGE_NAME" default:"user.lifecycle"`
	UserLifecycleExchangeType       string `envconfig:"QUEUE_USER_LIFECYCLE_EXCHANGE_TYPE" default:"topic"`
	UserLifecycleExchangePersistent bool   `envconfig:"QUEUE_USER_LIFECYCLE_EXCHANGE_PERSISTENT" default:"true"`
	UserLifecycleExchangeMandatory  bool   `envconfig:"QUEUE_USER_LIFECYCLE_EXCHANGE_MANDATORY" default:"true"`

	UserCreatedLifecycleRoutingKey   string `envconfig:"QUEUE_USER_CREATED_LIFECYCLE_ROUTING_KEY" default:"user.created"`
	UserVerifyLevelUpdatedRoutingKey string `envconfig:"QUEUE_USER_VERIFY_LEVEL_UPDATED_ROUTING_KEY" default:"user.verify_level.updated"`
}

// Queue returns the queue settings
func Queue() QueueSettings {
	return queueSettings
}

// loadQueueConfig loads the queue configuration from the environment variables
func loadQueueConfig() error {
	if err := envconfig.Process("", &queueSettings); err != nil {
		return fmt.Errorf("[loadQueueConfig][err: %w]", err)
	}
	return nil
}
