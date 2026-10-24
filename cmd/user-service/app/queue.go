package app

import (
	"fmt"

	"user-service/config"
	"user-service/internal/domain"

	wagsrmq "github.com/wagslane/go-rabbitmq"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/queue"
	"github.com/whagency/core-common/queue/rabbitmq"
)

// CloseQueueConnections closes the queue connections.
func (app *Application) CloseQueueConnections() {
	logger.Log().Info("[Application:CloseQueueConnections][msg: closing queue connections]")

	for _, conn := range app.queueConnections {
		if err := conn.Close(); err != nil {
			logger.Log().Errorf("[Application:CloseQueueConnections]%s", err)
		}
	}
}

// setupQueueConnections sets up the queue connections.
func (app *Application) setupQueueConnections() error {
	// Add the default queue connection
	if err := app.addNewQueueConnection(domain.DefaultQueueConnectionType, queue.ConnectionConfig{
		Host:     config.Queue().Host,
		Port:     config.Queue().Port,
		User:     config.Queue().User,
		Password: config.Queue().Password,
	}); err != nil {
		return fmt.Errorf("[app:setupQueue]%w", err)
	}

	return nil
}

// addNewQueueConnection adds a new queue connection to the application.
func (app *Application) addNewQueueConnection(queueType queue.ConnectionType, queueConnectionConfig queue.ConnectionConfig) error {
	logger.Log().Infof("[Application:addNewQueueConnection][queueType: %d][amqp://%s:hidden@%s:%s/%s]", queueType, queueConnectionConfig.User, queueConnectionConfig.Host, queueConnectionConfig.Port, queueConnectionConfig.VHost)

	conn, err := wagsrmq.NewConn(
		fmt.Sprintf("amqp://%s:%s@%s:%s/%s", queueConnectionConfig.User, queueConnectionConfig.Password, queueConnectionConfig.Host, queueConnectionConfig.Port, queueConnectionConfig.VHost),
		wagsrmq.WithConnectionOptionsLogging,
		wagsrmq.WithConnectionOptionsLogger(rabbitmq.QueueLogger{}),
		wagsrmq.WithConnectionOptionsReconnectInterval(config.Queue().ReconnectInterval),
	)
	if err != nil {
		return fmt.Errorf("[addNewQueueConnection][err: %w]", err)
	}

	app.queueConnections[queueType] = conn

	return nil
}

// setupQueueManager sets up the queue manager for the application.
func (app *Application) setupQueueManager() error {
	// Define queue manager
	queueManager := queue.NewManager()

	// Define publishers
	otpPublisher, err := rabbitmq.NewPublisher(
		app.queueConnections[domain.DefaultQueueConnectionType],
		rabbitmq.PublisherConfig{
			PublisherType:      domain.OTPQueuePublisherType,
			ExchangeName:       config.Queue().OTPExchangeName,
			ExchangeType:       config.Queue().OTPExchangeType,
			Mandatory:          config.Queue().OTPExchangeMandatory,
			Persistent:         config.Queue().OTPExchangePersistent,
			DefaultRoutingKeys: []string{config.Queue().OTPDefaultRoutingKey},
		})
	if err != nil {
		return fmt.Errorf("[setupQueueManager]%w", err)
	}

	pushPublisher, err := rabbitmq.NewPublisher(
		app.queueConnections[domain.DefaultQueueConnectionType],
		rabbitmq.PublisherConfig{
			PublisherType:      domain.PushQueuePublisherType,
			ExchangeName:       config.Queue().PushExchangeName,
			ExchangeType:       config.Queue().PushExchangeType,
			Mandatory:          config.Queue().PushExchangeMandatory,
			Persistent:         config.Queue().PushExchangePersistent,
			DefaultRoutingKeys: []string{config.Queue().PushDefaultRoutingKey},
		})
	if err != nil {
		return fmt.Errorf("[setupQueueManager]%w", err)
	}

	userEventPublisher, err := rabbitmq.NewPublisher(
		app.queueConnections[domain.DefaultQueueConnectionType],
		rabbitmq.PublisherConfig{
			PublisherType: domain.UserLifecycleQueuePublisherType,
			ExchangeName:  config.Queue().UserLifecycleExchangeName,
			ExchangeType:  config.Queue().UserLifecycleExchangeType,
			Mandatory:     config.Queue().UserLifecycleExchangeMandatory,
			Persistent:    config.Queue().UserLifecycleExchangePersistent,
		})
	if err != nil {
		return fmt.Errorf("[setupQueueManager]%w", err)
	}

	// Add publishers to the manager
	if err = queueManager.AddPublisher(otpPublisher); err != nil {
		return fmt.Errorf("[setupQueueManager]%w", err)
	}

	if err = queueManager.AddPublisher(pushPublisher); err != nil {
		return fmt.Errorf("[setupQueueManager]%w", err)
	}

	if err = queueManager.AddPublisher(userEventPublisher); err != nil {
		return fmt.Errorf("[setupQueueManager]%w", err)
	}

	app.queueManager = queueManager

	return nil
}
