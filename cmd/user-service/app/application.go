package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"user-service/internal/domain"
	"user-service/tools"

	"github.com/dgraph-io/ristretto"
	"github.com/hazelcast/hazelcast-go-client"
	"github.com/imroc/req/v3"
	"github.com/wagslane/go-rabbitmq"
	"github.com/whagency/core-common/cache"
	"github.com/whagency/core-common/cron"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/queue"
	"google.golang.org/grpc"
	"gorm.io/gorm"
)

type Application struct {
	httpServer       *http.Server
	httpClient       *req.Client
	grpcServer       *grpc.Server
	grpcListener     net.Listener
	db               *gorm.DB
	remoteCache      *hazelcast.Client
	globalLocalCache *ristretto.Cache
	queueConnections map[queue.ConnectionType]*rabbitmq.Conn

	remoteCacheManager   cache.RemoteCacheManager
	dbTransactionManager domain.TransactionManager
	queueManager         domain.QueueManager
	cronManager          *cron.Manager

	// Core
	core *Core
}

// NewApplication creates a new instance of Application.
func NewApplication() *Application {
	return &Application{
		queueConnections: make(map[queue.ConnectionType]*rabbitmq.Conn),
	}
}

// SetupDependencies initializes the dependencies for the application.
func (app *Application) SetupDependencies() error {
	if err := app.setupDB(); err != nil {
		return fmt.Errorf("[Application:SetupDependencies]%w", err)
	}

	if err := app.setupDBTransactionManager(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	if err := app.setupQueueConnections(); err != nil {
		return fmt.Errorf("[Application:SetupDependencies]%w", err)
	}

	if err := app.setupGlobalLocalCache(); err != nil {
		return fmt.Errorf("[Application:SetupDependencies]%w", err)
	}

	if err := app.setupRemoteCache(); err != nil {
		return fmt.Errorf("[Application:SetupDependencies]%w", err)
	}

	if err := app.setupRemoteCacheManager(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	if err := app.setupHTTPClient(); err != nil {
		return fmt.Errorf("[Application:SetupDependencies]%w", err)
	}

	return nil
}

// SetupStartupData initializes any necessary startup data for the application.
func (app *Application) SetupStartupData() error {
	tools.RegisterMetrics()

	if err := app.setupQueueManager(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	if err := app.buildCore(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	if err := app.setupHTTPServer(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	if err := app.setupGRPCServer(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	if err := app.setupCronManager(); err != nil {
		return fmt.Errorf("[Application:SetupStartupData]%w", err)
	}

	return nil
}

// CronManager returns the cron manager for the application.
func (app *Application) CronManager() *cron.Manager {
	return app.cronManager
}

// RemoteCacheManager returns the remote cache manager for the application.
func (app *Application) RemoteCacheManager() cache.RemoteCacheManager {
	return app.remoteCacheManager
}

// HTTPServer returns the HTTP server for the application.
func (app *Application) HTTPServer() *http.Server {
	return app.httpServer
}

// GRPCServer returns the gRPC server for the application.
func (app *Application) GRPCServer() *grpc.Server {
	return app.grpcServer
}

// GRPCListener returns the gRPC listener for the application.
func (app *Application) GRPCListener() net.Listener {
	return app.grpcListener
}

// DB returns the database connection for the application.
func (app *Application) DB() *gorm.DB {
	return app.db
}

// DBTransactionManager returns the db transaction manager for the application.
func (app *Application) DBTransactionManager() domain.TransactionManager {
	return app.dbTransactionManager
}

// RemoteCache returns the remote cache client for the application.
func (app *Application) RemoteCache() *hazelcast.Client {
	return app.remoteCache
}

// GlobalLocalCache returns the global local cache for the application.
func (app *Application) GlobalLocalCache() *ristretto.Cache {
	return app.globalLocalCache
}

// Core returns the core components of the application.
func (app *Application) Core() *Core {
	return app.core
}

// QueueManager returns the queue manager for the application.
func (app *Application) QueueManager() domain.QueueManager {
	return app.queueManager
}

// Close releases the infrastructure SetupDependencies acquired: the queue, the
// database pool, the remote cache client and the local cache.
//
// None of it used to be released at all. The practical cost is smaller than it
// sounds and worth stating honestly: on a clean exit the OS closes the sockets
// and Hazelcast reaps the endpoint on its own -- verified against a real cluster,
// which destroyed the client endpoint either way. What the explicit close buys
// is determinism where that does not hold: a SIGKILL, a container kill or a
// network partition otherwise leaves the server waiting out a heartbeat timeout,
// and the client's own goroutines die mid-operation rather than stopping.
//
// The ordering is the part that carries real weight. Call this after the
// background loops have finished, never alongside them: closing the queue while
// the outbox pool is still draining takes the publisher out from under an
// in-flight delivery.
//
// Every step runs even if an earlier one failed: a resource that cannot be
// released is not a reason to leave the others held. The first error is
// returned for the exit code.
func (app *Application) Close(timeout time.Duration) error {
	// The caller's context is already canceled by the time shutdown runs, so the
	// bound has to be a fresh one. Taking a duration rather than a context keeps
	// that decision here instead of repeating it at every call site.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var firstErr error

	record := func(step string, err error) {
		if err == nil {
			return
		}
		logger.Log().Errorf("[Application:Close][step:%s]%s", step, err)
		if firstErr == nil {
			firstErr = fmt.Errorf("[Application:Close][step:%s]%w", step, err)
		}
	}

	if app.queueManager != nil {
		record("queue publishers", app.queueManager.ClosePublishers())
	}
	app.CloseQueueConnections()

	if app.db != nil {
		sqlDB, err := app.db.DB()
		if err != nil {
			record("database handle", err)
		} else {
			record("database pool", sqlDB.Close())
		}
	}

	if app.remoteCache != nil {
		record("remote cache", app.remoteCache.Shutdown(ctx))
	}

	if app.globalLocalCache != nil {
		app.globalLocalCache.Close()
	}

	logger.Log().Info("[Application:Close][msg: infrastructure released]")

	return firstErr
}
