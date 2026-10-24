package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	application "user-service/cmd/user-service/app"
	"user-service/config"

	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/tracer"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const _shutdownTimeout = 10 * time.Second

func main() {
	if err := runMain(); err != nil {
		log.Printf("[main]%s", err)
		os.Exit(1)
	}
}

func runMain() error {
	app := application.NewApplication()

	if err := config.Init(); err != nil {
		return err
	}

	if err := logger.Init(config.LoggerConfig()); err != nil {
		return err
	}
	defer logger.Sync()

	if err := tracer.Init(config.TracerConfig()); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, app); err != nil {
		return err
	}

	return nil
}

// run sets up dependencies, starts servers, and handles graceful shutdown.
func run(ctx context.Context, app *application.Application) error {
	// Registered before setup starts, so a failure partway through still gives
	// back whatever had already been acquired. Close tolerates a half-built
	// Application for exactly that reason.
	defer func() {
		if err := app.Close(_shutdownTimeout); err != nil {
			logger.Log().Errorf("[main][err: releasing infrastructure failed: %s]", err)
		}
	}()

	logger.Log().Info("[main][msg: setting up dependencies]")
	if err := app.SetupDependencies(); err != nil {
		return err
	}

	logger.Log().Info("[main][msg: setting up startup data]")
	if err := app.SetupStartupData(); err != nil {
		return err
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		logger.Log().Info("[main][msg: starting cron jobs]")
		app.CronManager().Start()

		<-gctx.Done()

		logger.Log().Info("[main][msg: stopping cron jobs]")
		cronCtx := app.CronManager().Stop()
		<-cronCtx.Done()
		return nil
	})

	// Outbox relay + worker pool. Bound to gctx so SIGTERM stops the relay and
	// lets in-flight handlers finish; anything still queued falls back to lease
	// expiry and is reclaimed by another instance.
	g.Go(func() error {
		logger.Log().Info("[main][msg: starting outbox pool]")
		return app.Core().OutboxPool.Run(gctx)
	})

	// HTTP server
	g.Go(func() error {
		logger.Log().Infof("[main][msg: http server is starting on port %s]", config.HTTP().Port)

		err := app.HTTPServer().ListenAndServe()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})

	// gRPC server
	g.Go(func() error {
		logger.Log().Infof("[main][msg: grpc server is starting on port %s]", config.GRPC().Port)

		err := app.GRPCServer().Serve(app.GRPCListener())
		if err == nil || errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	})

	select {
	case <-ctx.Done():
		logger.Log().Info("[main][msg: shutdown requested]")
	case <-gctx.Done():
		logger.Log().Info("[main][msg: background task stopped]")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), _shutdownTimeout)
	defer cancel()

	// Two phases, in this order.
	//
	// Stopping the servers first is what lets the background loops finish: they
	// are bound to gctx and drain on their own, but the HTTP and gRPC goroutines
	// only return once their servers are down.
	stopServing(app, shutdownCtx)

	waitErr := g.Wait()

	// The queue, the database and the caches go in the deferred Close above --
	// only now is nothing using them. Releasing before g.Wait would take the
	// publisher out from under an outbox delivery still in flight.
	if err := tracer.Shutdown(shutdownCtx); err != nil {
		logger.Log().Errorf("[main][err: tracer shutdown failed: %s]", err)
	}

	if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
		return waitErr
	}
	return nil
}

// stopServing stops accepting new work: the HTTP and gRPC servers, and the
// outgoing gRPC clients they used.
//
// It deliberately releases nothing else. The queue, the database and the caches
// are still in use by the background loops until g.Wait returns, and are closed
// there -- see Application.Close.
func stopServing(app *application.Application, ctx context.Context) {
	// HTTP
	if err := app.HTTPServer().Shutdown(ctx); err != nil {
		logger.Log().Errorf("[main][err: http shutdown failed: %s]", err)
	} else {
		logger.Log().Info("[main][msg: http server shutdown gracefully]")
	}

	done := make(chan struct{})
	go func() {
		app.GRPCServer().GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		logger.Log().Info("[main][msg: grpc server shutdown gracefully]")
	case <-ctx.Done():
		logger.Log().Error("[main][msg: grpc graceful stop timeout, forcing stop]")
		app.GRPCServer().Stop()
	}

	if err := app.GRPCListener().Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Log().Errorf("[main][err: grpc listener close failed: %s]", err)
	}

	if err := app.Core().CloseGRPC(); err != nil {
		logger.Log().Errorf("[main][err: grpc clients close failed: %s]", err)
	} else {
		logger.Log().Info("[main][msg: grpc clients closed gracefully]")
	}
}
