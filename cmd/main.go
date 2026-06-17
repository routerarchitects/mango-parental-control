package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/routerarchitects/mango-parental-control/internal/app"
	"github.com/routerarchitects/mango-parental-control/internal/config"
	"github.com/routerarchitects/ra-common-mods/logger"
)

func main() {
	// 1. Intercept OS interrupt and termination signals
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// 2. Load configurations from environment variables
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("failed to parse environment configurations: %v", err))
	}

	// 3. Initialize structured slog logger
	rootLog, loggerShutdown, err := logger.Init(cfg.Logger.Config)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize structured logger: %v", err))
	}
	defer loggerShutdown()

	if rootLog == nil {
		panic("logger initialization returned nil logger")
	}
	rootLog.InfoContext(ctx, "structured logger successfully initialized")

	// 4. Construct the application wiring and dependencies
	application, err := app.New(ctx, cfg, rootLog)
	if err != nil {
		rootLog.ErrorContext(ctx, "application initialization failed", "error", err)
		panic(err)
	}

	// 5. Start the application
	serverErrCh, err := application.Start(ctx)
	if err != nil {
		rootLog.ErrorContext(ctx, "application startup failed", "error", err)
		panic(err)
	}

	// 6. Wait for OS signals or server failures
	select {
	case <-ctx.Done():
		rootLog.Info("OS shutdown signal intercepted, commencing graceful shutdown")
	case err := <-serverErrCh:
		if err != nil {
			rootLog.Error("HTTPS listener crashed unexpectedly", "error", err)
		} else {
			rootLog.Info("HTTPS listener exited normally")
		}
	}

	// 7. Graceful Shutdown sequence
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := application.Close(shutdownCtx); err != nil {
		rootLog.Error("forced shutdown occurred during cleanup", "error", err)
	}

	rootLog.Info("graceful service shutdown completed, exiting")
}
