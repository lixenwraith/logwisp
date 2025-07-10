// FILE: src/cmd/logwisp/main.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
)

var logger *log.Logger

func main() {
	// Parse and validate flags
	if err := parseFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Handle version flag
	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// Handle background mode
	if *background && !isBackgroundProcess() {
		if err := runInBackground(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start background process: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Set config file environment if specified
	if *configFile != "" {
		os.Setenv("LOGWISP_CONFIG_FILE", *configFile)
	}

	// Load configuration
	cfg, err := config.LoadWithCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := initializeLogger(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer shutdownLogger()

	// Log startup information
	logger.Info("msg", "LogWisp starting",
		"version", version.String(),
		"config_file", *configFile,
		"log_output", cfg.Logging.Output,
		"router_mode", *useRouter)

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Bootstrap the service
	svc, router, err := bootstrapService(ctx, cfg)
	if err != nil {
		logger.Error("msg", "Failed to bootstrap service", "error", err)
		os.Exit(1)
	}

	// Start status reporter if enabled
	if shouldEnableStatusReporter() {
		go statusReporter(svc)
	}

	// Wait for shutdown signal
	<-sigChan
	logger.Info("msg", "Shutdown signal received, starting graceful shutdown...")

	// Shutdown router first if using it
	if router != nil {
		logger.Info("msg", "Shutting down HTTP router...")
		router.Shutdown()
	}

	// Shutdown service with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		svc.Shutdown()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("msg", "Shutdown complete")
	case <-shutdownCtx.Done():
		logger.Error("msg", "Shutdown timeout exceeded - forcing exit")
		os.Exit(1)
	}
}

func shutdownLogger() {
	if logger != nil {
		if err := logger.Shutdown(2 * time.Second); err != nil {
			// Best effort - can't log the shutdown error
			fmt.Fprintf(os.Stderr, "Logger shutdown error: %v\n", err)
		}
	}
}

func shouldEnableStatusReporter() bool {
	// Status reporter can be disabled via environment variable
	if os.Getenv("LOGWISP_DISABLE_STATUS_REPORTER") == "1" {
		return false
	}
	return true
}