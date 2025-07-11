// FILE: src/cmd/logwisp/main.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
)

var logger *log.Logger

func main() {
	// Parse flags first to get quiet mode early
	flagCfg, err := ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Initialize output handler with quiet mode
	InitOutputHandler(flagCfg.Quiet)

	// Handle version flag
	if flagCfg.ShowVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// Handle background mode
	if flagCfg.Background && !isBackgroundProcess() {
		if err := runInBackground(); err != nil {
			FatalError(1, "Failed to start background process: %v\n", err)
		}
		os.Exit(0)
	}

	// Set config file environment if specified
	if flagCfg.ConfigFile != "" {
		os.Setenv("LOGWISP_CONFIG_FILE", flagCfg.ConfigFile)
	}

	// Load configuration with CLI overrides
	cfg, err := config.LoadWithCLI(os.Args[1:], flagCfg)
	if err != nil {
		if flagCfg.ConfigFile != "" && strings.Contains(err.Error(), "not found") {
			FatalError(2, "Config file not found: %s\n", flagCfg.ConfigFile)
		}
		FatalError(1, "Failed to load config: %v\n", err)

	}

	// DEBUG: Extra nil check
	if cfg == nil {
		FatalError(1, "Configuration is nil after loading\n")
	}

	// Initialize logger with quiet mode awareness
	if err := initializeLogger(cfg, flagCfg); err != nil {
		FatalError(1, "Failed to initialize logger: %v\n", err)
	}
	defer shutdownLogger()

	// Log startup information (respects quiet mode via logger config)
	logger.Info("msg", "LogWisp starting",
		"version", version.String(),
		"config_file", flagCfg.ConfigFile,
		"log_output", cfg.Logging.Output,
		"router_mode", flagCfg.UseRouter)

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	// Bootstrap the service
	svc, router, err := bootstrapService(ctx, cfg, flagCfg)
	if err != nil {
		logger.Error("msg", "Failed to bootstrap service", "error", err)
		os.Exit(1)
	}

	// Start status reporter if enabled
	if enableStatusReporter() {
		go statusReporter(svc)
	}

	// Wait for shutdown signal
	sig := <-sigChan

	// Handle SIGKILL for immediate shutdown
	if sig == syscall.SIGKILL {
		os.Exit(137) // Standard exit code for SIGKILL (128 + 9)
	}

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
			Error("Logger shutdown error: %v\n", err)
		}
	}
}

func enableStatusReporter() bool {
	// Status reporter can be disabled via environment variable
	if os.Getenv("LOGWISP_DISABLE_STATUS_REPORTER") == "1" {
		return false
	}
	return true
}