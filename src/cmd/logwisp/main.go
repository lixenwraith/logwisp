// FILE: logwisp/src/cmd/logwisp/main.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	// Emulates nohup
	signal.Ignore(syscall.SIGHUP)

	// Early check for help flag to avoid unnecessary config loading
	CheckAndDisplayHelp(os.Args[1:])

	// Load configuration with automatic CLI parsing
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		if strings.Contains(err.Error(), "not found") && cfg != nil && cfg.ConfigFile != "" {
			fmt.Fprintf(os.Stderr, "Error: Config file not found: %s\n", cfg.ConfigFile)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize output handler
	InitOutputHandler(cfg.Quiet)

	// Handle version
	if cfg.ShowVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// Background mode spawns a child with internal --background-daemon flag.
	if cfg.Background && !cfg.BackgroundDaemon {
		// Prepare arguments for the child process, including originals and daemon flag.
		args := append(os.Args[1:], "--background-daemon")

		cmd := exec.Command(os.Args[0], args...)

		if err := cmd.Start(); err != nil {
			FatalError(1, "Failed to start background process: %v\n", err)
		}

		Print("Started LogWisp in background (PID: %d)\n", cmd.Process.Pid)
		os.Exit(0) // The parent process exits successfully.
	}

	// Initialize logger instance and apply configuration
	if err := initializeLogger(cfg); err != nil {
		FatalError(1, "Failed to initialize logger: %v\n", err)
	}
	defer shutdownLogger()

	// Start the logger
	if err := logger.Start(); err != nil {
		FatalError(1, "Failed to start logger: %v\n", err)
	}

	// Log startup information
	logger.Info("msg", "LogWisp starting",
		"version", version.String(),
		"config_file", cfg.ConfigFile,
		"log_output", cfg.Logging.Output,
		"router_mode", cfg.UseRouter,
		"background_mode", cfg.Background)

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	// Bootstrap the service
	svc, router, err := bootstrapService(ctx, cfg)
	if err != nil {
		logger.Error("msg", "Failed to bootstrap service", "error", err)
		os.Exit(1)
	}

	// Start status reporter if enabled
	if !cfg.DisableStatusReporter {
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