// FILE: logwisp/src/cmd/logwisp/main.go
package main

import (
	"context"
	"fmt"
	"logwisp/src/cmd/logwisp/commands"
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/version"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lixenwraith/log"
)

// logger is the global logger instance for the application.
var logger *log.Logger

// main is the entry point for the LogWisp application.
func main() {
	// Handle subcommands before any config loading
	// This prevents flag conflicts with lixenwraith/config
	router := commands.NewCommandRouter()
	handled, err := router.Route(os.Args)

	if err != nil {
		// Command execution error
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if handled {
		// Command was successfully handled
		os.Exit(0)
	}

	// No subcommand, continue with main application

	// Emulates nohup
	signal.Ignore(syscall.SIGHUP)

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
		"background_mode", cfg.Background)

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Service and hot reload management
	var reloadManager *ReloadManager

	if cfg.ConfigAutoReload && cfg.ConfigFile != "" {
		// Use reload manager for dynamic configuration
		logger.Info("msg", "Config auto-reload enabled",
			"config_file", cfg.ConfigFile)

		reloadManager = NewReloadManager(cfg.ConfigFile, cfg, logger)

		if err := reloadManager.Start(ctx); err != nil {
			logger.Error("msg", "Failed to start reload manager", "error", err)
			os.Exit(1)
		}
		defer reloadManager.Shutdown()

		// Setup signal handler with reload support
		signalHandler := NewSignalHandler(reloadManager, logger)
		defer signalHandler.Stop()

		// Handle signals in background
		go func() {
			sig := signalHandler.Handle(ctx)
			if sig != nil {
				logger.Info("msg", "Shutdown signal received",
					"signal", sig)
				cancel() // Trigger shutdown
			}
		}()
	} else {
		// Traditional static bootstrap
		logger.Info("msg", "Config auto-reload disabled")

		svc, err := bootstrapService(ctx, cfg)
		if err != nil {
			logger.Error("msg", "Failed to bootstrap service", "error", err)
			os.Exit(1)
		}

		// Start status reporter if enabled (static mode)
		if !cfg.DisableStatusReporter {
			go statusReporter(svc, ctx)
		}

		// Setup traditional signal handling
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

		// Wait for shutdown signal
		sig := <-sigChan

		// Handle SIGKILL for immediate shutdown
		if sig == syscall.SIGKILL {
			os.Exit(137) // Standard exit code for SIGKILL (128 + 9)
		}

		logger.Info("msg", "Shutdown signal received, starting graceful shutdown...")

		// Shutdown service with timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), core.ShutdownTimeout)
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

		return // Exit from static mode
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown is handled by ReloadManager.Shutdown() in defer
	logger.Info("msg", "Shutdown complete")
}

// shutdownLogger gracefully shuts down the global logger.
func shutdownLogger() {
	if logger != nil {
		if err := logger.Shutdown(core.LoggerShutdownTimeout); err != nil {
			// Best effort - can't log the shutdown error
			Error("Logger shutdown error: %v\n", err)
		}
	}
}