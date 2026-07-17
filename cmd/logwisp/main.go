package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/version"

	"github.com/lixenwraith/log"
)

// logger is the global logger instance for the application
var logger *log.Logger

// main is the entry point for the LogWisp application
func main() {
	// --- 1. Initial setup ---
	// Emulates nohup
	signal.Ignore(syscall.SIGHUP)

	// Help handled before config parsing; loader has no help flag.
	// Also the future dispatch point for subcommands (tls, etc.)
	handleHelp(os.Args[1:])

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
		"status_reporter", cfg.StatusReporter,
		"auto_reload", cfg.ConfigAutoReload)

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- 2. Bootstrap initial service ---
	svc, statusReporterCancel, err := bootstrapInitial(ctx, cfg)
	if err != nil {
		logger.Error("msg", "Failed to initialize service", "error", err)
		os.Exit(1)
	}

	// --- 3. Setup signals and shutdown ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	var configChanges <-chan string
	lcfg := config.GetConfigManager()
	if cfg.ConfigAutoReload && lcfg != nil {
		configChanges = lcfg.Watch()
		logger.Info("msg", "Config auto-reload enabled", "config_file", cfg.ConfigFile)
	} else {
		logger.Info("msg", "Config auto-reload disabled")
	}

	// Service shutdown sequence
	defer func() {
		logger.Info("msg", "Shutdown initiated")
		if statusReporterCancel != nil {
			statusReporterCancel()
		}
		if svc != nil {
			svc.Shutdown()
		}
		if lcfg != nil {
			lcfg.StopAutoUpdate()
		}
		logger.Info("msg", "Shutdown complete")
		// Deferred logger shutdown will run after this
	}()

	// --- 4. Main Application Event Loop ---
	logger.Info("msg", "Application started, waiting for signals or config changes")
	for {
		select {
		case sig := <-sigChan:
			if sig == syscall.SIGHUP || sig == syscall.SIGUSR1 {
				logger.Info("msg", "Reload signal received, triggering manual reload", "signal", sig)
				newSvc, newCfg, newStatusCancel, err := handleReload(ctx, svc, statusReporterCancel)
				if err == nil {
					svc = newSvc
					cfg = newCfg
					statusReporterCancel = newStatusCancel
				}
			} else {
				logger.Info("msg", "Shutdown signal received", "signal", sig)
				cancel() // Trigger service shutdown via context
			}

		case event, ok := <-configChanges:
			if !ok {
				logger.Warn("msg", "Configuration watch channel closed, disabling auto-reload")
				configChanges = nil // Stop selecting on this channel
				continue
			}
			logger.Info("msg", "Configuration file change detected, triggering reload", "event", event)
			newSvc, newCfg, newStatusCancel, err := handleReload(ctx, svc, statusReporterCancel)
			if err == nil {
				svc = newSvc
				cfg = newCfg
				statusReporterCancel = newStatusCancel
			}

		case <-ctx.Done():
			return // Exit the loop and trigger deferred shutdown
		}
	}
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
