package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/version"

	"github.com/lixenwraith/log"
)

var logger *log.Logger

func main() {
	// Before handleHelp, so `lw auth <command> -h` prints the auth usage
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		os.Exit(runAuth(os.Args[2:], os.Stdout, os.Stderr))
	}

	// --- 1. Initial setup ---
	// Emulates nohup
	signal.Ignore(syscall.SIGHUP)

	// Before config parsing: the loader has no help flag
	handleHelp(os.Args[1:])

	manager, err := config.Load(os.Args[1:])
	if err != nil {
		if errors.Is(err, config.ErrConfigNotFound) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: Failed to load config: %v\n", err)
		os.Exit(1)
	}
	defer manager.Close()
	cfg, err := manager.Snapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read config: %v\n", err)
		os.Exit(1)
	}

	InitOutputHandler(cfg.Quiet)

	if cfg.ShowVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if err := initializeLogger(cfg); err != nil {
		FatalError(1, "Failed to initialize logger: %v\n", err)
	}
	defer shutdownLogger()

	if err := logger.Start(); err != nil {
		FatalError(1, "Failed to start logger: %v\n", err)
	}

	logger.Info("msg", "LogWisp starting",
		"version", version.String(),
		"config_file", cfg.ConfigFile,
		"log_output", cfg.Logging.Output,
		"status_reporter", cfg.StatusReporter,
		"auto_reload", cfg.ConfigAutoReload)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- 2. Bootstrap initial service ---
	svc, statusReporterCancel, err := bootstrapInitial(ctx, cfg)
	if err != nil {
		logger.Error("msg", "Failed to initialize service", "error", err)
		shutdownLogger()
		os.Exit(1)
	}

	// --- 3. Setup signals and shutdown ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	var configChanges <-chan string
	if cfg.ConfigAutoReload {
		configChanges = manager.Watch()
		logger.Info("msg", "Config auto-reload enabled", "config_file", cfg.ConfigFile)
	} else {
		logger.Info("msg", "Config auto-reload disabled")
	}

	defer func() {
		logger.Info("msg", "Shutdown initiated")
		if statusReporterCancel != nil {
			statusReporterCancel()
		}
		if svc != nil {
			svc.Shutdown()
		}
		manager.Close()
		logger.Info("msg", "Shutdown complete")
	}()

	reload := func(fromDisk bool) {
		var next *config.Config
		var err error
		if fromDisk {
			next, err = manager.Reload()
		} else {
			next, err = manager.Snapshot()
		}
		if err != nil {
			logger.Error("msg", "Failed to read reload configuration", "error", err, "action", "keeping current service")
			return
		}
		// Watch events are hints and may be duplicated or concern startup-only
		// settings. Signals always rebuild, including for certificate rotation.
		if !fromDisk && cfg.StatusReporter == next.StatusReporter && reflect.DeepEqual(cfg.Pipelines, next.Pipelines) {
			return
		}
		newSvc, newCfg, newStatusCancel, err := handleReload(ctx, next, svc, statusReporterCancel)
		if err == nil {
			svc, cfg, statusReporterCancel = newSvc, newCfg, newStatusCancel
		}
	}

	// --- 4. Main Application Event Loop ---
	logger.Info("msg", "Application started, waiting for signals or config changes")
	for {
		select {
		case sig := <-sigChan:
			if sig == syscall.SIGHUP || sig == syscall.SIGUSR1 {
				logger.Info("msg", "Reload signal received, triggering manual reload", "signal", sig)
				reload(true)
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
			if collectConfigChanges(event, configChanges) {
				reload(false)
			}

		case <-ctx.Done():
			return // Exit the loop and trigger deferred shutdown
		}
	}
}

func shutdownLogger() {
	if logger != nil {
		if err := logger.Shutdown(core.LoggerShutdownTimeout); err != nil {
			// Best effort - can't log the shutdown error
			Error("Logger shutdown error: %v\n", err)
		}
	}
}
