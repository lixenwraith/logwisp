package main

import (
	"context"
	"fmt"

	_ "logwisp/src/internal/source/console"
	_ "logwisp/src/internal/source/file"
	_ "logwisp/src/internal/source/null"
	_ "logwisp/src/internal/source/random"

	_ "logwisp/src/internal/sink/console"
	_ "logwisp/src/internal/sink/file"
	_ "logwisp/src/internal/sink/http"
	_ "logwisp/src/internal/sink/null"
	_ "logwisp/src/internal/sink/tcp"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
)

// bootstrapInitial handles initial service startup with status reporter
func bootstrapInitial(ctx context.Context, cfg *config.Config) (*service.Service, context.CancelFunc, error) {
	svc, err := bootstrapService(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to bootstrap service: %w", err)
	}

	if err := svc.Start(); err != nil {
		return nil, nil, fmt.Errorf("failed to start service pipelines: %w", err)
	}

	var statusCancel context.CancelFunc
	if cfg.StatusReporter {
		statusCancel = startStatusReporter(ctx, svc)
	}

	return svc, statusCancel, nil
}

// handleReload orchestrates the entire hot-reload process including status reporter lifecycle
func handleReload(ctx context.Context, oldSvc *service.Service, statusCancel context.CancelFunc) (*service.Service, *config.Config, context.CancelFunc, error) {
	logger.Info("msg", "Starting configuration hot reload")

	// Get updated config from the lixenwraith/config manager
	lcfg := config.GetConfigManager()
	if lcfg == nil {
		err := fmt.Errorf("config manager not available for reload")
		logger.Error("msg", "Reload failed", "error", err)
		return nil, nil, nil, err
	}

	updatedCfgStruct, err := lcfg.AsStruct()
	if err != nil {
		logger.Error("msg", "Failed to get updated config for reload", "error", err, "action", "keeping current configuration")
		return nil, nil, nil, err
	}
	newCfg := updatedCfgStruct.(*config.Config)

	// Bootstrap a new service to ensure it's valid before touching the old one
	logger.Debug("msg", "Bootstrapping new service with updated config")
	newService, err := bootstrapService(ctx, newCfg)
	if err != nil {
		logger.Error("msg", "Failed to bootstrap new service, keeping old service running", "error", err)
		return nil, nil, nil, err
	}

	// Gracefully shut down the old service
	if oldSvc != nil {
		logger.Info("msg", "Shutting down old service before activating new one")
		oldSvc.Shutdown()
	}

	// Start the new service
	if err := newService.Start(); err != nil {
		logger.Error("msg", "Failed to start new service pipelines after reload. The application may be in a non-functional state.", "error", err)
		return nil, nil, nil, fmt.Errorf("failed to start new service: %w", err)
	}

	// Manage status reporter lifecycle
	if statusCancel != nil {
		statusCancel()
	}

	var newStatusCancel context.CancelFunc
	if newCfg.StatusReporter {
		newStatusCancel = startStatusReporter(ctx, newService)
	}

	logger.Info("msg", "Configuration hot reload completed successfully")
	return newService, newCfg, newStatusCancel, nil
}

// bootstrapService creates and initializes the main log transport service and its pipelines
func bootstrapService(ctx context.Context, cfg *config.Config) (*service.Service, error) {
	// Create service with logger dependency injection
	svc, err := service.NewService(ctx, cfg, logger)
	if err != nil {
		logger.Error("msg", "Failed to initialize service",
			"component", "bootstrap",
		)
		return nil, err
	}

	logger.Info("msg", "LogWisp started",
		"version", version.Short(),
	)

	return svc, nil
}

// initializeLogger sets up the global logger based on the application's configuration
func initializeLogger(cfg *config.Config) error {
	logger = log.NewLogger()
	logCfg := log.DefaultConfig()

	if cfg.Quiet {
		// In quiet mode, disable ALL logging output
		logCfg.Level = 255 // A level that disables all output
		logCfg.EnableFile = false
		logCfg.EnableConsole = false
		return logger.ApplyConfig(logCfg)
	}

	// Determine log level
	levelValue, err := log.Level(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logCfg.Level = levelValue

	// Configure based on output mode
	switch cfg.Logging.Output {
	case "none":
		logCfg.EnableFile = false
		logCfg.EnableConsole = false
	case "stdout":
		logCfg.EnableFile = false
		logCfg.EnableConsole = true
		logCfg.ConsoleTarget = "stdout"
	case "stderr":
		logCfg.EnableFile = false
		logCfg.EnableConsole = true
		logCfg.ConsoleTarget = "stderr"
	case "split":
		logCfg.EnableFile = false
		logCfg.EnableConsole = true
		logCfg.ConsoleTarget = "split"
	case "file":
		logCfg.EnableFile = true
		logCfg.EnableConsole = false
		configureFileLogging(logCfg, cfg)
	case "all":
		logCfg.EnableFile = true
		logCfg.EnableConsole = true
		logCfg.ConsoleTarget = "split"
		configureFileLogging(logCfg, cfg)
	default:
		return fmt.Errorf("invalid log output mode: %s", cfg.Logging.Output)
	}

	return logger.ApplyConfig(logCfg)
}

// configureFileLogging sets up file-based logging parameters from the configuration
func configureFileLogging(logCfg *log.Config, cfg *config.Config) {
	if cfg.Logging.File != nil {
		logCfg.Directory = cfg.Logging.File.Directory
		logCfg.Name = cfg.Logging.File.Name
		logCfg.MaxSizeKB = cfg.Logging.File.MaxSizeMB * 1000
		logCfg.MaxTotalSizeKB = cfg.Logging.File.MaxTotalSizeMB * 1000
		if cfg.Logging.File.RetentionHours > 0 {
			logCfg.RetentionPeriodHrs = cfg.Logging.File.RetentionHours
		}
	}
}