// FILE: logwisp/src/cmd/logwisp/bootstrap.go
package main

import (
	"context"
	"fmt"
	"strings"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
)

// Creates and initializes the log transport service
func bootstrapService(ctx context.Context, cfg *config.Config) (*service.Service, error) {
	// Create service with logger dependency injection
	svc := service.NewService(ctx, logger)

	// Initialize pipelines
	successCount := 0
	for _, pipelineCfg := range cfg.Pipelines {
		logger.Info("msg", "Initializing pipeline", "pipeline", pipelineCfg.Name)

		// Create the pipeline
		if err := svc.NewPipeline(pipelineCfg); err != nil {
			logger.Error("msg", "Failed to create pipeline",
				"pipeline", pipelineCfg.Name,
				"error", err)
			continue
		}
		successCount++
		displayPipelineEndpoints(pipelineCfg)
	}

	if successCount == 0 {
		return nil, fmt.Errorf("no pipelines successfully started (attempted %d)", len(cfg.Pipelines))
	}

	logger.Info("msg", "LogWisp started",
		"version", version.Short(),
		"pipelines", successCount)

	return svc, nil
}

// Sets up the logger based on configuration
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
	levelValue, err := parseLogLevel(cfg.Logging.Level)
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

	// Apply format if specified
	if cfg.Logging.Console != nil && cfg.Logging.Console.Format != "" {
		logCfg.Format = cfg.Logging.Console.Format
	}

	return logger.ApplyConfig(logCfg)
}

// Sets up file-based logging parameters
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

func parseLogLevel(level string) (int64, error) {
	switch strings.ToLower(level) {
	case "debug":
		return log.LevelDebug, nil
	case "info":
		return log.LevelInfo, nil
	case "warn", "warning":
		return log.LevelWarn, nil
	case "error":
		return log.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level: %s", level)
	}
}