// FILE: src/cmd/logwisp/bootstrap.go
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

// bootstrapService creates and initializes the log transport service
func bootstrapService(ctx context.Context, cfg *config.Config) (*service.Service, *service.HTTPRouter, error) {
	// Create service with logger dependency injection
	svc := service.New(ctx, logger)

	// Create HTTP router if requested
	var router *service.HTTPRouter
	if cfg.UseRouter {
		router = service.NewHTTPRouter(svc, logger)
		logger.Info("msg", "HTTP router mode enabled")
	}

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

		// If using router mode, register HTTP sinks
		if cfg.UseRouter {
			pipeline, err := svc.GetPipeline(pipelineCfg.Name)
			if err == nil && len(pipeline.HTTPSinks) > 0 {
				if err := router.RegisterPipeline(pipeline); err != nil {
					logger.Error("msg", "Failed to register pipeline with router",
						"pipeline", pipelineCfg.Name,
						"error", err)
				}
			}
		}

		successCount++
		displayPipelineEndpoints(pipelineCfg, cfg.UseRouter)
	}

	if successCount == 0 {
		return nil, nil, fmt.Errorf("no pipelines successfully started (attempted %d)", len(cfg.Pipelines))
	}

	logger.Info("msg", "LogWisp started",
		"version", version.Short(),
		"pipelines", successCount)

	return svc, router, nil
}

// initializeLogger sets up the logger based on configuration
func initializeLogger(cfg *config.Config) error {
	logger = log.NewLogger()
	logCfg := log.DefaultConfig()

	if cfg.Quiet {
		// In quiet mode, disable ALL logging output
		logCfg.Level = 255 // A level that disables all output
		logCfg.DisableFile = true
		logCfg.EnableStdout = false
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
		logCfg.DisableFile = true
		logCfg.EnableStdout = false
	case "stdout":
		logCfg.DisableFile = true
		logCfg.EnableStdout = true
		logCfg.StdoutTarget = "stdout"
	case "stderr":
		logCfg.DisableFile = true
		logCfg.EnableStdout = true
		logCfg.StdoutTarget = "stderr"
	case "file":
		logCfg.EnableStdout = false
		configureFileLogging(logCfg, cfg)
	case "both":
		logCfg.EnableStdout = true
		configureFileLogging(logCfg, cfg)
		configureConsoleTarget(logCfg, cfg)
	default:
		return fmt.Errorf("invalid log output mode: %s", cfg.Logging.Output)
	}

	// Apply format if specified
	if cfg.Logging.Console != nil && cfg.Logging.Console.Format != "" {
		logCfg.Format = cfg.Logging.Console.Format
	}

	return logger.ApplyConfig(logCfg)
}

// configureFileLogging sets up file-based logging parameters
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

// configureConsoleTarget sets up console output parameters
func configureConsoleTarget(logCfg *log.Config, cfg *config.Config) {
	target := "stderr" // default

	if cfg.Logging.Console != nil && cfg.Logging.Console.Target != "" {
		target = cfg.Logging.Console.Target
	}

	// Set the target, which can be "stdout", "stderr", or "split"
	logCfg.StdoutTarget = target
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