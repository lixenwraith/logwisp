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

	var configArgs []string

	if cfg.Quiet {
		// In quiet mode, disable ALL logging output
		configArgs = append(configArgs,
			"disable_file=true",
			"enable_stdout=false",
			"level=255")

		return logger.InitWithDefaults(configArgs...)
	}

	// Determine log level
	levelValue, err := parseLogLevel(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	configArgs = append(configArgs, fmt.Sprintf("level=%d", levelValue))

	// Configure based on output mode
	switch cfg.Logging.Output {
	case "none":
		configArgs = append(configArgs, "disable_file=true", "enable_stdout=false")

	case "stdout":
		configArgs = append(configArgs,
			"disable_file=true",
			"enable_stdout=true",
			"stdout_target=stdout")

	case "stderr":
		configArgs = append(configArgs,
			"disable_file=true",
			"enable_stdout=true",
			"stdout_target=stderr")

	case "file":
		configArgs = append(configArgs, "enable_stdout=false")
		configureFileLogging(&configArgs, cfg)

	case "both":
		configArgs = append(configArgs, "enable_stdout=true")
		configureFileLogging(&configArgs, cfg)
		configureConsoleTarget(&configArgs, cfg)

	default:
		return fmt.Errorf("invalid log output mode: %s", cfg.Logging.Output)
	}

	// Apply format if specified
	if cfg.Logging.Console != nil && cfg.Logging.Console.Format != "" {
		configArgs = append(configArgs, fmt.Sprintf("format=%s", cfg.Logging.Console.Format))
	}

	return logger.InitWithDefaults(configArgs...)
}

// configureFileLogging sets up file-based logging parameters
func configureFileLogging(configArgs *[]string, cfg *config.Config) {
	if cfg.Logging.File != nil {
		*configArgs = append(*configArgs,
			fmt.Sprintf("directory=%s", cfg.Logging.File.Directory),
			fmt.Sprintf("name=%s", cfg.Logging.File.Name),
			fmt.Sprintf("max_size_mb=%d", cfg.Logging.File.MaxSizeMB),
			fmt.Sprintf("max_total_size_mb=%d", cfg.Logging.File.MaxTotalSizeMB))

		if cfg.Logging.File.RetentionHours > 0 {
			*configArgs = append(*configArgs,
				fmt.Sprintf("retention_period_hrs=%.1f", cfg.Logging.File.RetentionHours))
		}
	}
}

// configureConsoleTarget sets up console output parameters
func configureConsoleTarget(configArgs *[]string, cfg *config.Config) {
	target := "stderr" // default

	if cfg.Logging.Console != nil && cfg.Logging.Console.Target != "" {
		target = cfg.Logging.Console.Target
	}

	// Split mode by configuring log package with level-based routing
	if target == "split" {
		*configArgs = append(*configArgs, "stdout_split_mode=true")
		*configArgs = append(*configArgs, "stdout_target=split")
	} else {
		*configArgs = append(*configArgs, fmt.Sprintf("stdout_target=%s", target))
	}
}

func parseLogLevel(level string) (int, error) {
	switch strings.ToLower(level) {
	case "debug":
		return int(log.LevelDebug), nil
	case "info":
		return int(log.LevelInfo), nil
	case "warn", "warning":
		return int(log.LevelWarn), nil
	case "error":
		return int(log.LevelError), nil
	default:
		return 0, fmt.Errorf("unknown log level: %s", level)
	}
}