// FILE: src/cmd/logwisp/bootstrap.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
)

// bootstrapService creates and initializes the log transport service
func bootstrapService(ctx context.Context, cfg *config.Config) (*service.Service, *service.HTTPRouter, error) {
	// Create service
	svc := service.New(ctx, logger)

	// Create HTTP router if requested
	var router *service.HTTPRouter
	if *useRouter {
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
		if *useRouter {
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
		displayPipelineEndpoints(pipelineCfg, *useRouter)
	}

	if successCount == 0 {
		return nil, nil, fmt.Errorf("no pipelines successfully started (attempted %d)", len(cfg.Pipelines))
	}

	logger.Info("msg", "LogWisp started",
		"version", version.Short(),
		"pipelines", successCount)

	return svc, router, nil
}

// initializeLogger sets up the logger based on configuration and CLI flags
func initializeLogger(cfg *config.Config) error {
	logger = log.NewLogger()

	var configArgs []string

	// Determine output mode from CLI or config
	outputMode := cfg.Logging.Output
	if *logOutput != "" {
		outputMode = *logOutput
	}

	// Determine log level
	level := cfg.Logging.Level
	if *logLevel != "" {
		level = *logLevel
	}
	levelValue, err := parseLogLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	configArgs = append(configArgs, fmt.Sprintf("level=%d", levelValue))

	// Configure based on output mode
	switch outputMode {
	case "none":
		// ⚠️ SECURITY: Disabling logs may hide security events
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
		return fmt.Errorf("invalid log output mode: %s", outputMode)
	}

	// Apply format if specified
	if cfg.Logging.Console != nil && cfg.Logging.Console.Format != "" {
		configArgs = append(configArgs, fmt.Sprintf("format=%s", cfg.Logging.Console.Format))
	}

	return logger.InitWithDefaults(configArgs...)
}

// configureFileLogging sets up file-based logging parameters
func configureFileLogging(configArgs *[]string, cfg *config.Config) {
	// CLI overrides
	if *logFile != "" {
		dir := filepath.Dir(*logFile)
		name := strings.TrimSuffix(filepath.Base(*logFile), filepath.Ext(*logFile))
		*configArgs = append(*configArgs,
			fmt.Sprintf("directory=%s", dir),
			fmt.Sprintf("name=%s", name))
	} else if *logDir != "" {
		*configArgs = append(*configArgs,
			fmt.Sprintf("directory=%s", *logDir),
			fmt.Sprintf("name=%s", cfg.Logging.File.Name))
	} else if cfg.Logging.File != nil {
		// Use config file settings
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

	if *logConsole != "" {
		target = *logConsole
	} else if cfg.Logging.Console != nil && cfg.Logging.Console.Target != "" {
		target = cfg.Logging.Console.Target
	}

	// Handle "split" mode at application level since log package doesn't support it natively
	if target == "split" {
		// For now, default to stderr for all since log package doesn't support split
		// TODO: Future enhancement - route ERROR/WARN to stderr, INFO/DEBUG to stdout
		target = "stderr"
	}

	*configArgs = append(*configArgs, fmt.Sprintf("stdout_target=%s", target))
}

// isBackgroundProcess checks if we're already running in background
func isBackgroundProcess() bool {
	return os.Getenv("LOGWISP_BACKGROUND") == "1"
}

// runInBackground starts the process in background
func runInBackground() error {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "LOGWISP_BACKGROUND=1")
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout // Keep stdout for logging
	cmd.Stderr = os.Stderr // Keep stderr for logging

	if err := cmd.Start(); err != nil {
		return err
	}

	fmt.Printf("Started LogWisp in background (PID: %d)\n", cmd.Process.Pid)
	return nil
}