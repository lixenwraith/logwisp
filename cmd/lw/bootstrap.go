package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	_ "github.com/lixenwraith/logwisp/internal/source/console"
	_ "github.com/lixenwraith/logwisp/internal/source/file"
	_ "github.com/lixenwraith/logwisp/internal/source/httpchain"
	_ "github.com/lixenwraith/logwisp/internal/source/null"
	_ "github.com/lixenwraith/logwisp/internal/source/random"
	_ "github.com/lixenwraith/logwisp/internal/source/tcpchain"

	_ "github.com/lixenwraith/logwisp/internal/sink/console"
	_ "github.com/lixenwraith/logwisp/internal/sink/file"
	_ "github.com/lixenwraith/logwisp/internal/sink/http"
	_ "github.com/lixenwraith/logwisp/internal/sink/httpchain"
	_ "github.com/lixenwraith/logwisp/internal/sink/null"
	_ "github.com/lixenwraith/logwisp/internal/sink/tcp"
	_ "github.com/lixenwraith/logwisp/internal/sink/tcpchain"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/service"
	"github.com/lixenwraith/logwisp/internal/version"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/sanitizer"
	"github.com/lixenwraith/toml"
)

// bootstrapInitial handles initial service startup with status reporter
func bootstrapInitial(ctx context.Context, cfg *config.Config) (*service.Service, context.CancelFunc, error) {
	svc, err := bootstrapService(ctx, cfg, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to bootstrap service: %w", err)
	}
	authz.EndStartup() // a reload reads no descriptor, pipe or terminal

	if err := svc.Start(); err != nil {
		svc.Shutdown()
		return nil, nil, fmt.Errorf("failed to start service pipelines: %w", err)
	}

	var statusCancel context.CancelFunc
	if cfg.StatusReporter {
		statusCancel = startStatusReporter(ctx, svc)
	}

	return svc, statusCancel, nil
}

// errServiceStopped is a reload that failed after the old service stopped:
// no pipeline runs until a later reload succeeds.
var errServiceStopped = errors.New("old service stopped, new one failed to start")

// handleReload orchestrates the entire hot-reload process including status
// reporter lifecycle; tap is the screen's, nil for none
func handleReload(ctx context.Context, newCfg *config.Config, oldSvc *service.Service, statusCancel context.CancelFunc, tap *core.Tap) (*service.Service, *config.Config, context.CancelFunc, error) {
	logger.Info("msg", "Starting configuration hot reload")

	if err := config.ValidateConfig(newCfg); err != nil {
		logger.Error("msg", "Invalid reload configuration, keeping old service running", "error", oneLine(err))
		return nil, nil, nil, err
	}

	// Bootstrap a new service to ensure it's valid before touching the old one
	logger.Debug("msg", "Bootstrapping new service with updated config")
	newService, err := bootstrapService(ctx, newCfg, tap)
	if err != nil {
		logger.Error("msg", "Failed to bootstrap new service, keeping old service running", "error", err)
		return nil, nil, nil, err
	}

	if statusCancel != nil {
		statusCancel()
	}
	if oldSvc != nil {
		logger.Info("msg", "Shutting down old service before activating new one")
		oldSvc.Shutdown()
	}

	if err := newService.Start(); err != nil {
		newService.Shutdown()
		logger.Error("msg", "Failed to start new service pipelines after reload. The application may be in a non-functional state.", "error", err)
		return nil, nil, nil, fmt.Errorf("%w: %w", errServiceStopped, err)
	}

	var newStatusCancel context.CancelFunc
	if newCfg.StatusReporter {
		newStatusCancel = startStatusReporter(ctx, newService)
	}

	logger.Info("msg", "Configuration hot reload completed successfully")
	return newService, newCfg, newStatusCancel, nil
}

// bootstrapService builds the service and its pipelines, which offer what
// their flows decide to tap from their first entry; nil for none
func bootstrapService(ctx context.Context, cfg *config.Config, tap *core.Tap) (*service.Service, error) {
	svc, err := service.NewService(ctx, cfg, logger)
	if err != nil {
		logger.Error("msg", "Failed to initialize service",
			"component", "bootstrap",
		)
		return nil, err
	}
	svc.SetTap(tap)

	logger.Info("msg", "LogWisp started",
		"version", version.Short(),
	)

	return svc, nil
}

// checkConfig builds every pipeline and plugin as a start would, so TLS files,
// credentials and options are loaded and their warnings print, then exits
// before anything binds or reads: plugins start goroutines only in Start.
func checkConfig(cfg *config.Config) int {
	cfg.Logging.Output, cfg.Logging.Level = "stderr", "warn"
	if err := initializeLogger(cfg); err == nil && logger.Start() == nil {
		defer shutdownLogger()
	}
	if _, err := service.NewService(context.Background(), cfg, logger); err != nil {
		fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
		return 1
	}
	fmt.Printf("configuration ok: %d pipeline(s)\n", len(cfg.Pipelines))
	return 0
}

// dumpConfig prints the effective configuration, flags and environment
// resolved into it, as a file lw -c reads back.
func dumpConfig(cfg *config.Config, w io.Writer) int {
	config.Uninherit(cfg.Pipelines, cfg.Color)
	data, err := toml.Marshal(cfg)
	if err == nil {
		_, err = w.Write(data)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func initializeLogger(cfg *config.Config) error {
	logger = log.NewLogger()
	logCfg := log.DefaultConfig()

	if cfg.Quiet {
		logCfg.Level = 255 // A level that disables all output
		logCfg.EnableFile = false
		logCfg.EnableConsole = false
		return logger.ApplyConfig(logCfg)
	}

	levelValue, err := log.Level(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logCfg.Level = levelValue

	if cfg.Logging.Format != "" {
		logCfg.Format = cfg.Logging.Format
	}
	if cfg.Logging.Sanitization != "" {
		logCfg.Sanitization = sanitizer.PolicyPreset(cfg.Logging.Sanitization)
	}

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

func configureFileLogging(logCfg *log.Config, cfg *config.Config) {
	if cfg.Logging.File != nil {
		logCfg.Directory = config.ExpandHome(cfg.Logging.File.Directory)
		logCfg.Name = cfg.Logging.File.Name
		logCfg.MaxSizeKB = cfg.Logging.File.MaxSizeMB * 1000
		logCfg.MaxTotalSizeKB = cfg.Logging.File.MaxTotalSizeMB * 1000
		if cfg.Logging.File.RetentionHours > 0 {
			logCfg.RetentionPeriodHrs = cfg.Logging.File.RetentionHours
		}
	}
}
