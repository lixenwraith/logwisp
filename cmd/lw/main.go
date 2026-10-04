package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/version"

	"github.com/lixenwraith/log"
	"golang.org/x/term"
)

var logger *log.Logger

func main() {
	inv, err := parseCommandLine(os.Args[1:])
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	case inv.command != nil:
		os.Exit(inv.command.run(inv.args, os.Stdout, os.Stderr))
	case inv.help:
		printHelp()
		os.Exit(0)
	}

	// --- 1. Initial setup ---
	// Emulates nohup
	signal.Ignore(syscall.SIGHUP)

	manager, err := config.Load(inv.load)
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
	if cfg.Check {
		os.Exit(checkConfig(cfg))
	}
	if cfg.Dump {
		os.Exit(dumpConfig(cfg, os.Stdout))
	}

	if err := initializeLogger(cfg); err != nil {
		FatalError(1, "Failed to initialize logger: %v\n", err)
	}
	defer shutdownLogger()

	if err := logger.Start(); err != nil {
		FatalError(1, "Failed to start logger: %v\n", err)
	}

	configFile := cfg.ConfigFile
	if _, err := os.Stat(configFile); err != nil {
		configFile = "none" // flags, environment and built-in defaults only
	}
	logger.Info("msg", "LogWisp starting",
		"version", version.String(),
		"config_file", configFile,
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

	if !cfg.Quiet && readsStdin(cfg) && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "lw: reading standard input; Ctrl-D ends it (lw --help for usage)")
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

	// Closed when every pipeline's input ended (stdin); nil while none runs
	done := svc.Done()

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
		switch {
		case err == nil:
			svc, cfg, statusReporterCancel = newSvc, newCfg, newStatusCancel
			done = svc.Done()
		case errors.Is(err, errServiceStopped):
			done = nil // the stopped service's pipelines did not reach the end of input
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

		case <-done:
			logger.Info("msg", "Every pipeline finished: its input ended")
			return

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

// readsStdin reports a console source: typed into, it waits for the keyboard
func readsStdin(cfg *config.Config) bool {
	for _, p := range cfg.Pipelines {
		for _, src := range p.PluginSources {
			if src.Type == "console" {
				return true
			}
		}
	}
	return false
}
