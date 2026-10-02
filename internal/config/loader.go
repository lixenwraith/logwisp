package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"logwisp/internal/core"

	lconfig "github.com/lixenwraith/config"
)

// ErrConfigNotFound identifies an explicitly requested missing configuration file.
var ErrConfigNotFound = lconfig.ErrConfigNotFound

// Manager owns the configuration sources and watcher for one application instance.
// Its snapshots are detached from each other and from the running service.
type Manager struct {
	config *lconfig.Config
	path   string
}

// Load reads the startup sources and validates the initial configuration.
// Watching starts only when Watch is called after successful service startup.
func Load(args []string) (*Manager, error) {
	configPath, isExplicit, configArgs, err := resolveConfigPath(args)
	if err != nil {
		return nil, err
	}
	initial := defaults()
	cfg, err := lconfig.NewBuilder().
		WithTarget(initial).
		WithEnvPrefix("LOGWISP_").
		WithArgs(configArgs).
		WithFile(configPath).
		WithTypedValidator(ValidateConfig).
		WithSecurityOptions(lconfig.SecurityOptions{
			PreventPathTraversal: true,
			MaxFileSize:          10 * 1024 * 1024,
		}).
		Build()
	if err != nil {
		if !errors.Is(err, lconfig.ErrConfigNotFound) {
			return nil, fmt.Errorf("failed to load or validate config: %w", err)
		}
		if isExplicit {
			return nil, fmt.Errorf("config file %q: %w", configPath, err)
		}
		// A missing discovered default still permits valid CLI/env/default values.
	}
	if unknown := cfg.UnknownCLIKeys(); len(unknown) > 0 && !initial.Quiet {
		fmt.Fprintf(os.Stderr, "Warning: unrecognized flags ignored: %v\n", unknown)
	}
	return &Manager{config: cfg, path: configPath}, nil
}

// Snapshot validates a detached candidate before it is used to build a service.
// Builder validators only run during Load, so every reload needs this check too.
func (m *Manager) Snapshot() (*Config, error) {
	value, err := m.config.AsStruct()
	if err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	cfg := value.(*Config)
	cfg.ConfigFile = m.path
	if err := checkFileKeys(m.path); err != nil {
		return nil, fmt.Errorf("config file %q: %w", m.path, err)
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}

// Reload rereads the selected file, retaining the startup CLI/environment sources.
// Signals must call this even when automatic watching is disabled.
func (m *Manager) Reload() (*Config, error) {
	if err := m.config.LoadFile(m.path); err != nil {
		return nil, fmt.Errorf("reload %q: %w", m.path, err)
	}
	return m.Snapshot()
}

// Watch subscribes with logwisp's polling and debounce settings.
func (m *Manager) Watch() <-chan string {
	opts := lconfig.DefaultWatchOptions()
	opts.PollInterval = core.ReloadWatchPollInterval
	opts.Debounce = core.ReloadWatchDebounce
	opts.ReloadTimeout = core.ReloadWatchTimeout
	return m.config.WatchWithOptions(opts)
}

func (m *Manager) Close() { m.config.StopAutoUpdate() }

// defaults provides the default configuration values for the application
func defaults() *Config {
	return &Config{
		// Top-level flag defaults
		ShowVersion: false,
		Quiet:       false,

		// Runtime behavior defaults
		StatusReporter:   true,
		ConfigAutoReload: false,

		// Existing defaults
		Logging: &LogConfig{
			Output: "stdout",
			Level:  "info",
			Format: "txt",
			File: &LogFileConfig{
				Directory:      "./log",
				Name:           "logwisp",
				MaxSizeMB:      100,
				MaxTotalSizeMB: 1000,
				RetentionHours: 168, // 7 days
			},
			Console: &LogConsoleConfig{
				Target: "stdout",
			},
		},
		Pipelines: []PipelineConfig{
			{
				Name: "default_pipeline",
				Flow: &FlowConfig{
					RateLimit: &RateLimitConfig{
						Rate:              5,
						Burst:             10,
						Policy:            "drop",
						MaxEntrySizeBytes: 65536,
					},
					Format: &FormatConfig{
						Type:            "json",
						SanitizerPolicy: "json",
					},
				},
				PluginSources: []PluginSourceConfig{
					{
						ID:   "default_source",
						Type: "random",
						Config: map[string]any{
							"special": true,
						},
					},
				},
				PluginSinks: []PluginSinkConfig{
					{
						ID:   "default_sink",
						Type: "console",
						Config: map[string]any{
							"target":      "stdout",
							"buffer_size": 100,
						},
					},
				},
			},
		},
	}
}

// resolveConfigPath consumes file-selection flags before schema CLI parsing.
// The last selection wins, and -- terminates option handling.
func resolveConfigPath(args []string) (path string, isExplicit bool, remaining []string, err error) {
	remaining = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			remaining = append(remaining, args[i:]...)
			break
		}
		switch {
		case arg == "-c" || arg == "--config":
			if i+1 == len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return "", false, nil, fmt.Errorf("%s requires a configuration file path", arg)
			}
			i++
			path, isExplicit = args[i], true
		case strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-c="):
			_, path, _ = strings.Cut(arg, "=")
			if path == "" {
				return "", false, nil, fmt.Errorf("%s requires a configuration file path", arg)
			}
			isExplicit = true
		default:
			remaining = append(remaining, arg)
		}
	}
	if isExplicit {
		return path, true, remaining, nil
	}
	if configFile := os.Getenv("LOGWISP_CONFIG_FILE"); configFile != "" {
		path = configFile
		if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
			path = filepath.Join(configDir, configFile)
		}
		return path, true, remaining, nil
	}
	if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
		return filepath.Join(configDir, "logwisp.toml"), true, remaining, nil
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		path = filepath.Join(homeDir, ".config", "logwisp", "logwisp.toml")
		if _, err := os.Stat(path); err == nil {
			return path, false, remaining, nil
		}
	}
	return "logwisp.toml", false, remaining, nil
}
