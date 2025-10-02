// FILE: logwisp/src/internal/config/loader.go
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

func defaults() *Config {
	return &Config{
		// Top-level flag defaults
		Background:  false,
		ShowVersion: false,
		Quiet:       false,

		// Runtime behavior defaults
		DisableStatusReporter: false,
		ConfigAutoReload:      false,
		ConfigSaveOnExit:      false,

		// Child process indicator
		BackgroundDaemon: false,

		// Existing defaults
		Logging: DefaultLogConfig(),
		Pipelines: []PipelineConfig{
			{
				Name: "default",
				Sources: []SourceConfig{
					{
						Type: "directory",
						Options: map[string]any{
							"path":              "./",
							"pattern":           "*.log",
							"check_interval_ms": int64(100),
						},
					},
				},
				Sinks: []SinkConfig{
					{
						Type: "http",
						Options: map[string]any{
							"port":        int64(8080),
							"buffer_size": int64(1000),
							"stream_path": "/stream",
							"status_path": "/status",
							"heartbeat": map[string]any{
								"enabled":           true,
								"interval_seconds":  int64(30),
								"include_timestamp": true,
								"include_stats":     false,
								"format":            "comment",
							},
						},
					},
				},
			},
		},
	}
}

// Single entry point for loading all configuration
func Load(args []string) (*Config, error) {
	configPath, isExplicit := resolveConfigPath(args)
	// Build configuration with all sources
	cfg, err := lconfig.NewBuilder().
		WithDefaults(defaults()).
		WithEnvPrefix("LOGWISP_").
		WithEnvTransform(customEnvTransform).
		WithArgs(args).
		WithFile(configPath).
		WithSources(
			lconfig.SourceCLI,
			lconfig.SourceEnv,
			lconfig.SourceFile,
			lconfig.SourceDefault,
		).
		Build()

	if err != nil {
		// Handle file not found errors - maintain existing behavior
		if errors.Is(err, lconfig.ErrConfigNotFound) {
			if isExplicit {
				return nil, fmt.Errorf("config file not found: %s", configPath)
			}
			// If the default config file is not found, it's not an error
		} else {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Scan into final config struct - using new interface
	finalConfig := &Config{}
	if err := cfg.Scan(finalConfig); err != nil {
		return nil, fmt.Errorf("failed to scan config: %w", err)
	}

	// Set config file path if it exists
	if _, err := os.Stat(configPath); err == nil {
		finalConfig.ConfigFile = configPath
	}

	// Ensure critical fields are not nil
	if finalConfig.Logging == nil {
		finalConfig.Logging = DefaultLogConfig()
	}

	// Apply console target overrides if needed
	if err := applyConsoleTargetOverrides(finalConfig); err != nil {
		return nil, fmt.Errorf("failed to apply console target overrides: %w", err)
	}

	// Validate configuration
	return finalConfig, finalConfig.validate()
}

// Returns the configuration file path
func resolveConfigPath(args []string) (path string, isExplicit bool) {
	// 1. Check for --config flag in command-line arguments (highest precedence)
	for i, arg := range args {
		if (arg == "--config" || arg == "-c") && i+1 < len(args) {
			return args[i+1], true
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config="), true
		}
	}

	// 2. Check environment variables
	if configFile := os.Getenv("LOGWISP_CONFIG_FILE"); configFile != "" {
		path = configFile
		if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
			path = filepath.Join(configDir, configFile)
		}
		return path, true
	}
	if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
		return filepath.Join(configDir, "logwisp.toml"), true
	}

	// 3. Check default user config location
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath := filepath.Join(homeDir, ".config", "logwisp", "logwisp.toml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath, false // Found a default, but not explicitly set by user
		}
	}

	// 4. Fallback to default in current directory
	return "logwisp.toml", false
}

func customEnvTransform(path string) string {
	env := strings.ReplaceAll(path, ".", "_")
	env = strings.ToUpper(env)
	// env = "LOGWISP_" + env // already added by WithEnvPrefix
	return env
}

// Centralizes console target configuration
func applyConsoleTargetOverrides(cfg *Config) error {
	// Check environment variable for console target override
	consoleTarget := os.Getenv("LOGWISP_CONSOLE_TARGET")
	if consoleTarget == "" {
		return nil
	}

	// Validate console target value
	validTargets := map[string]bool{
		"stdout": true,
		"stderr": true,
		"split":  true,
	}
	if !validTargets[consoleTarget] {
		return fmt.Errorf("invalid LOGWISP_CONSOLE_TARGET value: %s", consoleTarget)
	}

	// Apply to console sinks
	for i, pipeline := range cfg.Pipelines {
		for j, sink := range pipeline.Sinks {
			if sink.Type == "console" {
				if sink.Options == nil {
					cfg.Pipelines[i].Sinks[j].Options = make(map[string]any)
				}
				// Set target for split mode handling
				cfg.Pipelines[i].Sinks[j].Options["target"] = consoleTarget
			}
		}
	}

	return nil
}