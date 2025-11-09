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

// configManager holds the global instance of the configuration manager.
var configManager *lconfig.Config

// Load is the single entry point for loading all application configuration.
func Load(args []string) (*Config, error) {
	configPath, isExplicit := resolveConfigPath(args)
	// Build configuration with all sources

	// Create target config instance that will be populated
	finalConfig := &Config{}

	// Builder handles loading, populating the target struct, and validation
	cfg, err := lconfig.NewBuilder().
		WithTarget(finalConfig).  // Typed target struct
		WithDefaults(defaults()). // Default values
		WithSources(
			lconfig.SourceCLI,
			lconfig.SourceEnv,
			lconfig.SourceFile,
			lconfig.SourceDefault,
		).
		WithEnvTransform(customEnvTransform). // Convert '.' to '_' in env separation
		WithEnvPrefix("LOGWISP_").            // Environment variable prefix
		WithArgs(args).                       // Command-line arguments
		WithFile(configPath).                 // TOML config file
		WithFileFormat("toml").               // Explicit format
		WithTypedValidator(ValidateConfig).   // Centralized validation
		WithSecurityOptions(lconfig.SecurityOptions{
			PreventPathTraversal: true,
			MaxFileSize:          10 * 1024 * 1024, // 10MB max config
		}).
		Build()

	if err != nil {
		// Handle file not found errors - maintain existing behavior
		if errors.Is(err, lconfig.ErrConfigNotFound) {
			if isExplicit {
				return nil, fmt.Errorf("config file not found: %s", configPath)
			}
			// If the default config file is not found, it's not an error, default/cli/env will be used
		} else {
			return nil, fmt.Errorf("failed to load or validate config: %w", err)
		}
	}

	// Store the config file path for hot reload
	finalConfig.ConfigFile = configPath

	// Store the manager for hot reload
	configManager = cfg

	return finalConfig, nil
}

// GetConfigManager returns the global configuration manager instance for hot-reloading.
func GetConfigManager() *lconfig.Config {
	return configManager
}

// defaults provides the default configuration values for the application.
func defaults() *Config {
	return &Config{
		// Top-level flag defaults
		Background:  false,
		ShowVersion: false,
		Quiet:       false,

		// Runtime behavior defaults
		DisableStatusReporter: false,
		ConfigAutoReload:      false,

		// Child process indicator
		BackgroundDaemon: false,

		// Existing defaults
		Logging: &LogConfig{
			Output: "stdout",
			Level:  "info",
			File: &LogFileConfig{
				Directory:      "./log",
				Name:           "logwisp",
				MaxSizeMB:      100,
				MaxTotalSizeMB: 1000,
				RetentionHours: 168, // 7 days
			},
			Console: &LogConsoleConfig{
				Target: "stdout",
				Format: "txt",
			},
		},
		Pipelines: []PipelineConfig{
			{
				Name: "default",
				Sources: []SourceConfig{
					{
						Type: "file",
						File: &FileSourceOptions{
							Directory:       "./",
							Pattern:         "*.log",
							CheckIntervalMS: int64(100),
						},
					},
				},
				Sinks: []SinkConfig{
					{
						Type: "console",
						Console: &ConsoleSinkOptions{
							Target:     "stdout",
							Colorize:   false,
							BufferSize: 100,
						},
					},
				},
			},
		},
	}
}

// resolveConfigPath determines the configuration file path based on CLI args, env vars, and default locations.
func resolveConfigPath(args []string) (path string, isExplicit bool) {
	// 1. Check for --config flag in command-line arguments (highest precedence)
	for i, arg := range args {
		if arg == "-c" {
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

// customEnvTransform converts TOML-style config paths (e.g., logging.level) to environment variable format (LOGGING_LEVEL).
func customEnvTransform(path string) string {
	env := strings.ReplaceAll(path, ".", "_")
	env = strings.ToUpper(env)
	// env = "LOGWISP_" + env // already added by WithEnvPrefix
	return env
}