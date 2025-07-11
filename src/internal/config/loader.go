// FILE: src/internal/config/loader.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

// LoadContext holds all configuration sources
type LoadContext struct {
	FlagConfig interface{} // Parsed command-line flags from main
}

func defaults() *Config {
	return &Config{
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
							"check_interval_ms": 100,
						},
					},
				},
				Sinks: []SinkConfig{
					{
						Type: "http",
						Options: map[string]any{
							"port":        8080,
							"buffer_size": 1000,
							"stream_path": "/transport",
							"status_path": "/status",
							"heartbeat": map[string]any{
								"enabled":           true,
								"interval_seconds":  30,
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

// LoadWithCLI loads config with CLI flag overrides
func LoadWithCLI(cliArgs []string, flagCfg interface{}) (*Config, error) {
	configPath := GetConfigPath()

	// Build configuration with all sources
	cfg, err := lconfig.NewBuilder().
		WithDefaults(defaults()).
		WithEnvPrefix("LOGWISP_").
		WithFile(configPath).
		WithArgs(cliArgs).
		WithEnvTransform(customEnvTransform).
		WithSources(
			lconfig.SourceCLI,
			lconfig.SourceEnv,
			lconfig.SourceFile,
			lconfig.SourceDefault,
		).
		Build()

	if err != nil {
		if strings.Contains(err.Error(), "not found") && configPath != "logwisp.toml" {
			// If explicit config file specified and not found, fail
			return nil, fmt.Errorf("config file not found: %s", configPath)
		}

		if !strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Likely never happens
	if cfg == nil {
		return nil, fmt.Errorf("configuration builder returned nil config")
	}

	finalConfig := &Config{}
	if err := cfg.Scan("", finalConfig); err != nil {
		return nil, fmt.Errorf("failed to scan config: %w", err)
	}

	// Ensure we have valid config even with defaults
	if finalConfig == nil {
		return nil, fmt.Errorf("configuration scan produced nil config")
	}

	// Ensure critical fields are not nil
	if finalConfig.Logging == nil {
		finalConfig.Logging = DefaultLogConfig()
	}

	// Apply any console target transformations here
	if err := applyConsoleTargetOverrides(finalConfig); err != nil {
		return nil, fmt.Errorf("failed to apply console target overrides: %w", err)
	}

	return finalConfig, finalConfig.validate()
}

// applyConsoleTargetOverrides centralizes console target configuration
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

	// Apply to all console sinks
	for i, pipeline := range cfg.Pipelines {
		for j, sink := range pipeline.Sinks {
			if sink.Type == "stdout" || sink.Type == "stderr" {
				if sink.Options == nil {
					cfg.Pipelines[i].Sinks[j].Options = make(map[string]any)
				}
				// Set target for split mode handling
				cfg.Pipelines[i].Sinks[j].Options["target"] = consoleTarget
			}
		}
	}

	// Also update logging console target if applicable
	if cfg.Logging.Console != nil && consoleTarget == "split" {
		cfg.Logging.Console.Target = "split"
	}

	return nil
}

// GetConfigPath returns the configuration file path
func GetConfigPath() string {
	// Check if explicit config file was specified via flag or env
	if configFile := os.Getenv("LOGWISP_CONFIG_FILE"); configFile != "" {
		if filepath.IsAbs(configFile) {
			return configFile
		}
		if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
			return filepath.Join(configDir, configFile)
		}
		return configFile
	}

	if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
		return filepath.Join(configDir, "logwisp.toml")
	}

	// Default locations
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath := filepath.Join(homeDir, ".config", "logwisp.toml")
		// Check if config exists in home directory
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}

	// Return current directory default
	return "logwisp.toml"
}

func customEnvTransform(path string) string {
	env := strings.ReplaceAll(path, ".", "_")
	env = strings.ToUpper(env)
	env = "LOGWISP_" + env
	return env
}