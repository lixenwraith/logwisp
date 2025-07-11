// FILE: src/internal/config/loader.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

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

func LoadWithCLI(cliArgs []string) (*Config, error) {
	configPath := GetConfigPath()

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
		if !strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	}

	finalConfig := &Config{}
	if err := cfg.Scan("", finalConfig); err != nil {
		return nil, fmt.Errorf("failed to scan config: %w", err)
	}

	return finalConfig, finalConfig.validate()
}

func customEnvTransform(path string) string {
	env := strings.ReplaceAll(path, ".", "_")
	env = strings.ToUpper(env)
	env = "LOGWISP_" + env
	return env
}

func GetConfigPath() string {
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

	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".config", "logwisp.toml")
	}

	return "logwisp.toml"
}