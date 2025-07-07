// FILE: src/internal/config/loader.go
package config

import (
	"fmt"
	lconfig "github.com/lixenwraith/config"
	"os"
	"path/filepath"
	"strings"
)

func defaults() *Config {
	return &Config{
		Monitor: MonitorConfig{
			CheckIntervalMs: 100,
		},
		Streams: []StreamConfig{
			{
				Name: "default",
				Monitor: &StreamMonitorConfig{
					Targets: []MonitorTarget{
						{Path: "./", Pattern: "*.log", IsFile: false},
					},
				},
				HTTPServer: &HTTPConfig{
					Enabled:    true,
					Port:       8080,
					BufferSize: 1000,
					StreamPath: "/stream",
					StatusPath: "/status",
					Heartbeat: HeartbeatConfig{
						Enabled:          true,
						IntervalSeconds:  30,
						IncludeTimestamp: true,
						IncludeStats:     false,
						Format:           "comment",
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