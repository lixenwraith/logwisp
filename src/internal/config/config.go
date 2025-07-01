// File: logwisp/src/internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds the complete configuration
type Config struct {
	Port    int           `toml:"port"`
	Monitor MonitorConfig `toml:"monitor"`
	Stream  StreamConfig  `toml:"stream"`
}

// MonitorConfig holds monitoring settings
type MonitorConfig struct {
	CheckIntervalMs int             `toml:"check_interval_ms"`
	Targets         []MonitorTarget `toml:"targets"`
}

// MonitorTarget represents a path to monitor
type MonitorTarget struct {
	Path    string `toml:"path"`
	Pattern string `toml:"pattern"`
}

// StreamConfig holds streaming settings
type StreamConfig struct {
	BufferSize int `toml:"buffer_size"`
}

// DefaultConfig returns configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Port: 8080,
		Monitor: MonitorConfig{
			CheckIntervalMs: 100,
			Targets: []MonitorTarget{
				{
					Path:    "./",
					Pattern: "*.log",
				},
			},
		},
		Stream: StreamConfig{
			BufferSize: 1000,
		},
	}
}

// Load reads configuration from default location or returns defaults
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Determine config path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil // Return defaults if can't find home
	}

	// configPath := filepath.Join(homeDir, ".config", "logwisp.toml")
	configPath := filepath.Join(homeDir, "git", "lixenwraith", "logwisp", "config", "logwisp.toml")

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// No config file, use defaults
		return cfg, nil
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// validate checks configuration sanity
func (c *Config) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	if c.Monitor.CheckIntervalMs < 10 {
		return fmt.Errorf("check interval too small: %d ms", c.Monitor.CheckIntervalMs)
	}

	if c.Stream.BufferSize < 1 {
		return fmt.Errorf("buffer size must be positive: %d", c.Stream.BufferSize)
	}

	if len(c.Monitor.Targets) == 0 {
		return fmt.Errorf("no monitor targets specified")
	}

	for i, target := range c.Monitor.Targets {
		if target.Path == "" {
			return fmt.Errorf("target %d: empty path", i)
		}
		if target.Pattern == "" {
			return fmt.Errorf("target %d: empty pattern", i)
		}
	}

	return nil
}