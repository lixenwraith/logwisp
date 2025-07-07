// FILE: src/internal/config/config.go
package config

type Config struct {
	// Global monitor settings
	Monitor MonitorConfig `toml:"monitor"`

	// Stream configurations
	Streams []StreamConfig `toml:"streams"`
}

type MonitorConfig struct {
	CheckIntervalMs int `toml:"check_interval_ms"`
}