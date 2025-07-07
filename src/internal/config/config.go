// FILE: src/internal/config/config.go
package config

type Config struct {
	// Stream configurations
	Streams []StreamConfig `toml:"streams"`
}

type MonitorConfig struct {
	CheckIntervalMs int `toml:"check_interval_ms"`
}