// FILE: logwisp/src/internal/config/config.go
package config

type Config struct {
	// Top-level flags for application control
	UseRouter   bool `toml:"router"`
	Background  bool `toml:"background"`
	ShowVersion bool `toml:"version"`
	Quiet       bool `toml:"quiet"`

	// Runtime behavior flags
	DisableStatusReporter bool `toml:"disable_status_reporter"`
	ConfigAutoReload      bool `toml:"config_auto_reload"`

	// Internal flag indicating demonized child process
	BackgroundDaemon bool `toml:"background-daemon"`

	// Configuration file path
	ConfigFile string `toml:"config"`

	// Existing fields
	Logging   *LogConfig       `toml:"logging"`
	Pipelines []PipelineConfig `toml:"pipelines"`
}