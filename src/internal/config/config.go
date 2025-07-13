// FILE: src/internal/config/config.go
package config

type Config struct {
	// Top-level flags for application control
	UseRouter   bool `toml:"router"`
	Background  bool `toml:"background"`
	ShowVersion bool `toml:"version"`
	Quiet       bool `toml:"quiet"`

	// Runtime behavior flags
	DisableStatusReporter bool `toml:"disable_status_reporter"`

	// Internal flag indicating demonized child process
	BackgroundDaemon bool `toml:"background-daemon"`

	// Configuration file path
	ConfigFile string `toml:"config"`

	// Existing fields
	Logging   *LogConfig       `toml:"logging"`
	Pipelines []PipelineConfig `toml:"pipelines"`
}

// Helper functions to handle type conversions from any
func toInt(v any) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	default:
		return 0, false
	}
}

func toFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	default:
		return 0, false
	}
}