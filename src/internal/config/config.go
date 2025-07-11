// FILE: src/internal/config/config.go
package config

type Config struct {
	// Logging configuration
	Logging *LogConfig `toml:"logging"`

	// Pipeline configurations
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