package format

import (
	"logwisp/internal/config"
	"logwisp/internal/core"
)

// Formatter defines the interface for transforming a LogEntry into a byte slice
type Formatter interface {
	// Format takes a LogEntry and returns the formatted log as a byte slice
	Format(entry core.LogEntry) ([]byte, error)

	// Name returns the formatter's type name (e.g., "json", "raw")
	Name() string
}

// NewFormatter creates a Formatter using formatter/sanitizer packages
func NewFormatter(cfg *config.FormatConfig) (Formatter, error) {
	if cfg == nil {
		cfg = &config.FormatConfig{
			Type:            DefaultFormatType,
			Flags:           0,
			SanitizerPolicy: "raw",
		}
	}

	return NewFormatterAdapter(cfg)
}