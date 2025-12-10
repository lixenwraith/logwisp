package format

import (
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
)

// Formatter defines the interface for transforming a LogEntry into a byte slice
type Formatter interface {
	// Format takes a LogEntry and returns the formatted log as a byte slice
	Format(entry core.LogEntry) ([]byte, error)

	// Name returns the formatter's type name (e.g., "json", "raw")
	Name() string
}

// NewFormatter creates a Formatter using the new formatter/sanitizer packages
func NewFormatter(cfg *config.FormatConfig) (Formatter, error) {
	if cfg == nil {
		// Default config
		cfg = &config.FormatConfig{
			Type:            "raw",
			Flags:           0,
			SanitizerPolicy: "raw",
		}
	}

	// Use the new FormatterAdapter that integrates formatter and sanitizer
	return NewFormatterAdapter(cfg)
}