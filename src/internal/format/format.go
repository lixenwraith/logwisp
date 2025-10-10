// FILE: logwisp/src/internal/format/format.go
package format

import (
	"fmt"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Defines the interface for transforming a LogEntry into a byte slice.
type Formatter interface {
	// Format takes a LogEntry and returns the formatted log as a byte slice.
	Format(entry core.LogEntry) ([]byte, error)

	// Name returns the formatter type name
	Name() string
}

// Creates a new Formatter based on the provided configuration.
func NewFormatter(cfg *config.FormatConfig, logger *log.Logger) (Formatter, error) {
	switch cfg.Type {
	case "json":
		return NewJSONFormatter(cfg.JSONFormatOptions, logger)
	case "txt":
		return NewTxtFormatter(cfg.TxtFormatOptions, logger)
	case "raw", "":
		return NewRawFormatter(cfg.RawFormatOptions, logger)
	default:
		return nil, fmt.Errorf("unknown formatter type: %s", cfg.Type)
	}
}