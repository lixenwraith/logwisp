// FILE: logwisp/src/internal/format/format.go
package format

import (
	"fmt"

	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Formatter defines the interface for transforming a LogEntry into a byte slice.
type Formatter interface {
	// Format takes a LogEntry and returns the formatted log as a byte slice.
	Format(entry source.LogEntry) ([]byte, error)

	// Name returns the formatter type name
	Name() string
}

// New creates a new Formatter based on the provided configuration.
func New(name string, options map[string]any, logger *log.Logger) (Formatter, error) {
	// Default to raw if no format specified
	if name == "" {
		name = "raw"
	}

	switch name {
	case "json":
		return NewJSONFormatter(options, logger)
	case "text":
		return NewTextFormatter(options, logger)
	case "raw":
		return NewRawFormatter(options, logger)
	default:
		return nil, fmt.Errorf("unknown formatter type: %s", name)
	}
}