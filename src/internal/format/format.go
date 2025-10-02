// FILE: logwisp/src/internal/format/format.go
package format

import (
	"fmt"

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
func NewFormatter(name string, options map[string]any, logger *log.Logger) (Formatter, error) {
	// Default to raw if no format specified
	if name == "" {
		name = "raw"
	}

	switch name {
	case "json":
		return NewJSONFormatter(options, logger)
	case "txt":
		return NewTextFormatter(options, logger)
	case "raw":
		return NewRawFormatter(options, logger)
	default:
		return nil, fmt.Errorf("unknown formatter type: %s", name)
	}
}