// FILE: logwisp/src/internal/format/raw.go
package format

import (
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Outputs the log message as-is with a newline
type RawFormatter struct {
	logger *log.Logger
}

// Creates a new raw formatter
func NewRawFormatter(options map[string]any, logger *log.Logger) (*RawFormatter, error) {
	return &RawFormatter{
		logger: logger,
	}, nil
}

// Returns the message with a newline appended
func (f *RawFormatter) Format(entry core.LogEntry) ([]byte, error) {
	// Simply return the message with newline
	return append([]byte(entry.Message), '\n'), nil
}

// Returns the formatter name
func (f *RawFormatter) Name() string {
	return "raw"
}