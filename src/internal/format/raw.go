// FILE: logwisp/src/internal/format/raw.go
package format

import (
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// RawFormatter outputs the log message as-is with a newline
type RawFormatter struct {
	logger *log.Logger
}

// NewRawFormatter creates a new raw formatter
func NewRawFormatter(options map[string]any, logger *log.Logger) (*RawFormatter, error) {
	return &RawFormatter{
		logger: logger,
	}, nil
}

// Format returns the message with a newline appended
func (f *RawFormatter) Format(entry source.LogEntry) ([]byte, error) {
	// Simply return the message with newline
	return append([]byte(entry.Message), '\n'), nil
}

// Name returns the formatter name
func (f *RawFormatter) Name() string {
	return "raw"
}