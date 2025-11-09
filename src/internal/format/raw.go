// FILE: logwisp/src/internal/format/raw.go
package format

import (
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// RawFormatter outputs the raw log message, optionally with a newline.
type RawFormatter struct {
	config *config.RawFormatterOptions
	logger *log.Logger
}

// NewRawFormatter creates a new raw pass-through formatter.
func NewRawFormatter(opts *config.RawFormatterOptions, logger *log.Logger) (*RawFormatter, error) {
	return &RawFormatter{
		config: opts,
		logger: logger,
	}, nil
}

// Format returns the raw message from the LogEntry as a byte slice.
func (f *RawFormatter) Format(entry core.LogEntry) ([]byte, error) {
	if f.config.AddNewLine {
		return append([]byte(entry.Message), '\n'), nil // Add back the trimmed new line
	} else {
		return []byte(entry.Message), nil // New line between log entries are trimmed
	}
}

// Name returns the formatter's type name.
func (f *RawFormatter) Name() string {
	return "raw"
}