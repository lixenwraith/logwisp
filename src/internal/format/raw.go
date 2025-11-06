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
func NewRawFormatter(cfg *config.RawFormatterOptions, logger *log.Logger) (*RawFormatter, error) {
	return &RawFormatter{
		config: cfg,
		logger: logger,
	}, nil
}

// Format returns the raw message from the LogEntry as a byte slice.
func (f *RawFormatter) Format(entry core.LogEntry) ([]byte, error) {
	// TODO: Standardize not to add "\n" when processing raw, check lixenwraith/log for consistency
	if f.config.AddNewLine {
		return append([]byte(entry.Message), '\n'), nil
	} else {
		return []byte(entry.Message), nil
	}
}

// Name returns the formatter's type name.
func (f *RawFormatter) Name() string {
	return "raw"
}