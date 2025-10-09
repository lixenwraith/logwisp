// FILE: logwisp/src/internal/format/raw.go
package format

import (
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Outputs the log message as-is with a newline
type RawFormatter struct {
	config *config.RawFormatterOptions
	logger *log.Logger
}

// Creates a new raw formatter
func NewRawFormatter(cfg *config.RawFormatterOptions, logger *log.Logger) (*RawFormatter, error) {
	return &RawFormatter{
		config: cfg,
		logger: logger,
	}, nil
}

// Returns the message with a newline appended
func (f *RawFormatter) Format(entry core.LogEntry) ([]byte, error) {
	// TODO: Standardize not to add "\n" when processing raw, check lixenwraith/log for consistency
	if f.config.AddNewLine {
		return append([]byte(entry.Message), '\n'), nil
	} else {
		return []byte(entry.Message), nil
	}
}

// Returns the formatter name
func (f *RawFormatter) Name() string {
	return "raw"
}