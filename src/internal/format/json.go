// FILE: logwisp/src/internal/format/json.go
package format

import (
	"encoding/json"
	"fmt"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// JSONFormatter produces structured JSON logs from LogEntry objects.
type JSONFormatter struct {
	config *config.JSONFormatterOptions
	logger *log.Logger
}

// NewJSONFormatter creates a new JSON formatter from configuration options.
func NewJSONFormatter(opts *config.JSONFormatterOptions, logger *log.Logger) (*JSONFormatter, error) {
	f := &JSONFormatter{
		config: opts,
		logger: logger,
	}

	return f, nil
}

// Format transforms a single LogEntry into a JSON byte slice.
func (f *JSONFormatter) Format(entry core.LogEntry) ([]byte, error) {
	// Start with a clean map
	output := make(map[string]any)

	// First, populate with LogWisp metadata
	output[f.config.TimestampField] = entry.Time.Format(time.RFC3339Nano)
	output[f.config.LevelField] = entry.Level
	output[f.config.SourceField] = entry.Source

	// Try to parse the message as JSON
	var msgData map[string]any
	if err := json.Unmarshal([]byte(entry.Message), &msgData); err == nil {
		// Message is valid JSON - merge fields
		// LogWisp metadata takes precedence
		for k, v := range msgData {
			// Don't overwrite our standard fields
			if k != f.config.TimestampField && k != f.config.LevelField && k != f.config.SourceField {
				output[k] = v
			}
		}

		// If the original JSON had these fields, log that we're overriding
		if _, hasTime := msgData[f.config.TimestampField]; hasTime {
			f.logger.Debug("msg", "Overriding timestamp from JSON message",
				"component", "json_formatter",
				"original", msgData[f.config.TimestampField],
				"logwisp", output[f.config.TimestampField])
		}
	} else {
		// Message is not valid JSON - add as message field
		output[f.config.MessageField] = entry.Message
	}

	// Add any additional fields from LogEntry.Fields
	if len(entry.Fields) > 0 {
		var fields map[string]any
		if err := json.Unmarshal(entry.Fields, &fields); err == nil {
			// Merge additional fields, but don't override existing
			for k, v := range fields {
				if _, exists := output[k]; !exists {
					output[k] = v
				}
			}
		}
	}

	// Marshal to JSON
	var result []byte
	var err error
	if f.config.Pretty {
		result, err = json.MarshalIndent(output, "", "  ")
	} else {
		result, err = json.Marshal(output)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Add newline
	return append(result, '\n'), nil
}

// Name returns the formatter's type name.
func (f *JSONFormatter) Name() string {
	return "json"
}

// FormatBatch transforms a slice of LogEntry objects into a single JSON array byte slice.
func (f *JSONFormatter) FormatBatch(entries []core.LogEntry) ([]byte, error) {
	// For batching, we need to create an array of formatted objects
	batch := make([]json.RawMessage, 0, len(entries))

	for _, entry := range entries {
		// Format each entry without the trailing newline
		formatted, err := f.Format(entry)
		if err != nil {
			f.logger.Warn("msg", "Failed to format entry in batch",
				"component", "json_formatter",
				"error", err)
			continue
		}

		// Remove the trailing newline for array elements
		if len(formatted) > 0 && formatted[len(formatted)-1] == '\n' {
			formatted = formatted[:len(formatted)-1]
		}

		batch = append(batch, formatted)
	}

	// Marshal the entire batch as an array
	var result []byte
	var err error
	if f.config.Pretty {
		result, err = json.MarshalIndent(batch, "", "  ")
	} else {
		result, err = json.Marshal(batch)
	}

	return result, err
}