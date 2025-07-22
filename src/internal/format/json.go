// FILE: logwisp/src/internal/format/json.go
package format

import (
	"encoding/json"
	"fmt"
	"time"

	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// JSONFormatter produces structured JSON logs
type JSONFormatter struct {
	pretty         bool
	timestampField string
	levelField     string
	messageField   string
	sourceField    string
	logger         *log.Logger
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(options map[string]any, logger *log.Logger) (*JSONFormatter, error) {
	f := &JSONFormatter{
		timestampField: "timestamp",
		levelField:     "level",
		messageField:   "message",
		sourceField:    "source",
		logger:         logger,
	}

	// Extract options
	if pretty, ok := options["pretty"].(bool); ok {
		f.pretty = pretty
	}
	if field, ok := options["timestamp_field"].(string); ok && field != "" {
		f.timestampField = field
	}
	if field, ok := options["level_field"].(string); ok && field != "" {
		f.levelField = field
	}
	if field, ok := options["message_field"].(string); ok && field != "" {
		f.messageField = field
	}
	if field, ok := options["source_field"].(string); ok && field != "" {
		f.sourceField = field
	}

	return f, nil
}

// Format formats the log entry as JSON
func (f *JSONFormatter) Format(entry source.LogEntry) ([]byte, error) {
	// Start with a clean map
	output := make(map[string]any)

	// First, populate with LogWisp metadata
	output[f.timestampField] = entry.Time.Format(time.RFC3339Nano)
	output[f.levelField] = entry.Level
	output[f.sourceField] = entry.Source

	// Try to parse the message as JSON
	var msgData map[string]any
	if err := json.Unmarshal([]byte(entry.Message), &msgData); err == nil {
		// Message is valid JSON - merge fields
		// LogWisp metadata takes precedence
		for k, v := range msgData {
			// Don't overwrite our standard fields
			if k != f.timestampField && k != f.levelField && k != f.sourceField {
				output[k] = v
			}
		}

		// If the original JSON had these fields, log that we're overriding
		if _, hasTime := msgData[f.timestampField]; hasTime {
			f.logger.Debug("msg", "Overriding timestamp from JSON message",
				"component", "json_formatter",
				"original", msgData[f.timestampField],
				"logwisp", output[f.timestampField])
		}
	} else {
		// Message is not valid JSON - add as message field
		output[f.messageField] = entry.Message
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
	if f.pretty {
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

// Name returns the formatter name
func (f *JSONFormatter) Name() string {
	return "json"
}

// FormatBatch formats multiple entries as a JSON array
// This is a special method for sinks that need to batch entries
func (f *JSONFormatter) FormatBatch(entries []source.LogEntry) ([]byte, error) {
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
	if f.pretty {
		result, err = json.MarshalIndent(batch, "", "  ")
	} else {
		result, err = json.Marshal(batch)
	}

	return result, err
}