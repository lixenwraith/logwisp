// FILE: src/internal/source/source.go
package source

import (
	"encoding/json"
	"time"
)

// LogEntry represents a single log record
type LogEntry struct {
	Time    time.Time       `json:"time"`
	Source  string          `json:"source"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields,omitempty"`
	RawSize int             `json:"-"`
}

// Source represents an input data stream
type Source interface {
	// Subscribe returns a channel that receives log entries
	Subscribe() <-chan LogEntry

	// Start begins reading from the source
	Start() error

	// Stop gracefully shuts down the source
	Stop()

	// GetStats returns source statistics
	GetStats() SourceStats
}

// SourceStats contains statistics about a source
type SourceStats struct {
	Type           string
	TotalEntries   uint64
	DroppedEntries uint64
	StartTime      time.Time
	LastEntryTime  time.Time
	Details        map[string]any
}

// Helper function for type conversion
func toInt(v any) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	default:
		return 0, false
	}
}