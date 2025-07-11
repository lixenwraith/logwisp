// FILE: src/internal/sink/sink.go
package sink

import (
	"context"
	"time"

	"logwisp/src/internal/source"
)

// Sink represents an output destination for log entries
type Sink interface {
	// Input returns the channel for sending log entries to this sink
	Input() chan<- source.LogEntry

	// Start begins processing log entries
	Start(ctx context.Context) error

	// Stop gracefully shuts down the sink
	Stop()

	// GetStats returns sink statistics
	GetStats() SinkStats
}

// SinkStats contains statistics about a sink
type SinkStats struct {
	Type              string
	TotalProcessed    uint64
	ActiveConnections int32
	StartTime         time.Time
	LastProcessed     time.Time
	Details           map[string]any
}

// Helper functions for type conversion
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

func toFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	default:
		return 0, false
	}
}