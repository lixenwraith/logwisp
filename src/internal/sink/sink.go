// FILE: logwisp/src/internal/sink/sink.go
package sink

import (
	"context"
	"time"

	"logwisp/src/internal/core"
)

// Represents an output data stream
type Sink interface {
	// Returns the channel for sending log entries to this sink
	Input() chan<- core.LogEntry

	// Begins processing log entries
	Start(ctx context.Context) error

	// Gracefully shuts down the sink
	Stop()

	// Returns sink statistics
	GetStats() SinkStats
}

// Contains statistics about a sink
type SinkStats struct {
	Type              string
	TotalProcessed    uint64
	ActiveConnections int64
	StartTime         time.Time
	LastProcessed     time.Time
	Details           map[string]any
}