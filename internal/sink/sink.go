package sink

import (
	"context"
	"time"

	"logwisp/internal/core"
)

// Sink represents an output data stream.
type Sink interface {
	// Capabilities returns a slice of supported Source capabilities
	Capabilities() []core.Capability

	// Input returns the channel for sending transport events to this sink.
	Input() chan<- core.TransportEvent

	// Start begins processing transport events.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the sink.
	Stop()

	// GetStats returns sink statistics.
	GetStats() SinkStats
}

// SinkStats contains statistics about a sink.
type SinkStats struct {
	ID                string
	Type              string
	TotalProcessed    uint64
	ActiveConnections int64
	StartTime         time.Time
	LastProcessed     time.Time
	Details           map[string]any
}