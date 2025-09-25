// FILE: logwisp/src/internal/sink/sink.go
package sink

import (
	"context"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
)

// Represents an output destination for log entries
type Sink interface {
	// Input returns the channel for sending log entries to this sink
	Input() chan<- core.LogEntry

	// Start begins processing log entries
	Start(ctx context.Context) error

	// Stop gracefully shuts down the sink
	Stop()

	// GetStats returns sink statistics
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

// Interface for sinks that can accept an AuthConfig
type AuthSetter interface {
	SetAuthConfig(auth *config.AuthConfig)
}