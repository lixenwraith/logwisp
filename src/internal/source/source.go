// FILE: logwisp/src/internal/source/source.go
package source

import (
	"time"

	"logwisp/src/internal/core"
)

// Source represents an input data stream for log entries.
type Source interface {
	// Subscribe returns a channel that receives log entries from the source.
	Subscribe() <-chan core.LogEntry

	// Start begins reading from the source.
	Start() error

	// Stop gracefully shuts down the source.
	Stop()

	// SourceStats contains statistics about a source.
	GetStats() SourceStats
}

// SourceStats contains statistics about a source.
type SourceStats struct {
	Type           string
	TotalEntries   uint64
	DroppedEntries uint64
	StartTime      time.Time
	LastEntryTime  time.Time
	Details        map[string]any
}