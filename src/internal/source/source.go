// FILE: logwisp/src/internal/source/source.go
package source

import (
	"time"

	"logwisp/src/internal/core"
)

// Represents an input data stream
type Source interface {
	// Returns a channel that receives log entries
	Subscribe() <-chan core.LogEntry

	// Begins reading from the source
	Start() error

	// Gracefully shuts down the source
	Stop()

	// Returns source statistics
	GetStats() SourceStats
}

// Contains statistics about a source
type SourceStats struct {
	Type           string
	TotalEntries   uint64
	DroppedEntries uint64
	StartTime      time.Time
	LastEntryTime  time.Time
	Details        map[string]any
}