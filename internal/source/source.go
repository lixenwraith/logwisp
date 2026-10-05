package source

import (
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
)

// Source represents an input data stream for log entries
type Source interface {
	// Capabilities returns a slice of supported Source capabilities
	Capabilities() []core.Capability

	// Subscribe returns a channel that receives log entries from the source
	Subscribe() <-chan core.LogEntry

	// Start begins reading from the source
	Start() error

	// Stop gracefully shuts down the source
	Stop()

	// SourceStats contains statistics about a source
	GetStats() SourceStats
}

// SourceStats contains statistics about a source
type SourceStats struct {
	ID             string
	Type           string
	TotalEntries   uint64
	DroppedEntries uint64
	StartTime      time.Time
	LastEntryTime  time.Time
	Details        map[string]any
}

// ExtractLogLevel returns the level the first word naming one marks, or ""
func ExtractLogLevel(line string) string {
	level, _, _ := core.LevelWord(line, "")
	return level
}
