// FILE: logwisp/src/internal/source/source.go
package source

import (
	"strings"
	"time"

	"logwisp/src/internal/core"
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

// ExtractLogLevel heuristically determines the log level from a line of text
func ExtractLogLevel(line string) string {
	patterns := []struct {
		patterns []string
		level    string
	}{
		{[]string{"[ERROR]", "ERROR:", " ERROR ", "ERR:", "[ERR]", "FATAL:", "[FATAL]"}, "ERROR"},
		{[]string{"[WARN]", "WARN:", " WARN ", "WARNING:", "[WARNING]"}, "WARN"},
		{[]string{"[INFO]", "INFO:", " INFO ", "[INF]", "INF:"}, "INFO"},
		{[]string{"[DEBUG]", "DEBUG:", " DEBUG ", "[DBG]", "DBG:"}, "DEBUG"},
		{[]string{"[TRACE]", "TRACE:", " TRACE "}, "TRACE"},
	}

	upperLine := strings.ToUpper(line)
	for _, group := range patterns {
		for _, pattern := range group.patterns {
			if strings.Contains(upperLine, pattern) {
				return group.level
			}
		}
	}

	return ""
}