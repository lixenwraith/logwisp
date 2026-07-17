package core

import (
	"encoding/json"
	"time"
)

// LogEntry represents a single log record flowing through the pipeline
type LogEntry struct {
	Time    time.Time       `json:"time"`
	Node    string          `json:"node,omitempty"` // origin node identity for chained topologies; first hop stamps, relays preserve
	Source  string          `json:"source"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields,omitempty"`
	RawSize int64           `json:"-"`
}

// TransportEvent contains the final payload and minimal metadata needed by sinks
type TransportEvent struct {
	Time time.Time
	// Formatted, serialized log payload
	Payload []byte
	// Structured entry for re-serializing sinks (chain links). Zero Time => absent
	Entry LogEntry
}

