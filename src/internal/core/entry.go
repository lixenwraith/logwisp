// FILE: logwisp/src/internal/core/entry.go
package core

import (
	"encoding/json"
	"time"
)

// Represents a single log record flowing through the pipeline
type LogEntry struct {
	Time    time.Time       `json:"time"`
	Source  string          `json:"source"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields,omitempty"`
	RawSize int64           `json:"-"`
}