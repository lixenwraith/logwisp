package core

import (
	"encoding/json"
	"strings"
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

// Levels are the entry levels by rising severity, each with the words naming
// it in a line: the sources, the console sink's painter and the viewer share them
var Levels = []struct {
	Level string   `json:"level"`
	Names []string `json:"names"`
}{
	{"TRACE", []string{"TRACE"}},
	{"DEBUG", []string{"DEBUG", "DBG"}},
	{"INFO", []string{"INFO", "INF"}},
	{"WARN", []string{"WARN", "WARNING"}},
	{"ERROR", []string{"ERROR", "ERR", "FATAL"}},
}

// LevelWord finds the first whole word of text, in any case, that names a
// level, or names want when it is set; it returns the level and the word's
// bounds, and "" when no word does.
func LevelWord[T string | []byte](text T, want string) (level string, start, end int) {
	for i := 0; i < len(text); i = end {
		for i < len(text) && !wordByte(text[i]) {
			i++
		}
		for end = i; end < len(text) && wordByte(text[end]); end++ {
		}
		for _, l := range Levels {
			for _, name := range l.Names {
				if end-i == len(name) && (want == "" || want == l.Level) && strings.EqualFold(string(text[i:end]), name) {
					return l.Level, i, end
				}
			}
		}
	}
	return "", 0, 0
}

func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
