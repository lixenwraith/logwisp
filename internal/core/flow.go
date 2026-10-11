package core

import (
	"encoding/json"
	"strings"
	"sync/atomic"
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

// Tapped is what a pipeline's flow decided about one entry: Stage names the
// stage that dropped Event.Entry (rate_limit, filters at Index, format), or is
// "" when it passed and Event.Payload is what the sinks got.
type Tapped struct {
	Pipeline string
	Source   string // the source's id; "" for a heartbeat
	Stage    string
	Index    int
	Event    TransportEvent
}

// Tap hands Tapped records to a viewer without ever waiting: a full tap drops
// and counts. Unless All is set it takes only what passed, so a strict filter
// cannot crowd those out.
type Tap struct {
	ch    chan Tapped
	All   atomic.Bool
	drops atomic.Uint64
}

func NewTap(size int) *Tap { return &Tap{ch: make(chan Tapped, size)} }

// Offer clips only what it can keep, so a full tap costs the pipeline nothing;
// a reader racing it costs a drop, never a wait
func (t *Tap) Offer(r Tapped) {
	switch {
	case r.Stage != "" && !t.All.Load():
		return
	case len(t.ch) == cap(t.ch):
		t.drops.Add(1)
		return
	}
	e := &r.Event.Entry
	r.Event.Payload = clip(r.Event.Payload, TapEntryBytes)
	e.Message, e.Fields = clip(e.Message, TapEntryBytes), clip(e.Fields, TapEntryBytes)
	e.Level, e.Source, e.Node = clip(e.Level, TapNameBytes), clip(e.Source, TapNameBytes), clip(e.Node, TapNameBytes)
	select {
	case t.ch <- r:
	default:
		t.drops.Add(1)
	}
}

func (t *Tap) Records() <-chan Tapped { return t.ch }

// Dropped counts the records a full tap could not take
func (t *Tap) Dropped() uint64 { return t.drops.Load() }

// clip copies the first n bytes of a longer s, so a kept record does not pin
// its line
func clip[T ~string | ~[]byte](s T, n int) T {
	if len(s) <= n {
		return s
	}
	head := make([]byte, n)
	copy(head, s)
	return T(head)
}

// Level is a level: the words naming it in a line, and the further values a
// level key may hold, which prose would misread ("critical path")
type Level struct {
	Level string   `json:"level"`
	Names []string `json:"names"`
	Keyed []string `json:"-"`
}

// Levels are the entry levels by rising severity: the sources, the console
// sink's painter and the viewer share them
var Levels = []Level{
	{"TRACE", []string{"TRACE"}, []string{"VERBOSE"}},
	{"DEBUG", []string{"DEBUG", "DBG"}, nil},
	{"INFO", []string{"INFO", "INF"}, []string{"I", "NOTICE", "INFORMATION"}},
	{"WARN", []string{"WARN", "WARNING"}, []string{"W"}},
	{"ERROR", []string{"ERROR", "ERR", "FATAL"}, []string{"E", "CRIT", "CRITICAL", "ALERT", "EMERG", "EMERGENCY", "PANIC", "DPANIC"}},
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
