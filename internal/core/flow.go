// Package core holds what the parts of a pipeline share: the LogEntry and the
// TransportEvent sinks get, the Tap a viewer reads a flow's decisions from,
// the level names, plugin capabilities, size limits and timings, and Network
// and Listen, which keep a listener or dialer to its host's address family.
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

// Label is the entry's source as formats write it, prefixed with its origin
// node as syslog prefixes a tag with the host
func (e LogEntry) Label() string {
	if e.Node == "" {
		return e.Source
	}
	return e.Node + "/" + e.Source
}

// TransportEvent contains the final payload and minimal metadata needed by sinks
type TransportEvent struct {
	Time time.Time
	// Formatted, serialized log payload
	Payload []byte
	// Structured entry for re-serializing sinks (chain links). Zero Time => absent
	Entry LogEntry
}

// AtomicTime is a time stats report, such as a plugin's last entry: stored
// and loaded atomically, without the allocation each store of a time.Time in
// an atomic.Value costs. It keeps the years 1678 to 2262; zero is unset.
type AtomicTime struct{ ns atomic.Int64 }

func (a *AtomicTime) Store(t time.Time) { a.ns.Store(t.UnixNano()) }

// Load returns the time last stored, or the zero time when none was
func (a *AtomicTime) Load() time.Time {
	if ns := a.ns.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// Tapped is what a pipeline's flow decided about one entry: Stage names the
// stage that dropped Event.Entry (rate_limit, filters at Index, format), or is
// "" when it passed and Event.Payload is what dispatch offered the sinks; a
// full sink input drops it for that sink only.
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
	held  atomic.Int64 // the bytes of the records queued, which Took hands back
	limit int64        // what held may reach; 0 bounds only the count
}

// NewTap holds up to records records and, when bytes is set, up to bytes of
// their text: a viewer reads a tick's bytes, so a count alone would queue
// long lines far past what it shows
func NewTap(records, bytes int) *Tap {
	return &Tap{ch: make(chan Tapped, records), limit: int64(bytes)}
}

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
	n := r.size()
	if held := t.held.Add(n); t.limit > 0 && held > t.limit {
		t.held.Add(-n)
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
		t.held.Add(-n)
		t.drops.Add(1)
	}
}

// Records are the records queued; a reader hands each one's bytes back with
// Took
func (t *Tap) Records() <-chan Tapped { return t.ch }

// Took hands back the bytes of a record read from Records
func (t *Tap) Took(r Tapped) { t.held.Add(-r.size()) }

// size is the text r holds once Offer clips it
func (r *Tapped) size() int64 {
	e := &r.Event.Entry
	return int64(min(len(r.Event.Payload), TapEntryBytes) + min(len(e.Message), TapEntryBytes) +
		min(len(e.Fields), TapEntryBytes) + min(len(e.Level), TapNameBytes) +
		min(len(e.Source), TapNameBytes) + min(len(e.Node), TapNameBytes))
}

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
		if n := end - i; n == 0 || n >= 64 || nameLens&(1<<n) == 0 || !nameFirst[text[i]] {
			continue
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

// nameLens has bit n set when a level name is n bytes long, and nameFirst
// holds the bytes, in either case, a name begins with: a word failing either
// names no level, so LevelWord skips it without walking Levels
var nameLens, nameFirst = func() (lens uint64, first [256]bool) {
	for _, l := range Levels {
		for _, n := range l.Names {
			lens |= 1 << len(n)
			first[n[0]|0x20], first[n[0]&^0x20] = true, true
		}
	}
	return lens, first
}()

func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
