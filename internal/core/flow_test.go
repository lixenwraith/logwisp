package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// A line's level is its first whole word, in any case, naming a level, not the
// most severe one named; a wanted level skips the names of the others.
func TestLevelIsTheFirstWordNamingOne(t *testing.T) {
	for _, c := range []struct {
		text, want, level string
		start, end        int
	}{
		{"warning disk full", "", "WARN", 0, 7},
		{"DBG x", "", "DEBUG", 0, 3},
		{"2026-10-05 [Info] retry after error", "", "INFO", 12, 16},
		{`{"level":"fatal","msg":"x"}`, "", "ERROR", 10, 15},
		{"terror informal x_ERR", "", "", 0, 0},
		{"INFO then ERR", "ERROR", "ERROR", 10, 13},
	} {
		level, start, end := LevelWord(c.text, c.want)
		if level != c.level || start != c.start || end != c.end {
			t.Errorf("%q want %q: got %q [%d:%d], want %q [%d:%d]", c.text, c.want, level, start, end, c.level, c.start, c.end)
		}
	}
}

// A tapped record keeps at most TapEntryBytes of an entry's message, fields
// and payload and TapNameBytes of its level, source and node, copied, so a
// viewer's scrollback holds none of the source's line
func TestTapClipsLongEntriesByCopying(t *testing.T) {
	line := strings.Repeat("x", MaxLogEntryBytes)
	payload, fields := []byte(line), json.RawMessage(line)
	tap := NewTap(1, 0)
	tap.Offer(Tapped{Event: TransportEvent{Payload: payload, Entry: LogEntry{Message: line, Fields: fields, Level: line, Source: line, Node: line}}})
	r := <-tap.Records()
	e := r.Event.Entry
	if len(e.Message) != TapEntryBytes || len(e.Fields) != TapEntryBytes || len(r.Event.Payload) != TapEntryBytes {
		t.Fatalf("kept %d, %d and %d bytes, want %d", len(e.Message), len(e.Fields), len(r.Event.Payload), TapEntryBytes)
	}
	if len(e.Level) != TapNameBytes || len(e.Source) != TapNameBytes || len(e.Node) != TapNameBytes {
		t.Fatalf("kept %d, %d and %d bytes of the names, want %d", len(e.Level), len(e.Source), len(e.Node), TapNameBytes)
	}
	for _, s := range []string{e.Message, e.Level, e.Source, e.Node} {
		if unsafe.StringData(s) == unsafe.StringData(line) {
			t.Fatal("a clipped part shares the source's line")
		}
	}
	if &e.Fields[0] == &fields[0] || &r.Event.Payload[0] == &payload[0] {
		t.Fatal("a clipped part shares the source's line")
	}
}

// A full tap drops and counts without copying anything, so a tap nobody
// reads costs a pipeline nothing
func TestAFullTapCostsNothing(t *testing.T) {
	line := strings.Repeat("x", MaxLogEntryBytes)
	tap := NewTap(1, 0)
	rec := Tapped{Event: TransportEvent{Payload: []byte(line), Entry: LogEntry{Message: line, Fields: json.RawMessage(line), Level: line}}}
	tap.Offer(rec)
	if allocs := testing.AllocsPerRun(100, func() { tap.Offer(rec) }); allocs != 0 || tap.Dropped() != 101 {
		t.Fatalf("%v allocations an offer, %d dropped", allocs, tap.Dropped())
	}
}

// A tap with a byte bound queues at most that much clipped text, dropping and
// counting a record past it; a record read and handed back with Took makes
// room again
func TestATapsByteBoundDropsPastItUntilTookMakesRoom(t *testing.T) {
	text := strings.Repeat("x", TapEntryBytes)
	rec := Tapped{Event: TransportEvent{Payload: []byte(text), Entry: LogEntry{Message: text + "cut", Source: "s"}}}
	tap := NewTap(10, 3*(2*TapEntryBytes+1))
	for range 4 {
		tap.Offer(rec)
	}
	queued, dropped := len(tap.Records()), tap.Dropped()
	tap.Took(<-tap.Records())
	tap.Offer(rec)
	if queued != 3 || dropped != 1 || len(tap.Records()) != 3 || tap.Dropped() != 1 {
		t.Fatalf("queued %d and dropped %d, then %d and %d once one was taken; want 3 and 1 both times",
			queued, dropped, len(tap.Records()), tap.Dropped())
	}
}

// A stats time keeps the instant stored, unset is the zero time, and storing
// one per entry allocates nothing
func TestAtomicTimeKeepsTheInstantWithoutAllocating(t *testing.T) {
	var a AtomicTime
	if !a.Load().IsZero() {
		t.Fatalf("unset: %v", a.Load())
	}
	at := time.Date(2026, 11, 13, 1, 2, 3, 456789012, time.UTC)
	a.Store(at)
	if got := a.Load(); !got.Equal(at) {
		t.Fatalf("stored %v, loaded %v", at, got)
	}
	if n := testing.AllocsPerRun(100, func() { a.Store(time.Now()) }); n != 0 {
		t.Fatalf("%v allocations per store", n)
	}
}
