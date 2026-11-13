package file

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/session"

	"github.com/lixenwraith/log"
)

func newSink(t *testing.T, dir string, options map[string]any) *FileSink {
	t.Helper()
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	options["directory"], options["name"] = dir, "out"
	created, err := NewFileSinkPlugin("out", options, log.NewLogger(), session.NewProxy(manager, "out"))
	if err != nil {
		t.Fatal(err)
	}
	return created.(*FileSink)
}

// Entries queued behind one another reach the file whole and in order, those
// past a batch's bound too: the writer keeps each batch it is handed while
// the sink builds the next.
func TestQueuedEntriesReachTheFileWholeAndInOrder(t *testing.T) {
	const n = 5000
	dir := t.TempDir()
	fs := newSink(t, dir, map[string]any{"buffer_size": int64(n)})
	var want []byte
	for i := range n {
		pad := i % 300
		if i%997 == 0 {
			pad = core.SinkWriteBatchBytes + 100
		}
		payload := fmt.Appendf(nil, "line %d %s\n", i, strings.Repeat("x", pad))
		want = append(want, payload...)
		fs.Input() <- core.TransportEvent{Payload: payload}
	}
	// Queued before Start, so the first write finds them all behind it
	if err := fs.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs.Stop()
	got, err := os.ReadFile(filepath.Join(dir, "out.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		at := 0
		for at < min(len(got), len(want)) && got[at] == want[at] {
			at++
		}
		line := bytes.Count(want[:at], []byte{'\n'})
		t.Fatalf("file differs from the entries at byte %d (line %d); %d bytes, want %d", at, line, len(got), len(want))
	}
	if processed := fs.GetStats().TotalProcessed; processed != n {
		t.Fatalf("counted %d entries processed, want %d", processed, n)
	}
}

// A record the writer loses is counted: here a disk that never has the space
// kept free refuses every one, and each batch of the queued entries is a record.
func TestRecordsTheWriterLosesAreCounted(t *testing.T) {
	const n, size = 1000, 100
	dir := t.TempDir()
	fs := newSink(t, dir, map[string]any{"buffer_size": int64(n), "min_disk_free_mb": int64(1) << 40})
	for range n {
		fs.Input() <- core.TransportEvent{Payload: append(bytes.Repeat([]byte{'x'}, size-1), '\n')}
	}
	if err := fs.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs.Stop()
	records := uint64(n / (core.SinkWriteBatchBytes / size))
	if dropped, _ := fs.GetStats().Details["dropped_records"].(uint64); dropped < records {
		t.Fatalf("counted %d records dropped, want at least the %d handed to a full disk", dropped, records)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "out.log")); len(got) > 0 {
		t.Fatalf("a full disk took %d bytes", len(got))
	}
}

// The sink starts only where config.LogDir finds the directory safe, so a
// planted link is never opened
func TestUnsafeLogFileIsRefusedAtStart(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Symlink(target, filepath.Join(dir, "out.log")); err != nil {
		t.Fatal(err)
	}
	fs := newSink(t, dir, map[string]any{})
	if err := fs.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("started through a planted link: %v", err)
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("the link's target was created")
	}
}

// The limits count and delete the sink's own files alone: another program's
// .log file in the directory, older and over max_total_size_mb, stays
func TestTheLimitsDeleteOnlyTheSinksOwnFiles(t *testing.T) {
	dir := t.TempDir()
	other, rotated := filepath.Join(dir, "app.log"), filepath.Join(dir, "out_260101_000000.log")
	for _, p := range []string{other, rotated} {
		if err := os.WriteFile(p, bytes.Repeat([]byte("x\n"), 1<<20), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	fs := newSink(t, dir, map[string]any{"max_total_size_mb": int64(1)})
	if err := fs.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs.Stop()
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another program's file: %v", err)
	}
	if _, err := os.Stat(rotated); err == nil {
		t.Fatal("the sink's own rotated file, over the limit, was kept")
	}
}
