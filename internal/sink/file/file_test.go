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
