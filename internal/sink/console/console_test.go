package console

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/session"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/terminal/inline"
)

// Each mark is painted in its kind's style, a level in its level's, one
// without a style (PROC) left plain; the text between marks stays as written.
func TestPaintStylesEachMarkAndKeepsTheText(t *testing.T) {
	p := inline.New(io.Discard)
	p.SetColor(true)
	grey, red, magenta, cyan := "\x1b[0;90m", "\x1b[0;1;31m", "\x1b[0;35m", "\x1b[0;36m"
	end := "\x1b[0m"
	for _, c := range []struct {
		in    string
		entry core.LogEntry
		want  string
	}{
		{"2026-11-05T07:51:43Z ERROR app \"disk full\" dev=sda\n", core.LogEntry{Level: "ERROR", Source: "app"},
			grey + "2026-11-05T07:51:43Z" + end + " " + red + "ERROR" + end + " " + magenta + "app" + end + " \"disk full\" " + cyan + "dev" + end + grey + "=" + end + "sda\n"},
		{"{\"level\":\"PROC\"}\n", core.LogEntry{Level: "PROC"},
			grey + "{" + end + cyan + "\"level\"" + end + grey + ":" + end + "\"PROC\"" + grey + "}" + end + "\n"},
	} {
		if got := string(newPalette(p).paint(nil, []byte(c.in), c.entry)); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// A failed write counts the entries it lost, and is logged once until its
// error changes: a hung-up terminal or a full disk fails every write
func TestWriteFailuresAreCountedAndLoggedOncePerError(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	var logged lockedLog
	logger := log.NewLogger()
	logger.SetConsoleWriter(&logged)
	if err := logger.ApplyConfigString("level=info"); err != nil {
		t.Fatal(err)
	}
	if err := logger.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Shutdown() })
	created, err := NewConsoleSinkPlugin("out", map[string]any{"target": "stdout"}, logger, session.NewProxy(manager, "out"))
	if err != nil {
		t.Fatal(err)
	}
	cs := created.(*ConsoleSink)
	cs.output = failingWriter{}
	for i := range 3 {
		cs.write(core.TransportEvent{Payload: []byte{'a' + byte(i), '\n'}})
	}
	if err := logger.Flush(time.Second); err != nil {
		t.Fatal(err)
	}
	if n, logs := cs.GetStats().Details["write_errors"], strings.Count(logged.String(), "Failed to write to console"); n != uint64(3) || logs != 1 {
		t.Fatalf("%v write errors counted, %d logged; want 3 and 1", n, logs)
	}
}

// Stop waits on a stalled output at most core.SinkFlushTimeout, then leaves
// the queue: the write in progress ends when it can, and nothing follows it
func TestStopLeavesAStalledOutputAfterTheFlushBound(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewConsoleSinkPlugin("out", map[string]any{"target": "stdout"}, log.NewLogger(), session.NewProxy(manager, "out"))
	if err != nil {
		t.Fatal(err)
	}
	cs := created.(*ConsoleSink)
	out := &stalledWriter{entered: make(chan struct{}, 1), release: make(chan struct{})}
	cs.output = out
	if err := cs.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	cs.Input() <- core.TransportEvent{Payload: []byte("a\n")}
	<-out.entered
	cs.Input() <- core.TransportEvent{Payload: []byte("b\n")}

	// A Stop that waits for the output fails here rather than hanging
	release := time.AfterFunc(core.SinkFlushTimeout+2*time.Second, func() { close(out.release) })
	start := time.Now()
	cs.Stop()
	took := time.Since(start)
	if release.Stop() {
		close(out.release)
	}
	<-cs.exited
	if took < core.SinkFlushTimeout || took > core.SinkFlushTimeout+time.Second || out.writes.Load() != 1 {
		t.Fatalf("Stop took %v and the output saw %d writes; want %v and 1", took, out.writes.Load(), core.SinkFlushTimeout)
	}
}

// stalledWriter holds every write until release closes
type stalledWriter struct {
	entered, release chan struct{}
	writes           atomic.Int32
}

func (w *stalledWriter) Write(p []byte) (int, error) {
	w.writes.Add(1)
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	return len(p), nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, syscall.EIO }

type lockedLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
