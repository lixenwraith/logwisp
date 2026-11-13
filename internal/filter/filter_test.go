package filter

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/log"
)

// lockedBuffer is written by the logger's goroutine and read by the test
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startedLogger(t *testing.T, level string, w io.Writer) *log.Logger {
	t.Helper()
	logger := log.NewLogger()
	logger.SetConsoleWriter(w)
	if err := logger.ApplyConfigString("level=" + level); err != nil {
		t.Fatal(err)
	}
	if err := logger.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Shutdown() })
	return logger
}

// sixteen patterns, the first matching the entry below
func patterns() []string {
	p := []string{"ERROR"}
	for i := range 15 {
		p = append(p, fmt.Sprintf("never%d", i))
	}
	return p
}

var entry = core.LogEntry{Source: "app.log", Level: "ERROR", Message: "disk full"}

// Below DEBUG an entry costs its match text: the report, which matches every
// pattern again and allocates for each, does not run
func TestApplyBelowDebugSkipsTheReport(t *testing.T) {
	f, err := NewFilter(config.FilterConfig{Type: "include", Logic: "or", Patterns: patterns()}, startedLogger(t, "info", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if !f.apply(entry, matchText(entry)) {
		t.Fatal("an entry matching the first pattern was dropped")
	}
	if allocs := testing.AllocsPerRun(100, func() { f.apply(entry, matchText(entry)) }); allocs >= float64(len(f.patterns)) {
		t.Fatalf("%v allocations per entry for %d patterns", allocs, len(f.patterns))
	}
}

// The debug report names no entry text: an exclude filter is how a secret is
// kept out of the output, and lw's own log must not carry it either
func TestDebugReportNamesNoEntryText(t *testing.T) {
	var out lockedBuffer
	logger := startedLogger(t, "debug", &out)
	f, err := NewFilter(config.FilterConfig{Type: "exclude", Logic: "or", Patterns: []string{"password"}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	secret := core.LogEntry{Source: "auth.log", Level: "INFO", Message: "login user=alice password=hunter2"}
	if f.apply(secret, matchText(secret)) {
		t.Fatal("an excluded entry passed")
	}
	if err := logger.Flush(time.Second); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "Filter decision") || strings.Contains(got, "hunter2") {
		t.Fatalf("debug report:\n%s", got)
	}
}

// At DEBUG the report still names every pattern's result, and the decision
func TestApplyAtDebugReportsEachPattern(t *testing.T) {
	var out lockedBuffer
	logger := startedLogger(t, "debug", &out)
	f, err := NewFilter(config.FilterConfig{Type: "include", Logic: "or", Patterns: patterns()}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if !f.apply(entry, matchText(entry)) {
		t.Fatal("an entry matching the first pattern was dropped")
	}
	if err := logger.Flush(time.Second); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if n := strings.Count(got, "Pattern match result"); n != len(f.patterns) || !strings.Contains(got, "Filter decision") {
		t.Fatalf("%d pattern results for %d patterns, decision reported: %v:\n%s",
			n, len(f.patterns), strings.Contains(got, "Filter decision"), got)
	}
}
