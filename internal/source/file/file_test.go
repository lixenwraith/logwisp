package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"logwisp/internal/core"
)

func TestStoppedWatcherReturnsNormally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	watcher := newFileWatcher(path, true, true, func(_ core.LogEntry) {}, nil)
	watcher.stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := watcher.watch(ctx); err != nil {
		t.Fatalf("stopped watcher returned error: %v", err)
	}
}

func TestRemoveWatcherPreservesReplacement(t *testing.T) {
	oldWatcher := &fileWatcher{}
	replacement := &fileWatcher{}
	source := &FileSource{
		watchers: map[string]*fileWatcher{
			"session.jsonl": replacement,
		},
	}

	source.removeWatcher("session.jsonl", oldWatcher)
	if got := source.watchers["session.jsonl"]; got != replacement {
		t.Fatalf("replacement watcher = %p, want %p", got, replacement)
	}

	source.removeWatcher("session.jsonl", replacement)
	if _, exists := source.watchers["session.jsonl"]; exists {
		t.Fatal("finished watcher was not removed")
	}
}
