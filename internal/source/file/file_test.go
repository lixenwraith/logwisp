package file

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
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

// A rotated file reappears under its archive name with the same inode. Its
// replacement watcher resumes where the original stopped, so a `from = "start"`
// source does not re-emit every record the file already delivered.
func TestRotatedFileResumesInsteadOfReplaying(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(active, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(active)
	if err != nil {
		t.Fatal(err)
	}
	inode := info.Sys().(*syscall.Stat_t).Ino

	archive := filepath.Join(dir, "session_260916_120000.jsonl")
	if err := os.Rename(active, archive); err != nil {
		t.Fatal(err)
	}

	for name, watcher := range map[string]*fileWatcher{
		"still tailing the renamed inode": {inode: inode, position: 8},
		"already moved on from it":        {inode: 99, prevInode: inode, prevPosition: 8},
	} {
		source := &FileSource{watchers: map[string]*fileWatcher{active: watcher}}
		position, ok := source.readPosition(archive)
		if !ok || position != 8 {
			t.Errorf("%s: position = %d, ok = %v, want 8, true", name, position, ok)
		}
	}

	unrelated := &FileSource{watchers: map[string]*fileWatcher{active: {inode: 99}}}
	if _, ok := unrelated.readPosition(archive); ok {
		t.Error("a file no watcher has read was treated as rotated")
	}
}
