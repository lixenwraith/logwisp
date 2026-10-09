package file

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/testutil"

	"github.com/lixenwraith/log"
)

// A file source never follows the file lw's stdout or stderr is: `lw > out.log`
// in the directory it follows would read its own output back, endlessly
func TestFileSourceSkipsItsOwnOutput(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "app.log"), "")
	testutil.WriteFile(t, filepath.Join(dir, "out.log"), "")
	own, err := os.Stat(filepath.Join(dir, "out.log"))
	if err != nil {
		t.Fatal(err)
	}
	source := &FileSource{
		config:     &config.FileSourceOptions{Directory: dir, Pattern: "*.log"},
		own:        []os.FileInfo{own},
		ownSkipped: map[string]bool{},
		logger:     log.NewLogger(),
	}
	files, err := source.scanFile()
	if err != nil || len(files) != 1 || filepath.Base(files[0]) != "app.log" {
		t.Fatalf("scanFile = %v, %v; want app.log alone", files, err)
	}
}

func TestStoppedWatcherReturnsNormally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	testutil.WriteFile(t, path, "")
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

// A line longer than core.MaxLogEntryBytes continues in the next entry, and the
// lines around it are read once: the watcher used to stop at it for good
func TestLongLineContinuesInTheNextEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	long := strings.Repeat("x", core.MaxLogEntryBytes+10)
	testutil.WriteFile(t, path, "first\n"+long+"\nafter\n")
	var got []string
	w := newFileWatcher(path, true, true, func(e core.LogEntry) { got = append(got, e.Message) }, log.NewLogger())
	for range 2 {
		if err := w.checkFile(); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"first", long[:core.MaxLogEntryBytes], long[core.MaxLogEntryBytes:], "after"}
	if !slices.Equal(got, want) {
		t.Fatalf("read %d entries, want %d: first, the long line in two, after", len(got), len(want))
	}
}

// A rotated file reappears under its archive name with the same inode. Its
// replacement watcher resumes where the original stopped, so a `from = "start"`
// source does not re-emit every record the file already delivered.
func TestRotatedFileResumesInsteadOfReplaying(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "session.jsonl")
	testutil.WriteFile(t, active, "one\ntwo\n")
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
