package file

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// A directory the source cannot read is logged when that starts and when it
// ends, not on every check: a missing one at info, as it may yet be made,
// any other failure at warn
func TestUnreadableDirectoryIsLoggedOncePerChange(t *testing.T) {
	logger, out := txtLogger(t)
	dir := filepath.Join(t.TempDir(), "logs")
	source := &FileSource{config: &config.FileSourceOptions{Directory: dir, Pattern: "*"}, watchers: map[string]*fileWatcher{}, logger: logger}
	checksAfter := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
		for range 3 {
			source.checkTargets()
		}
	}
	checksAfter(nil)
	checksAfter(os.Mkdir(dir, 0o700))
	checksAfter(errors.Join(os.Remove(dir), os.WriteFile(dir, nil, 0o600)))
	if err := logger.Flush(time.Second); err != nil {
		t.Fatal(err)
	}
	lines := slices.Collect(strings.Lines(out.String()))
	want := [][2]string{{"INFO", "Waiting for directory"}, {"INFO", "Directory readable"}, {"WARN", "Cannot read directory"}}
	for i, w := range want {
		if len(lines) != len(want) || !strings.Contains(lines[i], " "+w[0]+" ") || !strings.Contains(lines[i], w[1]) {
			t.Fatalf("logged:\n%swant %v", out.String(), want)
		}
	}
}

// A file the source cannot open, from its watcher's start or later, is logged
// as that starts, not on every check, and read once it opens: the watcher goes
// on
func TestUnreadableFileIsLoggedOnceAndWaitedFor(t *testing.T) {
	logger, out := txtLogger(t)
	dir := filepath.Join(t.TempDir(), "logs")
	block := func() error { return errors.Join(os.RemoveAll(dir), os.WriteFile(dir, nil, 0o600)) } // logs/a.log cannot open
	read := make(chan string, 10)
	w := newFileWatcher(filepath.Join(dir, "a.log"), true, true, func(e core.LogEntry) { read <- e.Message }, logger)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	if err := block(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- w.watch(ctx) }()
	time.Sleep(4 * core.FileWatcherPollInterval)
	if err := errors.Join(os.Remove(dir), os.Mkdir(dir, 0o700), os.WriteFile(filepath.Join(dir, "a.log"), []byte("first\n"), 0o600)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-read:
	case <-time.After(time.Second):
		t.Fatal("not read once it opened")
	}
	if err := block(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * core.FileWatcherPollInterval)
	cancel()
	<-done
	if err := logger.Flush(time.Second); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 2 || strings.Count(out.String(), " WARN ") != 2 || strings.Count(out.String(), "Cannot read file") != 2 {
		t.Fatalf("logged:\n%swant Cannot read file twice", out.String())
	}
}

// txtLogger logs txt lines into the buffer it returns, read after Flush
func txtLogger(t *testing.T) (*log.Logger, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	logger := log.NewLogger()
	logger.SetConsoleWriter(out)
	cfg := log.DefaultConfig()
	cfg.Format = "txt"
	if err := logger.ApplyConfig(cfg); err != nil || logger.Start() != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Shutdown() })
	return logger, out
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
// lines around it are read once
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

// lines are log lines stamped with day, from line first up to but not
// including last
func lines(day, first, last int) string {
	var b strings.Builder
	for i := first; i < last; i++ {
		fmt.Fprintf(&b, "Oct %d 00:00:%02d host app[1]: line %d\n", day, i%60, i)
	}
	return b.String()
}

// tailFrom starts a watcher at the file's end; each call of the check it
// returns polls once and gives the messages read
func tailFrom(t *testing.T, path string) func() []string {
	t.Helper()
	var got []string
	w := newFileWatcher(path, true, false, func(e core.LogEntry) { got = append(got, e.Message) }, log.NewLogger())
	if err := w.initPosition(); err != nil {
		t.Fatal(err)
	}
	return func() []string {
		t.Helper()
		got = nil
		if err := w.checkFile(); err != nil {
			t.Fatal(err)
		}
		return got
	}
}

// An edited file is still the file being read, however it is saved and
// wherever lines are deleted or inserted: reading resumes after the last line
// read, or at the end where the edit removed it, and replays nothing
func TestEditedFileResumesAfterTheLastLineRead(t *testing.T) {
	saves := map[string]func(t *testing.T, check func() []string, path, text string){
		"by rename": func(t *testing.T, _ func() []string, path, text string) {
			testutil.WriteFile(t, path+".tmp", text)
			if err := os.Rename(path+".tmp", path); err != nil {
				t.Fatal(err)
			}
		},
		"in place": func(t *testing.T, _ func() []string, path, text string) { testutil.WriteFile(t, path, text) },
		"in place, polled while empty": func(t *testing.T, check func() []string, path, text string) {
			testutil.WriteFile(t, path, "")
			if got := check(); len(got) != 0 {
				t.Fatalf("read %q from the emptied file", got)
			}
			testutil.WriteFile(t, path, text)
		},
		"in place, polled partway": func(t *testing.T, check func() []string, path, text string) {
			testutil.WriteFile(t, path, text[:len(text)/2])
			if got := check(); len(got) != 0 {
				t.Fatalf("read %q from the file half written", got)
			}
			testutil.WriteFile(t, path, text)
		},
	}
	for name, save := range saves {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "messages")
			base := lines(14, 0, 20)
			testutil.WriteFile(t, path, base)
			check := tailFrom(t, path)
			steps := []struct {
				text string
				want []string
			}{
				{base + "ssh in\n", []string{"ssh in"}},
				{base, nil}, // the line read last, deleted
				{base + "after\n", []string{"after"}},
				{lines(14, 0, 15) + lines(14, 16, 20) + "after\nmore\n", []string{"more"}}, // a line before it deleted
				{lines(14, 0, 5) + "inserted\n" + lines(14, 5, 15) + lines(14, 16, 20) + "after\nmore\nagain\n", []string{"again"}},
				{lines(14, 10, 15) + lines(14, 16, 20) + "after\nmore\nagain\nlast\n", []string{"last"}}, // the top trimmed
			}
			for i, step := range steps {
				save(t, check, path, step.text)
				// a missing line read last holds the file for one check, until it settles
				if got := append(check(), check()...); !slices.Equal(got, step.want) {
					t.Fatalf("save %d read %q, want %q", i+1, got, step.want)
				}
			}
		})
	}
}

// A file that starts anew is a rotation: it is read from its start, after the
// entry saying so and once it settles, however it was replaced and whatever
// its size
func TestRotatedFileIsReadFromItsStart(t *testing.T) {
	fresh := lines(15, 0, 3)
	rotations := map[string]func(t *testing.T, check func() []string, path string){
		"truncated and written again": func(t *testing.T, _ func() []string, path string) { testutil.WriteFile(t, path, fresh) },
		"renamed away and made anew": func(t *testing.T, _ func() []string, path string) {
			if err := os.Rename(path, path+".1"); err != nil {
				t.Fatal(err)
			}
			testutil.WriteFile(t, path, fresh)
		},
		"made anew past the position read": func(t *testing.T, _ func() []string, path string) {
			testutil.WriteFile(t, path, fresh+lines(15, 3, 60))
		},
		"emptied, polled, then written": func(t *testing.T, check func() []string, path string) {
			testutil.WriteFile(t, path, "")
			if got := check(); len(got) != 0 {
				t.Fatalf("read %q from the emptied file", got)
			}
			testutil.WriteFile(t, path, fresh)
		},
		// copytruncate under a writer that does not append: it goes on at its
		// offset, past a hole of NULs, which is no entry
		"truncated under a writer at its offset": func(t *testing.T, _ func() []string, path string) {
			testutil.WriteFile(t, path, strings.Repeat("\x00", len(lines(14, 0, 20)))+fresh)
		},
	}
	for name, rotate := range rotations {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "messages")
			testutil.WriteFile(t, path, lines(14, 0, 20))
			check := tailFrom(t, path)
			rotate(t, check, path)
			got := append(check(), check()...)
			want := slices.Collect(strings.Lines(fresh))
			if len(got) < len(want)+1 || !strings.HasPrefix(got[0], "Log rotation detected (#1)") {
				t.Fatalf("read %q, want the rotation entry, then the new file from its start", got)
			}
			for i, line := range want {
				if got[i+1] != strings.TrimSuffix(line, "\n") {
					t.Fatalf("read %q, want the new file from its start", got)
				}
			}
		})
	}
}

// readTo answers only for files the watcher has read: never the inode an
// editor's save freed, and while a check holds a replaced file, the one renamed
// away, not its replacement
func TestReadToAnswersOnlyForFilesRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	inode := func(name string) uint64 {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		return inodeOf(info)
	}
	text := lines(14, 0, 20)
	testutil.WriteFile(t, path, text)
	w := newFileWatcher(path, true, false, func(core.LogEntry) {}, log.NewLogger())
	if err := w.initPosition(); err != nil {
		t.Fatal(err)
	}

	freed := inode(path)
	text += "edited\n"
	testutil.WriteFile(t, path+".tmp", text)
	if err := errors.Join(os.Rename(path+".tmp", path), w.checkFile()); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.readTo(freed); ok {
		t.Error("the inode an editor's save freed is taken for an archive")
	}

	archive := path + ".1"
	if err := os.Rename(path, archive); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, path, "")
	if err := w.checkFile(); err != nil {
		t.Fatal(err)
	}
	if position, ok := w.readTo(inode(archive)); !ok || position != int64(len(text)) {
		t.Errorf("held: the renamed file read to %d, %v; want %d, true", position, ok, len(text))
	}
	if _, ok := w.readTo(inode(path)); ok {
		t.Error("held: the replacement is answered for before it is judged")
	}
}
