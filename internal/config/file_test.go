package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The directories LogDir creates are closed to other users
func TestLogDirIsCreatedClosedToOtherUsers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := LogDir(dir, "out.log"); err != nil {
		t.Fatal(err)
	}
	for d := dir; d != filepath.Dir(filepath.Dir(dir)); d = filepath.Dir(d) {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o027 != 0 {
			t.Errorf("%s created %v, want at most 0750", d, perm)
		}
	}
}

// A directory every user can write is refused, sticky or not: another user
// could plant the file there as a link before the writer opens it
func TestLogDirEveryUserCanWriteIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o777 | os.ModeSticky} {
		dir := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := LogDir(dir, "out.log"); err == nil || !strings.Contains(err.Error(), "writable by every user") {
			t.Errorf("%v directory: %v", mode, err)
		}
	}
}

// A log file that is a link, a FIFO or a directory is refused, and a regular
// one is kept
func TestLogFileThatIsNotARegularFileIsRefused(t *testing.T) {
	for _, c := range []struct {
		kind string
		make func(path string) error
	}{
		{"link", func(path string) error { return os.Symlink(filepath.Join(filepath.Dir(path), "target"), path) }},
		{"fifo", func(path string) error { return syscall.Mkfifo(path, 0o600) }},
		{"directory", func(path string) error { return os.Mkdir(path, 0o700) }},
		{"regular", func(path string) error { return os.WriteFile(path, nil, 0o600) }},
	} {
		dir := t.TempDir()
		if err := c.make(filepath.Join(dir, "out.log")); err != nil {
			t.Fatal(err)
		}
		err := LogDir(dir, "out.log")
		if refused := err != nil && strings.Contains(err.Error(), "not a regular file"); refused != (c.kind != "regular") {
			t.Errorf("out.log as a %s: %v", c.kind, err)
		}
	}
}
