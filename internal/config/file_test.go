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

// ReadRegular reads a regular file within its limit; a FIFO is refused at
// once, with no writer to wait for, and so is a file over the limit
func TestReadRegularReadsOnlyARegularFileWithinItsLimit(t *testing.T) {
	dir := t.TempDir()
	file, fifo := filepath.Join(dir, "file"), filepath.Join(dir, "fifo")
	if err := os.WriteFile(file, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadRegular(file, 5); err != nil || string(data) != "12345" {
		t.Fatalf("regular file: %q, %v", data, err)
	}
	if _, err := ReadRegular(file, 4); err == nil || !strings.Contains(err.Error(), "over 4") {
		t.Fatalf("over the limit: %v", err)
	}
	if _, err := ReadRegular(fifo, 5); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO: %v", err)
	}
}
