package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteNew writes data to a file it creates, mode as given: it never replaces
// a file, and removes what it created when the write fails
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// LogDir readies dir for a writer appending to file there, creating what is
// missing as 0750. It refuses a directory every user can write, where another
// could plant file as a link to what lw may write, and a file that is not a
// regular one: the writer's first open follows a link and waits on a FIFO.
func LogDir(dir, file string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s is writable by every user: refusing to write %s there (chmod o-w)", dir, file)
	}
	path := filepath.Join(dir, file)
	switch info, err := os.Lstat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !info.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (%v): refusing to write through it", path, info.Mode())
	}
	return nil
}
