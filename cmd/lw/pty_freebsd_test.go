package main

import (
	"os"
	"syscall"
)

// openPtyMaster opens a new pseudo-terminal's master, as posix_openpt does;
// its terminal needs no unlocking. Non-blocking, the master is read through
// the runtime's poller, so Close ends a read under way.
func openPtyMaster() (*os.File, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_POSIX_OPENPT, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0, 0)
	if errno != 0 {
		return nil, errno
	}
	if err := syscall.SetNonblock(int(fd), true); err != nil {
		syscall.Close(int(fd))
		return nil, err
	}
	return os.NewFile(fd, "/dev/ptmx"), nil
}
