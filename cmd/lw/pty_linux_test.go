package main

import (
	"os"
	"syscall"
	"unsafe"
)

// openPtyMaster opens a new pseudo-terminal's master and unlocks its
// terminal, as posix_openpt and unlockpt do
func openPtyMaster() (*os.File, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	var locked int32
	if err := ioctl(m, syscall.TIOCSPTLCK, unsafe.Pointer(&locked)); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}
