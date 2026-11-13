//go:build unix

package config

import "syscall"

// openNonBlock opens a FIFO without waiting for a writer, for ReadRegular to
// refuse
const openNonBlock = syscall.O_NONBLOCK
