// FILE: logwisp/src/cmd/logwisp/output.go
package main

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// OutputHandler manages all application output, respecting the global quiet mode.
type OutputHandler struct {
	quiet  bool
	mu     sync.RWMutex
	stdout io.Writer
	stderr io.Writer
}

// output is the global instance of the OutputHandler.
var output *OutputHandler

// InitOutputHandler initializes the global output handler.
func InitOutputHandler(quiet bool) {
	output = &OutputHandler{
		quiet:  quiet,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
}

// Print writes to stdout.
func Print(format string, args ...any) {
	if output != nil {
		output.Print(format, args...)
	}
}

// Error writes to stderr.
func Error(format string, args ...any) {
	if output != nil {
		output.Error(format, args...)
	}
}

// FatalError writes to stderr and exits the application.
func FatalError(code int, format string, args ...any) {
	if output != nil {
		output.FatalError(code, format, args...)
	} else {
		// Fallback if handler not initialized
		fmt.Fprintf(os.Stderr, format, args...)
		os.Exit(code)
	}
}

// Print writes a formatted string to stdout if not in quiet mode.
func (o *OutputHandler) Print(format string, args ...any) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.quiet {
		fmt.Fprintf(o.stdout, format, args...)
	}
}

// Error writes a formatted string to stderr if not in quiet mode.
func (o *OutputHandler) Error(format string, args ...any) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.quiet {
		fmt.Fprintf(o.stderr, format, args...)
	}
}

// FatalError writes a formatted string to stderr and exits with the given code.
func (o *OutputHandler) FatalError(code int, format string, args ...any) {
	o.Error(format, args...)
	os.Exit(code)
}

// IsQuiet returns the current quiet mode status.
func (o *OutputHandler) IsQuiet() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.quiet
}

// SetQuiet updates the quiet mode status.
func (o *OutputHandler) SetQuiet(quiet bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.quiet = quiet
}