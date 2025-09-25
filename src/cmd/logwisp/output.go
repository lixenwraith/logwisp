// FILE: logwisp/src/cmd/logwisp/output.go
package main

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Manages all application output respecting quiet mode
type OutputHandler struct {
	quiet  bool
	mu     sync.RWMutex
	stdout io.Writer
	stderr io.Writer
}

// Global output handler instance
var output *OutputHandler

// Initializes the global output handler
func InitOutputHandler(quiet bool) {
	output = &OutputHandler{
		quiet:  quiet,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
}

// Writes to stdout if not in quiet mode
func (o *OutputHandler) Print(format string, args ...any) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.quiet {
		fmt.Fprintf(o.stdout, format, args...)
	}
}

// Writes to stderr if not in quiet mode
func (o *OutputHandler) Error(format string, args ...any) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if !o.quiet {
		fmt.Fprintf(o.stderr, format, args...)
	}
}

// Writes to stderr and exits (respects quiet mode)
func (o *OutputHandler) FatalError(code int, format string, args ...any) {
	o.Error(format, args...)
	os.Exit(code)
}

// Returns the current quiet mode status
func (o *OutputHandler) IsQuiet() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.quiet
}

// Updates quiet mode (useful for testing)
func (o *OutputHandler) SetQuiet(quiet bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.quiet = quiet
}

// Helper functions for global output handler
func Print(format string, args ...any) {
	if output != nil {
		output.Print(format, args...)
	}
}

func Error(format string, args ...any) {
	if output != nil {
		output.Error(format, args...)
	}
}

func FatalError(code int, format string, args ...any) {
	if output != nil {
		output.FatalError(code, format, args...)
	} else {
		// Fallback if handler not initialized
		fmt.Fprintf(os.Stderr, format, args...)
		os.Exit(code)
	}
}