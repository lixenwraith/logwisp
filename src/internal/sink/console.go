// FILE: logwisp/src/internal/sink/console.go
package sink

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"logwisp/src/internal/core"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
)

// ConsoleConfig holds common configuration for console sinks
type ConsoleConfig struct {
	Target     string // "stdout", "stderr", or "split"
	BufferSize int64
}

// StdoutSink writes log entries to stdout
type StdoutSink struct {
	input     chan core.LogEntry
	config    ConsoleConfig
	output    io.Writer
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger
	formatter format.Formatter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewStdoutSink creates a new stdout sink
func NewStdoutSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*StdoutSink, error) {
	config := ConsoleConfig{
		Target:     "stdout",
		BufferSize: 1000,
	}

	// Check for split mode configuration
	if target, ok := options["target"].(string); ok {
		config.Target = target
	}

	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		config.BufferSize = bufSize
	}

	s := &StdoutSink{
		input:     make(chan core.LogEntry, config.BufferSize),
		config:    config,
		output:    os.Stdout,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	s.lastProcessed.Store(time.Time{})

	return s, nil
}

func (s *StdoutSink) Input() chan<- core.LogEntry {
	return s.input
}

func (s *StdoutSink) Start(ctx context.Context) error {
	go s.processLoop(ctx)
	s.logger.Info("msg", "Stdout sink started",
		"component", "stdout_sink",
		"target", s.config.Target)
	return nil
}

func (s *StdoutSink) Stop() {
	s.logger.Info("msg", "Stopping stdout sink")
	close(s.done)
	s.logger.Info("msg", "Stdout sink stopped")
}

func (s *StdoutSink) GetStats() SinkStats {
	lastProc, _ := s.lastProcessed.Load().(time.Time)

	return SinkStats{
		Type:           "stdout",
		TotalProcessed: s.totalProcessed.Load(),
		StartTime:      s.startTime,
		LastProcessed:  lastProc,
		Details: map[string]any{
			"target": s.config.Target,
		},
	}
}

func (s *StdoutSink) processLoop(ctx context.Context) {
	for {
		select {
		case entry, ok := <-s.input:
			if !ok {
				return
			}

			s.totalProcessed.Add(1)
			s.lastProcessed.Store(time.Now())

			// Handle split mode - only process INFO/DEBUG for stdout
			if s.config.Target == "split" {
				upperLevel := strings.ToUpper(entry.Level)
				if upperLevel == "ERROR" || upperLevel == "WARN" || upperLevel == "WARNING" {
					// Skip ERROR/WARN levels in stdout when in split mode
					continue
				}
			}

			// Format and write
			formatted, err := s.formatter.Format(entry)
			if err != nil {
				s.logger.Error("msg", "Failed to format log entry for stdout", "error", err)
				continue
			}
			s.output.Write(formatted)

		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}

// StderrSink writes log entries to stderr
type StderrSink struct {
	input     chan core.LogEntry
	config    ConsoleConfig
	output    io.Writer
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger
	formatter format.Formatter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewStderrSink creates a new stderr sink
func NewStderrSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*StderrSink, error) {
	config := ConsoleConfig{
		Target:     "stderr",
		BufferSize: 1000,
	}

	// Check for split mode configuration
	if target, ok := options["target"].(string); ok {
		config.Target = target
	}

	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		config.BufferSize = bufSize
	}

	s := &StderrSink{
		input:     make(chan core.LogEntry, config.BufferSize),
		config:    config,
		output:    os.Stderr,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	s.lastProcessed.Store(time.Time{})

	return s, nil
}

func (s *StderrSink) Input() chan<- core.LogEntry {
	return s.input
}

func (s *StderrSink) Start(ctx context.Context) error {
	go s.processLoop(ctx)
	s.logger.Info("msg", "Stderr sink started",
		"component", "stderr_sink",
		"target", s.config.Target)
	return nil
}

func (s *StderrSink) Stop() {
	s.logger.Info("msg", "Stopping stderr sink")
	close(s.done)
	s.logger.Info("msg", "Stderr sink stopped")
}

func (s *StderrSink) GetStats() SinkStats {
	lastProc, _ := s.lastProcessed.Load().(time.Time)

	return SinkStats{
		Type:           "stderr",
		TotalProcessed: s.totalProcessed.Load(),
		StartTime:      s.startTime,
		LastProcessed:  lastProc,
		Details: map[string]any{
			"target": s.config.Target,
		},
	}
}

func (s *StderrSink) processLoop(ctx context.Context) {
	for {
		select {
		case entry, ok := <-s.input:
			if !ok {
				return
			}

			s.totalProcessed.Add(1)
			s.lastProcessed.Store(time.Now())

			// Handle split mode - only process ERROR/WARN for stderr
			if s.config.Target == "split" {
				upperLevel := strings.ToUpper(entry.Level)
				if upperLevel != "ERROR" && upperLevel != "WARN" && upperLevel != "WARNING" {
					// Skip non-ERROR/WARN levels in stderr when in split mode
					continue
				}
			}

			// Format and write
			formatted, err := s.formatter.Format(entry)
			if err != nil {
				s.logger.Error("msg", "Failed to format log entry for stderr", "error", err)
				continue
			}
			s.output.Write(formatted)

		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}