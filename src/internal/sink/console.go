// FILE: src/internal/sink/console.go
package sink

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// StdoutSink writes log entries to stdout
type StdoutSink struct {
	input     chan source.LogEntry
	writer    *log.Logger
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewStdoutSink creates a new stdout sink
func NewStdoutSink(options map[string]any, logger *log.Logger) (*StdoutSink, error) {
	// Create internal logger for stdout writing
	writer := log.NewLogger()
	if err := writer.InitWithDefaults(
		"enable_stdout=true",
		"disable_file=true",
		"stdout_target=stdout",
		"show_timestamp=false", // We format our own
		"show_level=false",     // We format our own
	); err != nil {
		return nil, fmt.Errorf("failed to initialize stdout writer: %w", err)
	}

	bufferSize := 1000
	if bufSize, ok := toInt(options["buffer_size"]); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	s := &StdoutSink{
		input:     make(chan source.LogEntry, bufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
	}
	s.lastProcessed.Store(time.Time{})

	return s, nil
}

func (s *StdoutSink) Input() chan<- source.LogEntry {
	return s.input
}

func (s *StdoutSink) Start(ctx context.Context) error {
	go s.processLoop(ctx)
	s.logger.Info("msg", "Stdout sink started", "component", "stdout_sink")
	return nil
}

func (s *StdoutSink) Stop() {
	s.logger.Info("msg", "Stopping stdout sink")
	close(s.done)
	s.writer.Shutdown(1 * time.Second)
	s.logger.Info("msg", "Stdout sink stopped")
}

func (s *StdoutSink) GetStats() SinkStats {
	lastProc, _ := s.lastProcessed.Load().(time.Time)

	return SinkStats{
		Type:           "stdout",
		TotalProcessed: s.totalProcessed.Load(),
		StartTime:      s.startTime,
		LastProcessed:  lastProc,
		Details:        map[string]any{},
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

			// Format and write
			timestamp := entry.Time.Format(time.RFC3339Nano)
			level := entry.Level
			if level == "" {
				level = "INFO"
			}

			s.writer.Message(fmt.Sprintf("[%s] %s %s", timestamp, level, entry.Message))

		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}

// StderrSink writes log entries to stderr
type StderrSink struct {
	input     chan source.LogEntry
	writer    *log.Logger
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewStderrSink creates a new stderr sink
func NewStderrSink(options map[string]any, logger *log.Logger) (*StderrSink, error) {
	// Create internal logger for stderr writing
	writer := log.NewLogger()
	if err := writer.InitWithDefaults(
		"enable_stdout=true",
		"disable_file=true",
		"stdout_target=stderr",
		"show_timestamp=false", // We format our own
		"show_level=false",     // We format our own
	); err != nil {
		return nil, fmt.Errorf("failed to initialize stderr writer: %w", err)
	}

	bufferSize := 1000
	if bufSize, ok := toInt(options["buffer_size"]); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	s := &StderrSink{
		input:     make(chan source.LogEntry, bufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
	}
	s.lastProcessed.Store(time.Time{})

	return s, nil
}

func (s *StderrSink) Input() chan<- source.LogEntry {
	return s.input
}

func (s *StderrSink) Start(ctx context.Context) error {
	go s.processLoop(ctx)
	s.logger.Info("msg", "Stderr sink started", "component", "stderr_sink")
	return nil
}

func (s *StderrSink) Stop() {
	s.logger.Info("msg", "Stopping stderr sink")
	close(s.done)
	s.writer.Shutdown(1 * time.Second)
	s.logger.Info("msg", "Stderr sink stopped")
}

func (s *StderrSink) GetStats() SinkStats {
	lastProc, _ := s.lastProcessed.Load().(time.Time)

	return SinkStats{
		Type:           "stderr",
		TotalProcessed: s.totalProcessed.Load(),
		StartTime:      s.startTime,
		LastProcessed:  lastProc,
		Details:        map[string]any{},
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

			// Format and write
			timestamp := entry.Time.Format(time.RFC3339Nano)
			level := entry.Level
			if level == "" {
				level = "INFO"
			}

			s.writer.Message(fmt.Sprintf("[%s] %s %s", timestamp, level, entry.Message))

		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}