// FILE: logwisp/src/internal/sink/console.go
package sink

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
)

// ConsoleSink writes log entries to the console (stdout/stderr) using an dedicated logger instance
type ConsoleSink struct {
	config    *config.ConsoleSinkOptions
	input     chan core.LogEntry
	writer    *log.Logger // Dedicated internal logger instance for console writing
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger // Application logger for app logs
	formatter format.Formatter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// Creates a new console sink
func NewConsoleSink(opts *config.ConsoleSinkOptions, appLogger *log.Logger, formatter format.Formatter) (*ConsoleSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("console sink options cannot be nil")
	}

	// Set defaults if not configured
	if opts.Target == "" {
		opts.Target = "stdout"
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 1000
	}

	// Dedicated logger instance as console writer
	writer, err := log.NewBuilder().
		EnableFile(false).
		EnableConsole(true).
		ConsoleTarget(opts.Target).
		Format("raw").        // Passthrough pre-formatted messages
		ShowTimestamp(false). // Disable writer's own timestamp
		ShowLevel(false).     // Disable writer's own level prefix
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create console writer: %w", err)
	}

	s := &ConsoleSink{
		config:    opts,
		input:     make(chan core.LogEntry, opts.BufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    appLogger,
		formatter: formatter,
	}
	s.lastProcessed.Store(time.Time{})

	return s, nil
}

func (s *ConsoleSink) Input() chan<- core.LogEntry {
	return s.input
}

func (s *ConsoleSink) Start(ctx context.Context) error {
	// Start the internal writer's processing goroutine.
	if err := s.writer.Start(); err != nil {
		return fmt.Errorf("failed to start console writer: %w", err)
	}
	go s.processLoop(ctx)
	s.logger.Info("msg", "Console sink started",
		"component", "console_sink",
		"target", s.writer.GetConfig().ConsoleTarget)
	return nil
}

func (s *ConsoleSink) Stop() {
	target := s.writer.GetConfig().ConsoleTarget
	s.logger.Info("msg", "Stopping console sink", "target", target)
	close(s.done)

	// Shutdown the internal writer with a timeout.
	if err := s.writer.Shutdown(2 * time.Second); err != nil {
		s.logger.Error("msg", "Error shutting down console writer",
			"component", "console_sink",
			"error", err)
	}
	s.logger.Info("msg", "Console sink stopped", "target", target)
}

func (s *ConsoleSink) GetStats() SinkStats {
	lastProc, _ := s.lastProcessed.Load().(time.Time)

	return SinkStats{
		Type:           "console",
		TotalProcessed: s.totalProcessed.Load(),
		StartTime:      s.startTime,
		LastProcessed:  lastProc,
		Details: map[string]any{
			"target": s.writer.GetConfig().ConsoleTarget,
		},
	}
}

// processLoop reads entries, formats them, and passes them to the internal writer.
func (s *ConsoleSink) processLoop(ctx context.Context) {
	for {
		select {
		case entry, ok := <-s.input:
			if !ok {
				return
			}

			s.totalProcessed.Add(1)
			s.lastProcessed.Store(time.Now())

			// Format the entry using the pipeline's configured formatter.
			formatted, err := s.formatter.Format(entry)
			if err != nil {
				s.logger.Error("msg", "Failed to format log entry for console",
					"component", "console_sink",
					"error", err)
				continue
			}

			// Convert to string to prevent hex encoding of []byte by log package
			// Strip new line, writer adds it
			message := string(bytes.TrimSuffix(formatted, []byte{'\n'}))
			switch strings.ToUpper(entry.Level) {
			case "DEBUG":
				s.writer.Debug(message)
			case "INFO":
				s.writer.Info(message)
			case "WARN", "WARNING":
				s.writer.Warn(message)
			case "ERROR", "FATAL":
				s.writer.Error(message)
			default:
				s.writer.Message(message)
			}

		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}