// FILE: logwisp/src/internal/sink/file.go
package sink

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
)

// FileSink writes log entries to files with rotation.
type FileSink struct {
	config    *config.FileSinkOptions
	input     chan core.LogEntry
	writer    *log.Logger // Internal logger instance for file writing
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger // Application logger
	formatter format.Formatter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewFileSink creates a new file sink.
func NewFileSink(opts *config.FileSinkOptions, logger *log.Logger, formatter format.Formatter) (*FileSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("file sink options cannot be nil")
	}

	// Create configuration for the internal log writer
	writerConfig := log.DefaultConfig()
	writerConfig.Directory = opts.Directory
	writerConfig.Name = opts.Name
	writerConfig.EnableConsole = false // File only
	writerConfig.ShowTimestamp = false // We already have timestamps in entries
	writerConfig.ShowLevel = false     // We already have levels in entries

	// Create internal logger for file writing
	writer := log.NewLogger()
	if err := writer.ApplyConfig(writerConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize file writer: %w", err)
	}

	fs := &FileSink{
		input:     make(chan core.LogEntry, opts.BufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	fs.lastProcessed.Store(time.Time{})

	return fs, nil
}

// Input returns the channel for sending log entries.
func (fs *FileSink) Input() chan<- core.LogEntry {
	return fs.input
}

// Start begins the processing loop for the sink.
func (fs *FileSink) Start(ctx context.Context) error {
	// Start the internal file writer
	if err := fs.writer.Start(); err != nil {
		return fmt.Errorf("failed to start sink file writer: %w", err)
	}

	go fs.processLoop(ctx)
	fs.logger.Info("msg", "File sink started", "component", "file_sink")
	return nil
}

// Stop gracefully shuts down the sink.
func (fs *FileSink) Stop() {
	fs.logger.Info("msg", "Stopping file sink")
	close(fs.done)

	// Shutdown the writer with timeout
	if err := fs.writer.Shutdown(2 * time.Second); err != nil {
		fs.logger.Error("msg", "Error shutting down file writer",
			"component", "file_sink",
			"error", err)
	}

	fs.logger.Info("msg", "File sink stopped")
}

// GetStats returns the sink's statistics.
func (fs *FileSink) GetStats() SinkStats {
	lastProc, _ := fs.lastProcessed.Load().(time.Time)

	return SinkStats{
		Type:           "file",
		TotalProcessed: fs.totalProcessed.Load(),
		StartTime:      fs.startTime,
		LastProcessed:  lastProc,
		Details:        map[string]any{},
	}
}

// processLoop reads entries, formats them, and writes to a file.
func (fs *FileSink) processLoop(ctx context.Context) {
	for {
		select {
		case entry, ok := <-fs.input:
			if !ok {
				return
			}

			fs.totalProcessed.Add(1)
			fs.lastProcessed.Store(time.Now())

			// Format using the formatter instead of fmt.Sprintf
			formatted, err := fs.formatter.Format(entry)
			if err != nil {
				fs.logger.Error("msg", "Failed to format log entry",
					"component", "file_sink",
					"error", err)
				continue
			}

			// Convert to string to prevent hex encoding of []byte by log package
			// Strip new line, writer adds it
			message := string(bytes.TrimSuffix(formatted, []byte{'\n'}))
			fs.writer.Message(message)

		case <-ctx.Done():
			return
		case <-fs.done:
			return
		}
	}
}