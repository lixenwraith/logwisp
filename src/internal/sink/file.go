// FILE: logwisp/src/internal/sink/file.go
package sink

import (
	"bytes"
	"context"
	"fmt"
	"logwisp/src/internal/config"
	"sync/atomic"
	"time"

	"logwisp/src/internal/core"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
)

// Writes log entries to files with rotation
type FileSink struct {
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

// Creates a new file sink
func NewFileSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*FileSink, error) {
	directory, ok := options["directory"].(string)
	if !ok || directory == "" {
		directory = "./"
		logger.Warn("No directory or invalid directory provided, current directory will be used")
	}

	name, ok := options["name"].(string)
	if !ok || name == "" {
		name = "logwisp.output"
		logger.Warn(fmt.Sprintf("No filename provided, %s will be used", name))
	}

	// Create configuration for the internal log writer
	writerConfig := log.DefaultConfig()
	writerConfig.Directory = directory
	writerConfig.Name = name
	writerConfig.EnableConsole = false // File only
	writerConfig.ShowTimestamp = false // We already have timestamps in entries
	writerConfig.ShowLevel = false     // We already have levels in entries

	// Add optional configurations
	if maxSize, ok := options["max_size_mb"].(int64); ok && maxSize > 0 {
		writerConfig.MaxSizeKB = maxSize * 1000
	}

	if maxTotalSize, ok := options["max_total_size_mb"].(int64); ok && maxTotalSize >= 0 {
		writerConfig.MaxTotalSizeKB = maxTotalSize * 1000
	}

	if retention, ok := options["retention_hours"].(int64); ok && retention > 0 {
		writerConfig.RetentionPeriodHrs = float64(retention)
	}

	if minDiskFree, ok := options["min_disk_free_mb"].(int64); ok && minDiskFree > 0 {
		writerConfig.MinDiskFreeKB = minDiskFree * 1000
	}

	// Create internal logger for file writing
	writer := log.NewLogger()
	if err := writer.ApplyConfig(writerConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize file writer: %w", err)
	}

	// Start the internal file writer
	if err := writer.Start(); err != nil {
		return nil, fmt.Errorf("failed to start file writer: %w", err)
	}

	// Buffer size for input channel
	// TODO: Centralized constant file in core package
	bufferSize := int64(1000)
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	fs := &FileSink{
		input:     make(chan core.LogEntry, bufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	fs.lastProcessed.Store(time.Time{})

	return fs, nil
}

func (fs *FileSink) Input() chan<- core.LogEntry {
	return fs.input
}

func (fs *FileSink) Start(ctx context.Context) error {
	go fs.processLoop(ctx)
	fs.logger.Info("msg", "File sink started", "component", "file_sink")
	return nil
}

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

func (fs *FileSink) SetAuth(auth *config.AuthConfig) {
	// Authentication does not apply to file sink
}