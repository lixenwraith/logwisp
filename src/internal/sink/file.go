// FILE: src/internal/sink/file.go
package sink

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/src/internal/format"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// FileSink writes log entries to files with rotation
type FileSink struct {
	input     chan source.LogEntry
	writer    *log.Logger // Internal logger instance for file writing
	done      chan struct{}
	startTime time.Time
	logger    *log.Logger // Application logger
	formatter format.Formatter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewFileSink creates a new file sink
func NewFileSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*FileSink, error) {
	directory, ok := options["directory"].(string)
	if !ok || directory == "" {
		return nil, fmt.Errorf("file sink requires 'directory' option")
	}

	name, ok := options["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("file sink requires 'name' option")
	}

	// Create configuration for the internal log writer
	var configArgs []string
	configArgs = append(configArgs,
		fmt.Sprintf("directory=%s", directory),
		fmt.Sprintf("name=%s", name),
		"enable_stdout=false",  // File only
		"show_timestamp=false", // We already have timestamps in entries
		"show_level=false",     // We already have levels in entries
	)

	// Add optional configurations
	if maxSize, ok := toInt(options["max_size_mb"]); ok && maxSize > 0 {
		configArgs = append(configArgs, fmt.Sprintf("max_size_mb=%d", maxSize))
	}

	if maxTotalSize, ok := toInt(options["max_total_size_mb"]); ok && maxTotalSize >= 0 {
		configArgs = append(configArgs, fmt.Sprintf("max_total_size_mb=%d", maxTotalSize))
	}

	if retention, ok := toFloat(options["retention_hours"]); ok && retention > 0 {
		configArgs = append(configArgs, fmt.Sprintf("retention_period_hrs=%.1f", retention))
	}

	if minDiskFree, ok := toInt(options["min_disk_free_mb"]); ok && minDiskFree > 0 {
		configArgs = append(configArgs, fmt.Sprintf("min_disk_free_mb=%d", minDiskFree))
	}

	// Create internal logger for file writing
	writer := log.NewLogger()
	if err := writer.InitWithDefaults(configArgs...); err != nil {
		return nil, fmt.Errorf("failed to initialize file writer: %w", err)
	}

	// Buffer size for input channel
	bufferSize := 1000
	if bufSize, ok := toInt(options["buffer_size"]); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	fs := &FileSink{
		input:     make(chan source.LogEntry, bufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	fs.lastProcessed.Store(time.Time{})

	return fs, nil
}

func (fs *FileSink) Input() chan<- source.LogEntry {
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

			// Write formatted bytes (strip newline as writer adds it)
			message := string(formatted)
			if len(message) > 0 && message[len(message)-1] == '\n' {
				message = message[:len(message)-1]
			}
			fs.writer.Message(message)

		case <-ctx.Done():
			return
		case <-fs.done:
			return
		}
	}
}