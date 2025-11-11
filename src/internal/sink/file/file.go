// FILE: logwisp/src/internal/sink/file.go
package file

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/plugin"
	"logwisp/src/internal/session"
	"logwisp/src/internal/sink"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSink("file", NewFileSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register file sink: %v", err))
	}
}

// FileSink writes log entries to files with rotation
type FileSink struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Configuration
	config *config.FileSinkOptions

	// Application
	input  chan core.TransportEvent
	writer *log.Logger // internal logger for file writing
	logger *log.Logger // application logger

	// Runtime
	done      chan struct{}
	startTime time.Time

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewFileSinkPlugin creates a file sink through plugin factory
func NewFileSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	// Step 1: Create empty config struct with defaults
	opts := &config.FileSinkOptions{
		Directory:       "",   // Required field - no default
		Name:            "",   // Required field - no default
		MaxSizeMB:       100,  // Default max file size
		MaxTotalSizeMB:  1000, // Default max total size
		MinDiskFreeMB:   100,  // Default min disk free
		RetentionHours:  168,  // Default retention (7 days)
		BufferSize:      1000, // Default buffer size
		FlushIntervalMs: 100,  // Default flush interval
	}

	// Step 2: Use lconfig to scan map into struct (overriding defaults)
	cfg := lconfig.New()
	for path, value := range lconfig.FlattenMap(configMap, "") {
		cfg.Set(path, value)
	}
	if err := cfg.Scan(opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Step 3: Validate required fields
	if opts.Directory == "" {
		return nil, fmt.Errorf("directory is mandatory")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("name is mandatory")
	}

	// Validate sizes
	if opts.MaxSizeMB <= 0 {
		return nil, fmt.Errorf("max_size_mb must be positive")
	}
	if opts.MaxTotalSizeMB <= 0 {
		return nil, fmt.Errorf("max_total_size_mb must be positive")
	}
	if opts.MinDiskFreeMB < 0 {
		return nil, fmt.Errorf("min_disk_free_mb cannot be negative")
	}
	if opts.RetentionHours <= 0 {
		return nil, fmt.Errorf("retention_hours must be positive")
	}
	if opts.BufferSize <= 0 {
		return nil, fmt.Errorf("buffer_size must be positive")
	}
	if opts.FlushIntervalMs <= 0 {
		return nil, fmt.Errorf("flush_interval_ms must be positive")
	}

	// Step 4: Create and return plugin instance
	// Create configuration for the internal log writer
	writerConfig := log.DefaultConfig()
	writerConfig.Directory = opts.Directory
	writerConfig.Name = opts.Name
	writerConfig.MaxSizeKB = opts.MaxSizeMB * 1000
	writerConfig.MaxTotalSizeKB = opts.MaxTotalSizeMB * 1000
	writerConfig.MinDiskFreeKB = opts.MinDiskFreeMB * 1000
	writerConfig.RetentionPeriodHrs = opts.RetentionHours
	writerConfig.BufferSize = opts.BufferSize
	writerConfig.FlushIntervalMs = opts.FlushIntervalMs
	// Sink logic
	writerConfig.EnableConsole = false
	writerConfig.EnableFile = true
	writerConfig.ShowTimestamp = false
	writerConfig.ShowLevel = false
	writerConfig.Format = "raw"

	// Create internal logger for file writing
	writer := log.NewLogger()
	if err := writer.ApplyConfig(writerConfig); err != nil {
		return nil, fmt.Errorf("failed to initialize file writer: %w", err)
	}

	fs := &FileSink{
		id:        id,
		proxy:     proxy,
		config:    opts,
		input:     make(chan core.TransportEvent, opts.BufferSize),
		writer:    writer,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
	}
	fs.lastProcessed.Store(time.Time{})

	// Create session for file output
	fs.session = proxy.CreateSession(
		fmt.Sprintf("file:///%s/%s", opts.Directory, opts.Name),
		map[string]any{
			"instance_id": id,
			"type":        "file",
			"directory":   opts.Directory,
			"name":        opts.Name,
		},
	)

	fs.logger.Info("msg", "File sink initialized",
		"component", "file_sink",
		"instance_id", id,
		"directory", opts.Directory,
		"name", opts.Name)

	return fs, nil
}

// Capabilities returns supported capabilities
func (fs *FileSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware, // Single output session
	}
}

// Input returns the channel for sending transport events
func (fs *FileSink) Input() chan<- core.TransportEvent {
	return fs.input
}

// Start begins the processing loop for the sink
func (fs *FileSink) Start(ctx context.Context) error {
	// Start the internal file writer
	if err := fs.writer.Start(); err != nil {
		return fmt.Errorf("failed to start file writer: %w", err)
	}

	go fs.processLoop(ctx)

	fs.logger.Info("msg", "File sink started",
		"component", "file_sink",
	)
	fs.logger.Debug("msg", "File sink config",
		"component", "file_sink",
		"directory", fs.config.Directory,
		"name", fs.config.Name,
		"max_size_mb", fs.config.MaxSizeMB,
		"max_total_size_mb", fs.config.MaxTotalSizeMB,
		"min_disk_free_mb", fs.config.MinDiskFreeMB,
		"retention_hours", fs.config.RetentionHours,
		"buffer_size", fs.config.BufferSize,
		"flush_interval_ms", fs.config.FlushIntervalMs,
	)

	return nil
}

// Stop gracefully shuts down the sink
func (fs *FileSink) Stop() {
	fs.logger.Info("msg", "Stopping file sink",
		"component", "file_sink",
		"directory", fs.config.Directory,
		"name", fs.config.Name)

	close(fs.done)

	// Remove session
	if fs.session != nil {
		fs.proxy.RemoveSession(fs.session.ID)
	}

	// Shutdown the writer with timeout
	if err := fs.writer.Shutdown(2 * time.Second); err != nil {
		fs.logger.Error("msg", "Error shutting down file writer",
			"component", "file_sink",
			"error", err)
	}

	fs.logger.Info("msg", "File sink stopped",
		"component", "file_sink",
		"instance_id", fs.id,
		"total_processed", fs.totalProcessed.Load())
}

// GetStats returns the sink's statistics
func (fs *FileSink) GetStats() sink.SinkStats {
	return sink.SinkStats{
		ID:             fs.id,
		Type:           "file",
		TotalProcessed: fs.totalProcessed.Load(),
		StartTime:      fs.startTime,
		LastProcessed:  fs.lastProcessed.Load().(time.Time),
		Details: map[string]any{
			"directory": fs.config.Directory,
			"name":      fs.config.Name,
		},
	}
}

// processLoop reads transport events and writes to file
func (fs *FileSink) processLoop(ctx context.Context) {
	for {
		select {
		case event, ok := <-fs.input:
			if !ok {
				return
			}

			// Write the pre-formatted payload directly
			// The writer handles rotation automatically based on configuration
			fs.writer.Message(string(event.Payload))

			fs.totalProcessed.Add(1)
			fs.lastProcessed.Store(time.Now())

		case <-ctx.Done():
			return

		case <-fs.done:
			return
		}
	}
}