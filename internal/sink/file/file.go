package file

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"

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
	input        chan core.TransportEvent
	writer       *log.Logger // internal logger for file writing
	writerConfig *log.Config
	logger       *log.Logger // application logger

	// Runtime
	done      chan struct{}
	exited    chan struct{}
	started   atomic.Bool
	startTime time.Time

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

const (
	// Defaults
	DefaultFileMaxSizeMB       = 100
	DefaultFileMaxTotalSizeMB  = 1000
	DefaultFileMinDiskFreeMB   = 100
	DefaultFileRetentionHours  = 168 // 7 days
	DefaultFileBufferSize      = 1000
	DefaultFileFlushIntervalMs = 100
)

// NewFileSinkPlugin creates a file sink through plugin factory
func NewFileSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	// Create empty config struct
	opts := &config.FileSinkOptions{}

	// Scan config map into struct
	if err := config.Scan(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	if err := lconfig.NonEmpty(opts.Directory); err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if err := lconfig.NonEmpty(opts.Name); err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}

	// Defaults
	if opts.MaxSizeMB <= 0 {
		opts.MaxSizeMB = DefaultFileMaxSizeMB
	}
	if opts.MaxTotalSizeMB <= 0 {
		opts.MaxTotalSizeMB = DefaultFileMaxTotalSizeMB
	}
	if opts.MinDiskFreeMB < 0 {
		opts.MinDiskFreeMB = DefaultFileMinDiskFreeMB
	}
	if opts.RetentionHours <= 0 {
		opts.RetentionHours = DefaultFileRetentionHours
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultFileBufferSize
	}
	if opts.FlushIntervalMs <= 0 {
		opts.FlushIntervalMs = DefaultFileFlushIntervalMs
	}

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

	// Validated here, applied in Start: applying creates the directory and
	// file, which lw --check and a rejected reload must not do
	if err := writerConfig.Validate(); err != nil {
		return nil, fmt.Errorf("failed to initialize file writer: %w", err)
	}

	fs := &FileSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		input:        make(chan core.TransportEvent, opts.BufferSize),
		writer:       log.NewLogger(),
		writerConfig: writerConfig,
		done:         make(chan struct{}),
		exited:       make(chan struct{}),
		logger:       logger,
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
	if err := fs.writer.ApplyConfig(fs.writerConfig); err != nil {
		return fmt.Errorf("failed to initialize file writer: %w", err)
	}
	if err := fs.writer.Start(); err != nil {
		return fmt.Errorf("failed to start file writer: %w", err)
	}

	fs.startTime = time.Now()
	fs.started.Store(true)
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

	// The loop writes what is queued before the writer shuts down
	close(fs.done)
	if fs.started.Load() {
		<-fs.exited
	}

	// Remove session
	if fs.session != nil {
		fs.proxy.RemoveSession(fs.session.ID)
	}

	// Shutdown the writer with timeout
	if err := fs.writer.Shutdown(core.LoggerShutdownTimeout); err != nil {
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

// processLoop writes transport events until stopped, then what is queued
func (fs *FileSink) processLoop(ctx context.Context) {
	defer close(fs.exited)
	for {
		select {
		case event := <-fs.input:
			fs.write(event)
		case <-ctx.Done():
			fs.drain()
			return
		case <-fs.done:
			fs.drain()
			return
		}
	}
}

func (fs *FileSink) drain() {
	for {
		select {
		case event := <-fs.input:
			fs.write(event)
		default:
			return
		}
	}
}

// write hands the formatted payload to the writer, which rotates files
func (fs *FileSink) write(event core.TransportEvent) {
	fs.writer.Write(string(event.Payload))
	fs.totalProcessed.Add(1)
	fs.lastProcessed.Store(time.Now())
}
