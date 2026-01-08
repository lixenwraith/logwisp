package console

import (
	"context"
	"fmt"
	"io"
	"os"
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
	if err := plugin.RegisterSink("console", NewConsoleSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register console sink: %v", err))
	}
}

// ConsoleSink writes log entries to the console (stdout/stderr) using an dedicated logger instance
type ConsoleSink struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Configuration
	config *config.ConsoleSinkOptions

	// Application
	input  chan core.TransportEvent
	output io.Writer
	logger *log.Logger // application logger

	// Runtime
	done      chan struct{}
	startTime time.Time

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

const (
	// Defaults
	DefaultConsoleTarget     = "stdout"
	DefaultConsoleBufferSize = 1000
)

// NewConsoleSinkPlugin creates a console sink through plugin factory
func NewConsoleSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.ConsoleSinkOptions{}

	// Scan config map into struct
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate and apply defaults
	if opts.Target == "" {
		opts.Target = DefaultConsoleTarget
	} else {
		validateTarget := lconfig.OneOf("stdout", "stderr")
		if err := validateTarget(opts.Target); err != nil {
			return nil, fmt.Errorf("target: %w", err)
		}
	}

	var output io.Writer
	switch opts.Target {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	}

	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultConsoleBufferSize
	}

	// Create and return plugin instance
	cs := &ConsoleSink{
		id:     id,
		proxy:  proxy,
		config: opts,
		input:  make(chan core.TransportEvent, opts.BufferSize),
		output: output,
		done:   make(chan struct{}),
		logger: logger,
	}
	cs.lastProcessed.Store(time.Time{})

	// Create session for output
	cs.session = proxy.CreateSession(
		fmt.Sprintf("console:%s", opts.Target),
		map[string]any{
			"instance_id": id,
			"type":        "console",
			"target":      opts.Target,
		},
	)

	cs.logger.Info("msg", "Console sink initialized",
		"component", "console_sink",
		"instance_id", id,
		"target", opts.Target,
	)

	return cs, nil
}

// Capabilities returns supported capabilities
func (cs *ConsoleSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware, // Single output session
	}
}

// Input returns the channel for sending transport events
func (cs *ConsoleSink) Input() chan<- core.TransportEvent {
	return cs.input
}

// Start begins the processing loop
func (cs *ConsoleSink) Start(ctx context.Context) error {
	cs.startTime = time.Now()
	go cs.processLoop(ctx)
	cs.logger.Info("msg", "Console sink started",
		"component", "console_sink",
		"target", cs.config.Target)
	return nil
}

// Stop gracefully shuts down the sink
func (cs *ConsoleSink) Stop() {
	cs.logger.Info("msg", "Stopping console sink", "target", cs.config.Target)

	// Remove session
	if cs.session != nil {
		cs.proxy.RemoveSession(cs.session.ID)
	}

	close(cs.done)

	cs.logger.Info("msg", "Console sink stopped",
		"instance_id", cs.id,
		"target", cs.config.Target,
		"instance_id", cs.id,
	)
}

// GetStats returns sink statistics
func (cs *ConsoleSink) GetStats() sink.SinkStats {
	lastProc, _ := cs.lastProcessed.Load().(time.Time)

	return sink.SinkStats{
		ID:             cs.id,
		Type:           "console",
		TotalProcessed: cs.totalProcessed.Load(),
		StartTime:      cs.startTime,
		LastProcessed:  lastProc,
		Details: map[string]any{
			"target":      cs.config.Target,
			"buffer_size": cs.config.BufferSize,
		},
	}
}

// processLoop reads transport events and writes to console
func (cs *ConsoleSink) processLoop(ctx context.Context) {
	for {
		select {
		case event, ok := <-cs.input:
			if !ok {
				return
			}

			// Write pre-formatted payload directly to output
			if _, err := cs.output.Write(event.Payload); err != nil {
				cs.logger.Error("msg", "Failed to write to console",
					"component", "console_sink",
					"target", cs.config.Target,
					"error", err)
				continue
			}

			cs.totalProcessed.Add(1)
			cs.lastProcessed.Store(time.Now())

		case <-ctx.Done():
			return
		case <-cs.done:
			return
		}
	}
}