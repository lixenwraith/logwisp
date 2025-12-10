package null

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/src/internal/core"
	"logwisp/src/internal/plugin"
	"logwisp/src/internal/session"
	"logwisp/src/internal/sink"

	"github.com/lixenwraith/log"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSink("null", NewNullSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register null sink: %v", err))
	}
}

// NullSink discards all received transport events, used for testing
type NullSink struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Application
	input  chan core.TransportEvent
	logger *log.Logger

	// Runtime
	done      chan struct{}
	startTime time.Time

	// Statistics
	totalReceived atomic.Uint64
	totalBytes    atomic.Uint64
	lastReceived  atomic.Value // time.Time
}

// NewNullSinkPlugin creates a null sink through plugin factory
func NewNullSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	ns := &NullSink{
		id:     id,
		proxy:  proxy,
		input:  make(chan core.TransportEvent, 1000),
		done:   make(chan struct{}),
		logger: logger,
	}
	ns.lastReceived.Store(time.Time{})

	// Create session for null sink
	ns.session = proxy.CreateSession(
		"null://devnull",
		map[string]any{
			"instance_id": id,
			"type":        "null",
		},
	)

	logger.Debug("msg", "Null sink initialized",
		"component", "null_sink",
		"instance_id", id)

	return ns, nil
}

// Capabilities returns supported capabilities
func (ns *NullSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
	}
}

// Input returns the channel for sending transport events
func (ns *NullSink) Input() chan<- core.TransportEvent {
	return ns.input
}

// Start begins the processing loop
func (ns *NullSink) Start(ctx context.Context) error {

	ns.startTime = time.Now()
	go ns.processLoop(ctx)
	ns.logger.Debug("msg", "Null sink started",
		"component", "null_sink",
		"instance_id", ns.id)
	return nil
}

// Stop gracefully shuts down the sink
func (ns *NullSink) Stop() {
	if ns.session != nil {
		ns.proxy.RemoveSession(ns.session.ID)
	}
	close(ns.done)
	ns.logger.Debug("msg", "Null sink stopped",
		"instance_id", ns.id,
		"total_received", ns.totalReceived.Load())
}

// GetStats returns sink statistics
func (ns *NullSink) GetStats() sink.SinkStats {
	lastRcv, _ := ns.lastReceived.Load().(time.Time)

	return sink.SinkStats{
		ID:             ns.id,
		Type:           "null",
		TotalProcessed: ns.totalReceived.Load(),
		StartTime:      ns.startTime,
		LastProcessed:  lastRcv,
		Details: map[string]any{
			"total_bytes": ns.totalBytes.Load(),
		},
	}
}

// processLoop reads transport events and discards them
func (ns *NullSink) processLoop(ctx context.Context) {
	for {
		select {
		case event, ok := <-ns.input:
			if !ok {
				return
			}
			// Discard the event, only update stats
			ns.totalReceived.Add(1)
			ns.totalBytes.Add(uint64(len(event.Payload)))
			ns.lastReceived.Store(time.Now())

		case <-ctx.Done():
			return
		case <-ns.done:
			return
		}
	}
}