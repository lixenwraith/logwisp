package null

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

	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSink("null", NewNullSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register null sink: %v", err))
	}
}

// NullSink discards every event: it holds a sink's place until one is chosen,
// or isolates a source or flow while it is measured
type NullSink struct {
	id      string
	proxy   *session.Proxy
	session *session.Session

	input  chan core.TransportEvent
	logger *log.Logger

	done      chan struct{}
	exited    chan struct{} // closed when processLoop has counted what was queued
	started   atomic.Bool
	startTime time.Time

	totalReceived atomic.Uint64
	totalBytes    atomic.Uint64
	lastReceived  core.AtomicTime
}

func NewNullSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	if _, err := config.Decode[config.NullSinkOptions]("sink", "null", configMap); err != nil {
		return nil, err
	}
	ns := &NullSink{
		id:     id,
		proxy:  proxy,
		input:  make(chan core.TransportEvent, 1000),
		done:   make(chan struct{}),
		exited: make(chan struct{}),
		logger: logger,
	}

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

func (ns *NullSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
		core.CapBackpressure, // it discards at once: a wait loses nothing, a drop would count
	}
}

func (ns *NullSink) Input() chan<- core.TransportEvent {
	return ns.input
}

func (ns *NullSink) Start(ctx context.Context) error {
	ns.startTime = time.Now()
	ns.started.Store(true)
	go ns.processLoop(ctx)
	ns.logger.Debug("msg", "Null sink started",
		"component", "null_sink",
		"instance_id", ns.id)
	return nil
}

func (ns *NullSink) Stop() {
	if ns.session != nil {
		ns.proxy.RemoveSession(ns.session.ID)
	}
	close(ns.done)
	if ns.started.Load() {
		<-ns.exited // its counts then include what was queued
	}
	ns.logger.Debug("msg", "Null sink stopped",
		"instance_id", ns.id,
		"total_received", ns.totalReceived.Load())
}

func (ns *NullSink) GetStats() sink.SinkStats {
	lastRcv := ns.lastReceived.Load()

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

// processLoop counts events until stopped, then what is queued: what a
// measured source or flow sent must appear in the counts
func (ns *NullSink) processLoop(ctx context.Context) {
	defer close(ns.exited)
	for {
		select {
		case event := <-ns.input:
			ns.count(event)
		case <-ctx.Done():
			ns.drain()
			return
		case <-ns.done:
			ns.drain()
			return
		}
	}
}

func (ns *NullSink) drain() {
	for {
		select {
		case event := <-ns.input:
			ns.count(event)
		default:
			return
		}
	}
}

func (ns *NullSink) count(event core.TransportEvent) {
	ns.totalReceived.Add(1)
	ns.totalBytes.Add(uint64(len(event.Payload)))
	ns.lastReceived.Store(time.Now())
}
