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
	startTime time.Time

	totalReceived atomic.Uint64
	totalBytes    atomic.Uint64
	lastReceived  atomic.Value // time.Time
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
		logger: logger,
	}
	ns.lastReceived.Store(time.Time{})

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
	ns.logger.Debug("msg", "Null sink stopped",
		"instance_id", ns.id,
		"total_received", ns.totalReceived.Load())
}

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

func (ns *NullSink) processLoop(ctx context.Context) {
	for {
		select {
		case event, ok := <-ns.input:
			if !ok {
				return
			}
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
