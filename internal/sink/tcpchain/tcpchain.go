package tcpchain

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/sink"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSink("tcp_chain", NewTCPChainSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register tcp_chain sink: %v", err))
	}
}

const (
	DefaultChainSinkBufferSize        = 1000
	DefaultChainSinkDialTimeoutMS     = 5000
	DefaultChainSinkWriteTimeoutMS    = 5000
	DefaultChainSinkBackoffMinMS      = 500
	DefaultChainSinkBackoffMaxMS      = 30000
	DefaultChainSinkKeepAlivePeriodMS = 30000
)

// TCPChainSink forwards structured entries to a downstream tcp_chain source
type TCPChainSink struct {
	id      string
	proxy   *session.Proxy
	session *session.Session
	config  *config.TCPChainSinkOptions

	node      string
	addr      string
	helloLine []byte

	input  chan core.TransportEvent
	logger *log.Logger

	// conn owned exclusively by run loop goroutine
	conn          net.Conn
	everConnected bool
	dialTimeout   time.Duration
	writeTimeout  time.Duration

	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time

	totalProcessed atomic.Uint64
	writeErrors    atomic.Uint64
	reconnects     atomic.Uint64
	synthesized    atomic.Uint64
	connected      atomic.Bool
	lastProcessed  atomic.Value // time.Time
}

// NewTCPChainSinkPlugin creates a tcp_chain sink through plugin factory
func NewTCPChainSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.TCPChainSinkOptions{
		KeepAlive: true,
	}
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.NonEmpty(opts.Host); err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}

	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultChainSinkBufferSize
	}
	if opts.DialTimeoutMS <= 0 {
		opts.DialTimeoutMS = DefaultChainSinkDialTimeoutMS
	}
	if opts.WriteTimeoutMS <= 0 {
		opts.WriteTimeoutMS = DefaultChainSinkWriteTimeoutMS
	}
	if opts.BackoffMinMS <= 0 {
		opts.BackoffMinMS = DefaultChainSinkBackoffMinMS
	}
	if opts.BackoffMaxMS < opts.BackoffMinMS {
		opts.BackoffMaxMS = DefaultChainSinkBackoffMaxMS
	}
	if opts.KeepAlivePeriodMS <= 0 {
		opts.KeepAlivePeriodMS = DefaultChainSinkKeepAlivePeriodMS
	}

	node := opts.Node
	if node == "" {
		if hn, err := os.Hostname(); err == nil {
			node = hn
		} else {
			node = "unknown"
		}
	}

	helloLine, err := chain.EncodeHello(node)
	if err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}

	t := &TCPChainSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		node:         node,
		addr:         net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10)),
		helloLine:    helloLine,
		input:        make(chan core.TransportEvent, opts.BufferSize),
		done:         make(chan struct{}),
		logger:       logger,
		dialTimeout:  time.Duration(opts.DialTimeoutMS) * time.Millisecond,
		writeTimeout: time.Duration(opts.WriteTimeoutMS) * time.Millisecond,
	}
	t.lastProcessed.Store(time.Time{})

	t.session = proxy.CreateSession(
		"tcp_chain://"+t.addr,
		map[string]any{
			"instance_id": id,
			"type":        "tcp_chain",
			"target":      t.addr,
			"node":        node,
		},
	)

	logger.Info("msg", "TCP chain sink initialized",
		"component", "tcp_chain_sink",
		"instance_id", id,
		"target", t.addr,
		"node", node)
	return t, nil
}

// Capabilities returns supported capabilities
func (t *TCPChainSink) Capabilities() []core.Capability {
	// CapTLS/CapAuth added when transport security lands
	return []core.Capability{
		core.CapSessionAware,
	}
}

// Input returns the channel for sending transport events
func (t *TCPChainSink) Input() chan<- core.TransportEvent {
	return t.input
}

// Start launches the forwarding loop; connection is established lazily so
// pipeline start does not depend on downstream availability
func (t *TCPChainSink) Start(ctx context.Context) error {
	t.startTime = time.Now()
	t.wg.Add(1)
	go t.runLoop(ctx)

	t.logger.Info("msg", "TCP chain sink started",
		"component", "tcp_chain_sink",
		"instance_id", t.id,
		"target", t.addr)
	return nil
}

// Stop terminates the forwarding loop. Worst-case latency: one write timeout
// plus one backoff wait (both interruptible or bounded).
func (t *TCPChainSink) Stop() {
	t.logger.Info("msg", "Stopping TCP chain sink",
		"component", "tcp_chain_sink",
		"instance_id", t.id)

	close(t.done)
	t.wg.Wait()

	if t.session != nil {
		t.proxy.RemoveSession(t.session.ID)
	}

	t.logger.Info("msg", "TCP chain sink stopped",
		"component", "tcp_chain_sink",
		"instance_id", t.id,
		"total_processed", t.totalProcessed.Load())
}

// GetStats returns sink statistics
func (t *TCPChainSink) GetStats() sink.SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)
	var active int64
	if t.connected.Load() {
		active = 1
	}
	return sink.SinkStats{
		ID:                t.id,
		Type:              "tcp_chain",
		TotalProcessed:    t.totalProcessed.Load(),
		ActiveConnections: active,
		StartTime:         t.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"target":       t.addr,
			"node":         t.node,
			"connected":    t.connected.Load(),
			"reconnects":   t.reconnects.Load(),
			"write_errors": t.writeErrors.Load(),
			"synthesized":  t.synthesized.Load(),
		},
	}
}

// runLoop consumes transport events and forwards them downstream
func (t *TCPChainSink) runLoop(ctx context.Context) {
	defer t.wg.Done()
	defer t.closeConn()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		case event, ok := <-t.input:
			if !ok {
				return
			}
			entry, synthesized := chain.EntryFromEvent(event, t.node, t.id)
			if synthesized {
				t.synthesized.Add(1)
			}
			line, err := json.Marshal(entry)
			if err != nil {
				// Non-transient: drop
				t.logger.Error("msg", "Failed to marshal chain entry",
					"component", "tcp_chain_sink",
					"error", err)
				continue
			}
			if !t.deliver(ctx, append(line, '\n')) {
				return // shutdown during retry
			}
			t.totalProcessed.Add(1)
			t.lastProcessed.Store(time.Now())
			t.proxy.UpdateActivity(t.session.ID)
		}
	}
}

// toEntry extracts the structured entry, stamping node identity at first hop
func (t *TCPChainSink) toEntry(event core.TransportEvent) core.LogEntry {
	entry := event.Entry
	if entry.Time.IsZero() {
		// Defensive: event without structured entry, wrap formatted payload
		t.synthesized.Add(1)
		entry = core.LogEntry{
			Time:    event.Time,
			Source:  t.id,
			Message: string(event.Payload),
		}
	}
	if entry.Node == "" {
		entry.Node = t.node
	}
	return entry
}

// deliver writes one line, holding it across reconnects until sent or shutdown.
// Backpressure during outage propagates to the pipeline dispatch drop counter.
func (t *TCPChainSink) deliver(ctx context.Context, line []byte) bool {
	failures := 0
	for {
		if t.conn == nil {
			if failures > 0 && !t.waitBackoff(ctx, failures) {
				return false
			}
			if err := t.connect(ctx); err != nil {
				if ctx.Err() != nil {
					return false
				}
				failures++
				t.logger.Debug("msg", "Chain connect failed",
					"component", "tcp_chain_sink",
					"target", t.addr,
					"attempt", failures,
					"error", err)
				continue
			}
		}

		t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
		if _, err := t.conn.Write(line); err != nil {
			t.writeErrors.Add(1)
			failures++
			t.logger.Warn("msg", "Chain write failed",
				"component", "tcp_chain_sink",
				"target", t.addr,
				"error", err)
			t.closeConn()
			continue
		}
		return true
	}
}

// connect performs a single dial + hello attempt
func (t *TCPChainSink) connect(ctx context.Context) error {
	d := net.Dialer{Timeout: t.dialTimeout}
	if t.config.KeepAlive {
		d.KeepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   time.Duration(t.config.KeepAlivePeriodMS) * time.Millisecond,
		}
	}

	// IPv4-only
	conn, err := d.DialContext(ctx, "tcp4", t.addr)
	if err != nil {
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	if _, err := conn.Write(t.helloLine); err != nil {
		conn.Close()
		return fmt.Errorf("hello: %w", err)
	}

	t.conn = conn
	t.connected.Store(true)
	if t.everConnected {
		t.reconnects.Add(1)
	}
	t.everConnected = true

	t.logger.Info("msg", "Chain link established",
		"component", "tcp_chain_sink",
		"target", t.addr,
		"node", t.node)
	return nil
}

// closeConn tears down the current connection (run loop goroutine only)
func (t *TCPChainSink) closeConn() {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.connected.Store(false)
}

// waitBackoff sleeps for the computed delay, interruptible by shutdown
func (t *TCPChainSink) waitBackoff(ctx context.Context, failures int) bool {
	minD := time.Duration(t.config.BackoffMinMS) * time.Millisecond
	maxD := time.Duration(t.config.BackoffMaxMS) * time.Millisecond
	timer := time.NewTimer(chain.BackoffDelay(minD, maxD, failures))
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	case <-t.done:
		return false
	}
}

// backoffDelay computes exponential backoff with ±20% jitter
func (t *TCPChainSink) backoffDelay(failures int) time.Duration {
	minD := time.Duration(t.config.BackoffMinMS) * time.Millisecond
	maxD := time.Duration(t.config.BackoffMaxMS) * time.Millisecond

	d := maxD
	if failures < 63 {
		if v := minD << uint(failures-1); v > 0 && v < maxD {
			d = v
		}
	}
	return d - d/5 + time.Duration(rand.Int64N(int64(2*d/5)+1))
}
