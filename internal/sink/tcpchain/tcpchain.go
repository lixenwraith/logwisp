package tcpchain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/tlsx"

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
	network   string
	tlsConfig *tls.Config

	// Authorization: pins the downstream server's identity
	auth *authz.Policy

	input  chan core.TransportEvent
	logger *log.Logger

	// conn and the backoff state are owned exclusively by the run loop goroutine.
	// failures survives a link that dies right after connecting, so a refusing
	// source is retried with growing delays rather than in a tight loop.
	conn          net.Conn
	connectedAt   time.Time
	failures      int
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
	if err := config.Scan(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.NonEmpty(opts.Host); err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	network, err := core.Network(opts.Host)
	if err != nil {
		return nil, fmt.Errorf("host: %w", err)
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

	tlsCfg, err := tlsx.Client(opts.TLS, opts.Host)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, tlsCfg, authz.RoleDialer, authz.TCP)
	if err != nil {
		return nil, err
	}
	if authPolicy.Enabled() {
		// Runs after the standard chain and hostname checks, so a server the
		// policy rejects fails the handshake instead of the first write
		tlsCfg.VerifyConnection = authPolicy.VerifyConnection
	}

	t := &TCPChainSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		node:         node,
		addr:         net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10)),
		network:      network,
		tlsConfig:    tlsCfg,
		auth:         authPolicy,
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
		"node", node,
		"tls", tlsCfg != nil,
		"mtls", tlsCfg != nil && len(tlsCfg.Certificates) > 0,
		"auth", authPolicy.Describe())
	tlsx.LogWarnings(logger, "tcp_chain_sink", id, opts.TLS, false)
	authPolicy.LogStartup(logger, "tcp_chain_sink", id, false)
	return t, nil
}

// Capabilities returns supported capabilities
func (t *TCPChainSink) Capabilities() []core.Capability {
	caps := []core.Capability{core.CapSessionAware}
	if t.tlsConfig != nil {
		caps = append(caps, core.CapTLS)
	}
	if t.auth.Enabled() {
		caps = append(caps, core.CapAuth) // pins the server identity
	}
	return caps
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
	details := map[string]any{
		"target":       t.addr,
		"node":         t.node,
		"tls":          t.tlsConfig != nil,
		"connected":    t.connected.Load(),
		"reconnects":   t.reconnects.Load(),
		"write_errors": t.writeErrors.Load(),
		"synthesized":  t.synthesized.Load(),
	}
	maps.Copy(details, t.auth.Stats())

	return sink.SinkStats{
		ID:                t.id,
		Type:              "tcp_chain",
		TotalProcessed:    t.totalProcessed.Load(),
		ActiveConnections: active,
		StartTime:         t.startTime,
		LastProcessed:     lastProc,
		Details:           details,
	}
}

// runLoop consumes transport events and forwards them downstream
func (t *TCPChainSink) runLoop(ctx context.Context) {
	defer t.wg.Done()
	defer t.closeConn()

	// Fold done into the context, so a connect or exchange in flight ends on Stop
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-t.done:
			cancel()
		case <-ctx.Done():
		}
	}()

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

// deliver writes one line, holding it across reconnects until sent or shutdown.
// Backpressure during outage propagates to the pipeline dispatch drop counter.
func (t *TCPChainSink) deliver(ctx context.Context, line []byte) bool {
	for {
		if t.conn == nil {
			if t.failures > 0 && !t.waitBackoff(ctx, t.failures) {
				return false
			}
			if err := t.connect(ctx); err != nil {
				if ctx.Err() != nil {
					return false
				}
				t.failures++
				if errors.Is(err, authz.ErrRefused) || errors.As(err, new(*tls.CertificateVerificationError)) {
					// A refusal, or a server failing its CA or pin, is
					// configuration, not weather: show it by default
					t.logger.Warn("msg", "Chain connect refused",
						"component", "tcp_chain_sink",
						"target", t.addr,
						"attempt", t.failures,
						"error", err)
				} else {
					t.logger.Debug("msg", "Chain connect failed",
						"component", "tcp_chain_sink",
						"target", t.addr,
						"attempt", t.failures,
						"error", err)
				}
				continue
			}
		}

		t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
		if _, err := t.conn.Write(line); err != nil {
			t.writeErrors.Add(1)
			t.failures++
			t.logger.Warn("msg", "Chain write failed",
				"component", "tcp_chain_sink",
				"target", t.addr,
				"error", err)
			t.closeConn()
			continue
		}
		// Healthy once it outlives the shortest backoff
		if t.failures > 0 && time.Since(t.connectedAt) >= time.Duration(t.config.BackoffMinMS)*time.Millisecond {
			t.failures = 0
		}
		return true
	}
}

// connect performs a single dial (+ TLS handshake) + hello attempt
func (t *TCPChainSink) connect(ctx context.Context) error {
	nd := net.Dialer{Timeout: t.dialTimeout}
	if t.config.KeepAlive {
		nd.KeepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   time.Duration(t.config.KeepAlivePeriodMS) * time.Millisecond,
		}
	}

	var conn net.Conn
	var err error
	if t.tlsConfig != nil {
		// nd.Timeout only bounds the TCP connect; tls.Dialer runs the
		// handshake under ctx, so bound dial + handshake together here
		dctx, cancel := context.WithTimeout(ctx, t.dialTimeout+tlsx.HandshakeTimeout)
		td := tls.Dialer{NetDialer: &nd, Config: t.tlsConfig}
		conn, err = td.DialContext(dctx, t.network, t.addr)
		cancel()
	} else {
		conn, err = nd.DialContext(ctx, t.network, t.addr)
	}
	if err != nil {
		return err
	}

	r, err := t.auth.Greet(ctx, conn, t.node)
	if err != nil {
		conn.Close()
		return err
	}
	// A source never writes once a link is up: a line is a refusal this sink
	// could not otherwise see, EOF a close. Stop writing into either.
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		err := authz.AwaitClose(r)
		conn.Close()
		if errors.Is(err, authz.ErrRefused) {
			t.logger.Warn("msg", "Chain link refused",
				"component", "tcp_chain_sink",
				"target", t.addr,
				"error", err)
		}
	}()
	t.connectedAt = time.Now()

	t.conn = conn
	t.connected.Store(true)
	if t.everConnected {
		t.reconnects.Add(1)
	}
	t.everConnected = true

	t.logger.Info("msg", "Chain link established",
		"component", "tcp_chain_sink",
		"target", t.addr,
		"node", t.node,
		"tls", t.tlsConfig != nil)
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
