package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
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
	if err := plugin.RegisterSink("tcp", NewTCPSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register tcp sink: %v", err))
	}
}

const (
	DefaultTCPHost              = "0.0.0.0"
	DefaultTCPBufferSize        = 1000
	DefaultTCPClientBufferSize  = 256
	DefaultTCPWriteTimeoutMS    = 5000
	DefaultTCPKeepAlivePeriodMS = 30000
)

// TCPSink streams formatted log entries to connected TCP clients
// Concurrency model: one broadcast loop fans out into bounded per-client queues
// each connection owns a writer goroutine (drains queue) and a reader goroutine (disconnect detection)
// A stalled client drops events, never the pipeline.
type TCPSink struct {
	// Plugin identity and session management
	id    string
	proxy *session.Proxy

	// Configuration
	config  *config.TCPSinkOptions
	addr    string
	network string

	// Network
	listener net.Listener

	// Application
	input  chan core.TransportEvent
	logger *log.Logger

	// Client registry. conns holds every accepted connection, so shutdown also
	// reaches peers still in the handshake, before they become clients.
	clients      map[uint64]*tcpClient
	conns        map[net.Conn]struct{}
	clientsMu    sync.Mutex
	nextClientID atomic.Uint64
	writeTimeout time.Duration

	// TLS
	tlsConfig          *tls.Config
	tlsHandshakeErrors atomic.Uint64

	// Authorization
	auth *authz.Policy

	// Runtime. Stop closes flush; the broadcast loop then moves what remains
	// of its input to tail and closes flushed; each writer writes its queue
	// and tail on its own, until flushBy. done tears down what is left.
	done      chan struct{}
	flush     chan struct{}
	flushed   chan struct{}
	flushBy   time.Time
	tail      [][]byte // read only once flushed is closed
	flushing  bool     // under clientsMu: no client registers once set
	stopOnce  sync.Once
	wg        sync.WaitGroup
	startTime time.Time

	// Statistics
	activeConns    atomic.Int64
	totalProcessed atomic.Uint64
	writeErrors    atomic.Uint64
	droppedWrites  atomic.Uint64
	rejectedConns  atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// tcpClient is a registered connection's bounded send queue.
// send is written by the broadcast loop (non-blocking) and drained by the
// writer goroutine; closed signals reader-detected disconnect, exited the
// writer's end.
type tcpClient struct {
	send      chan []byte
	sessionID string
	closed    chan struct{}
	exited    chan struct{}
}

// NewTCPSinkPlugin creates a tcp sink through plugin factory
func NewTCPSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.TCPSinkOptions{
		Host:      DefaultTCPHost,
		KeepAlive: true,
	}
	if err := config.Scan(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	network, err := core.Network(opts.Host)
	if err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultTCPBufferSize
	}
	if opts.ClientBufferSize <= 0 {
		opts.ClientBufferSize = DefaultTCPClientBufferSize
	}
	if opts.WriteTimeoutMS <= 0 {
		opts.WriteTimeoutMS = DefaultTCPWriteTimeoutMS
	}
	if opts.KeepAlivePeriodMS <= 0 {
		opts.KeepAlivePeriodMS = DefaultTCPKeepAlivePeriodMS
	}
	tlsCfg, err := tlsx.Server(opts.TLS, opts.Host)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, tlsCfg, authz.RoleListener, authz.TCP)
	if err != nil {
		return nil, err
	}

	t := &TCPSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		addr:         net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10)),
		network:      network,
		input:        make(chan core.TransportEvent, opts.BufferSize),
		done:         make(chan struct{}),
		flush:        make(chan struct{}),
		flushed:      make(chan struct{}),
		logger:       logger,
		clients:      make(map[uint64]*tcpClient),
		conns:        make(map[net.Conn]struct{}),
		writeTimeout: time.Duration(opts.WriteTimeoutMS) * time.Millisecond,
		tlsConfig:    tlsCfg,
		auth:         authPolicy,
	}
	t.lastProcessed.Store(time.Time{})

	logger.Info("msg", " TCP sink initialized",
		"component", "tcp_sink",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port,
		"tls", tlsCfg != nil,
		"mtls", tlsCfg != nil && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert,
		"auth", authPolicy.Describe())
	tlsx.LogWarnings(logger, "tcp_sink", id, opts.TLS, true)
	authPolicy.LogStartup(logger, "tcp_sink", id, false)
	return t, nil
}

// Capabilities returns supported capabilities
func (t *TCPSink) Capabilities() []core.Capability {
	caps := []core.Capability{core.CapSessionAware, core.CapMultiSession}
	if t.tlsConfig != nil {
		caps = append(caps, core.CapTLS)
	}
	if t.auth.Enabled() {
		caps = append(caps, core.CapAuth) // authorizes clients, not just the CA
	}
	return caps
}

// Input returns the channel for sending transport events
func (t *TCPSink) Input() chan<- core.TransportEvent {
	return t.input
}

// listen creates the server listener, TLS-wrapped when configured.
// Handshake is deferred: tls.NewListener conns handshake explicitly in
// handleConn under tlsx.HandshakeTimeout, post max_connections admission.
func (t *TCPSink) listen() (net.Listener, error) {
	lc := net.ListenConfig{}
	if t.config.KeepAlive {
		lc.KeepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   time.Duration(t.config.KeepAlivePeriodMS) * time.Millisecond,
		}
	}
	ln, err := core.Listen(context.Background(), &lc, t.network, t.addr)
	if err != nil {
		return nil, err
	}
	if t.tlsConfig != nil {
		ln = tls.NewListener(ln, t.tlsConfig)
	}
	return ln, nil
}

// Start binds the listener and launches accept and broadcast loops
func (t *TCPSink) Start(ctx context.Context) error {
	if err := t.auth.Start(); err != nil {
		return err
	}
	ln, err := t.listen()
	if err != nil {
		t.auth.Close()
		return fmt.Errorf("tcp sink bind %s: %w", t.addr, err)
	}
	t.listener = ln
	t.startTime = time.Now()

	t.wg.Add(2)
	go t.acceptLoop()
	go t.broadcastLoop()

	// Pipeline context cancellation mirrors gnet engine stop: cease accepting
	// and tear down existing connections
	go func() {
		select {
		case <-ctx.Done():
			t.shutdown()
		case <-t.done:
		}
	}()

	t.logger.Info("msg", " TCP server started",
		"component", "tcp_sink",
		"instance_id", t.id,
		"addr", t.addr)
	return nil
}

// Stop gracefully shuts down the sink
func (t *TCPSink) Stop() {
	t.logger.Info("msg", "Stopping TCP sink",
		"component", "tcp_sink",
		"instance_id", t.id)

	t.shutdown()
	t.wg.Wait()
	t.auth.Close()

	t.logger.Info("msg", " TCP sink stopped",
		"component", "tcp_sink",
		"instance_id", t.id,
		"total_processed", t.totalProcessed.Load())
}

// shutdown funnels ctx-cancel and Stop() teardown through a single path.
// Clients first receive what is queued, within sink.FlushBound, so a finite
// input reaches them whole.
func (t *TCPSink) shutdown() {
	t.stopOnce.Do(func() {
		if t.listener != nil {
			t.listener.Close() // unblocks acceptLoop
			t.flushBy = time.Now().Add(sink.FlushBound(t.writeTimeout))
			close(t.flush)
			t.clientsMu.Lock()
			t.flushing = true
			clients := slices.Collect(maps.Values(t.clients))
			t.clientsMu.Unlock()
			for _, c := range clients {
				select {
				case <-c.exited:
				case <-time.After(time.Until(t.flushBy)):
				}
			}
		}
		close(t.done)
		t.clientsMu.Lock()
		for conn := range t.conns {
			conn.Close() // unblocks handshakes and per-connection readers
		}
		t.clientsMu.Unlock()
	})
}

// acceptLoop accepts client connections until listener close
func (t *TCPSink) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.logger.Warn("msg", "Accept error",
				"component", "tcp_sink",
				"error", err)
			continue
		}

		if t.config.MaxConnections > 0 && t.activeConns.Load() >= t.config.MaxConnections {
			// Load/admit race can over-admit by a conn under burst; acceptable
			t.rejectedConns.Add(1)
			conn.Close()
			continue
		}

		t.clientsMu.Lock()
		select {
		case <-t.done:
			// shutdown already swept conns; this one would outlive it
			t.clientsMu.Unlock()
			conn.Close()
			return
		default:
		}
		t.conns[conn] = struct{}{}
		t.clientsMu.Unlock()

		t.wg.Add(1)
		go t.handleConn(conn)
	}
}

// handleConn registers the client and runs its writer; a companion reader
// goroutine drains inbound bytes for disconnect detection
func (t *TCPSink) handleConn(conn net.Conn) {
	defer t.wg.Done()
	remote := conn.RemoteAddr().String()

	// Counted from accept: max_connections bounds concurrent handshakes too
	count := t.activeConns.Add(1)
	defer func() {
		conn.Close()
		t.clientsMu.Lock()
		delete(t.conns, conn)
		t.clientsMu.Unlock()
		newCount := t.activeConns.Add(-1)
		t.logger.Debug("msg", "TCP connection closed",
			"component", "tcp_sink",
			"remote_addr", remote,
			"active_connections", newCount)
	}()

	meta := map[string]any{
		"type":        "tcp_client",
		"remote_addr": remote,
	}
	var tlsState *tls.ConnectionState
	if tc, ok := conn.(*tls.Conn); ok {
		hctx, cancel := context.WithTimeout(context.Background(), tlsx.HandshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			t.tlsHandshakeErrors.Add(1)
			t.logger.Debug("msg", "TLS handshake failed",
				"component", "tcp_sink",
				"remote_addr", remote,
				"error", err)
			return
		}
		cs := tc.ConnectionState()
		tlsState = &cs
		meta["tls"] = true
		if cn := tlsx.PeerCN(cs); cn != "" {
			meta["tls_peer_cn"] = cn
		}
	}

	// Admit before registration, so an unauthorized peer never enters the
	// client map and never receives a broadcast. Under scram the viewer's
	// hello opens the exchange; without it the sink reads nothing.
	adm, err := t.auth.Admit(conn, tlsState, false, authz.ExchangeTimeout)
	if err == nil {
		err = adm.Accept()
	}
	if err != nil {
		t.rejectedConns.Add(1)
		t.logger.Warn("msg", "Connection rejected by auth policy",
			"component", "tcp_sink",
			"instance_id", t.id,
			"remote_addr", remote,
			"error", err)
		return
	}
	ident := adm.Identity
	ident.Apply(meta)

	sess := t.proxy.CreateSession(remote, meta)
	c := &tcpClient{
		send:      make(chan []byte, t.config.ClientBufferSize),
		sessionID: sess.ID,
		closed:    make(chan struct{}),
		exited:    make(chan struct{}),
	}
	defer close(c.exited)
	id := t.nextClientID.Add(1)

	t.clientsMu.Lock()
	if t.flushing {
		t.clientsMu.Unlock()
		t.proxy.RemoveSession(sess.ID)
		return
	}
	t.clients[id] = c
	t.clientsMu.Unlock()

	t.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_sink",
		"remote_addr", remote,
		"session_id", sess.ID,
		"auth_identity", ident.Name,
		"active_connections", count)

	defer func() {
		t.clientsMu.Lock()
		delete(t.clients, id)
		t.clientsMu.Unlock()
		conn.Close()
		<-c.closed // reader has exited
		t.proxy.RemoveSession(sess.ID)
	}()

	// Reader: sink is write-only; drain and discard inbound bytes to detect
	// disconnect and refresh session activity on client traffic
	go func() {
		defer close(c.closed)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				t.proxy.UpdateActivity(sess.ID)
			}
			if err != nil {
				return
			}
		}
	}()

	// Writer: synchronous lib write with deadline. A failed write means
	// the kernel buffer stayed full for the full deadline - connection is
	// dead or hopelessly stalled, so disconnect immediately.
	write := func(data []byte, deadline time.Time) bool {
		if !deadline.IsZero() {
			conn.SetWriteDeadline(deadline)
		}
		if _, err := conn.Write(data); err != nil {
			t.writeErrors.Add(1)
			t.logger.Debug("msg", "Write failed, closing client",
				"component", "tcp_sink",
				"remote_addr", remote,
				"error", err)
			return false
		}
		t.proxy.UpdateActivity(sess.ID)
		return true
	}
	for {
		select {
		case data := <-c.send:
			var deadline time.Time
			if t.writeTimeout > 0 {
				deadline = time.Now().Add(t.writeTimeout)
			}
			if !write(data, deadline) {
				return
			}
		case <-t.flushed:
			// Nothing more will be queued: write the queue, then the tail
			for len(c.send) > 0 {
				if !write(<-c.send, t.flushBy) {
					return
				}
			}
			for _, data := range t.tail {
				if !write(data, t.flushBy) {
					return
				}
			}
			return
		case <-c.closed:
			return
		case <-t.done:
			return
		}
	}
}

// broadcastLoop fans out transport events to all client queues until flush,
// which shutdown closes on Stop and on context cancellation alike.
func (t *TCPSink) broadcastLoop() {
	defer t.wg.Done()
	for {
		select {
		case <-t.flush: // first: a select with both ready picks at random
			t.flushInput()
			return
		default:
		}
		select {
		case <-t.flush:
			t.flushInput()
			return
		case event := <-t.input:
			t.totalProcessed.Add(1)
			t.lastProcessed.Store(time.Now())

			t.clientsMu.Lock()
			for _, c := range t.clients {
				select {
				case c.send <- event.Payload:
				default:
					// Slow client: drop its event, never stall siblings
					t.droppedWrites.Add(1)
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

// flushInput moves what remains of the input to tail for the writers
func (t *TCPSink) flushInput() {
	t.tail = sink.Drain(t.input)
	t.totalProcessed.Add(uint64(len(t.tail)))
	close(t.flushed)
}

// GetStats returns sink statistics
func (t *TCPSink) GetStats() sink.SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)
	details := map[string]any{
		"host":                 t.config.Host,
		"port":                 t.config.Port,
		"buffer_size":          t.config.BufferSize,
		"write_errors":         t.writeErrors.Load(),
		"dropped_writes":       t.droppedWrites.Load(),
		"rejected_conns":       t.rejectedConns.Load(),
		"tls":                  t.tlsConfig != nil,
		"tls_handshake_errors": t.tlsHandshakeErrors.Load(),
	}
	maps.Copy(details, t.auth.Stats())

	return sink.SinkStats{
		ID:                t.id,
		Type:              "tcp",
		TotalProcessed:    t.totalProcessed.Load(),
		ActiveConnections: t.activeConns.Load(),
		StartTime:         t.startTime,
		LastProcessed:     lastProc,
		Details:           details,
	}
}
