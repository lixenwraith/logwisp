package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/sink"

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
	config *config.TCPSinkOptions
	addr   string

	// Network
	listener net.Listener

	// Application
	input  chan core.TransportEvent
	logger *log.Logger

	// Client registry
	clients      map[uint64]*tcpClient
	clientsMu    sync.Mutex
	nextClientID atomic.Uint64

	// Runtime
	done      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	startTime time.Time

	writeTimeout time.Duration

	// Statistics
	activeConns    atomic.Int64
	totalProcessed atomic.Uint64
	writeErrors    atomic.Uint64
	droppedWrites  atomic.Uint64
	rejectedConns  atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// tcpClient pairs a connection with its bounded send queue.
// send is written by the broadcast loop (non-blocking) and drained by the
// writer goroutine; closed signals reader-detected disconnect.
type tcpClient struct {
	conn      net.Conn
	send      chan []byte
	sessionID string
	closed    chan struct{}
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
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
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

	t := &TCPSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		addr:         net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10)),
		input:        make(chan core.TransportEvent, opts.BufferSize),
		done:         make(chan struct{}),
		logger:       logger,
		clients:      make(map[uint64]*tcpClient),
		writeTimeout: time.Duration(opts.WriteTimeoutMS) * time.Millisecond,
	}
	t.lastProcessed.Store(time.Time{})

	logger.Info("msg", " TCP sink initialized",
		"component", "tcp_sink",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port)
	return t, nil
}

// Capabilities returns supported capabilities
func (t *TCPSink) Capabilities() []core.Capability {
	// CapTLS/CapAuth appended when transport security lands
	return []core.Capability{
		core.CapSessionAware,
		core.CapMultiSession,
	}
}

// Input returns the channel for sending transport events
func (t *TCPSink) Input() chan<- core.TransportEvent {
	return t.input
}

// listen creates the server listener.
// TLS extension point: wrap the returned listener with tls.NewListener here
// once cert config lands; no other code path changes. mTLS peer identity is
// then available via conn.(*tls.Conn).ConnectionState() in the auth hook.
func (t *TCPSink) listen() (net.Listener, error) {
	lc := net.ListenConfig{}
	if t.config.KeepAlive {
		lc.KeepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   time.Duration(t.config.KeepAlivePeriodMS) * time.Millisecond,
		}
	}
	// IPv4-only, parity with existing network sinks
	return lc.Listen(context.Background(), "tcp4", t.addr)
}

// Start binds the listener and launches accept and broadcast loops
func (t *TCPSink) Start(ctx context.Context) error {
	ln, err := t.listen()
	if err != nil {
		return fmt.Errorf("tcp sink bind %s: %w", t.addr, err)
	}
	t.listener = ln
	t.startTime = time.Now()

	t.wg.Add(2)
	go t.acceptLoop()
	go t.broadcastLoop(ctx)

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

	t.logger.Info("msg", " TCP sink stopped",
		"component", "tcp_sink",
		"instance_id", t.id,
		"total_processed", t.totalProcessed.Load())
}

// shutdown funnels ctx-cancel and Stop() teardown through a single path
func (t *TCPSink) shutdown() {
	t.stopOnce.Do(func() {
		close(t.done)
		if t.listener != nil {
			t.listener.Close() // unblocks acceptLoop
		}
		t.clientsMu.Lock()
		for _, c := range t.clients {
			c.conn.Close() // unblocks per-connection readers
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

		// Auth extension point: credential/peer verification runs here,
		// pre-registration (password preamble read or TLS peer cert check)

		t.wg.Add(1)
		go t.handleConn(conn)
	}
}

// handleConn registers the client and runs its writer; a companion reader
// goroutine drains inbound bytes for disconnect detection
func (t *TCPSink) handleConn(conn net.Conn) {
	defer t.wg.Done()
	remote := conn.RemoteAddr().String()

	sess := t.proxy.CreateSession(remote, map[string]any{
		"type":        "tcp_client",
		"remote_addr": remote,
	})

	c := &tcpClient{
		conn:      conn,
		send:      make(chan []byte, t.config.ClientBufferSize),
		sessionID: sess.ID,
		closed:    make(chan struct{}),
	}
	id := t.nextClientID.Add(1)

	t.clientsMu.Lock()
	t.clients[id] = c
	t.clientsMu.Unlock()

	count := t.activeConns.Add(1)
	t.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_sink",
		"remote_addr", remote,
		"session_id", sess.ID,
		"active_connections", count)

	defer func() {
		t.clientsMu.Lock()
		delete(t.clients, id)
		t.clientsMu.Unlock()
		conn.Close()
		<-c.closed // reader has exited
		t.proxy.RemoveSession(sess.ID)
		newCount := t.activeConns.Add(-1)
		t.logger.Debug("msg", "TCP connection closed",
			"component", "tcp_sink",
			"remote_addr", remote,
			"active_connections", newCount)
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
	// dead or hopelessly stalled, so disconnect immediately (no gnet-style
	// consecutive-error counter needed for transient async callback errors).
	for {
		select {
		case data := <-c.send:
			if t.writeTimeout > 0 {
				conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
			}
			if _, err := conn.Write(data); err != nil {
				t.writeErrors.Add(1)
				t.logger.Debug("msg", "Write failed, closing client",
					"component", "tcp_sink",
					"remote_addr", remote,
					"error", err)
				return
			}
			t.proxy.UpdateActivity(sess.ID)
		case <-c.closed:
			return
		case <-t.done:
			return
		}
	}
}

// broadcastLoop fans out transport events to all client queues, non-blocking
func (t *TCPSink) broadcastLoop(ctx context.Context) {
	defer t.wg.Done()
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

// GetStats returns sink statistics
func (t *TCPSink) GetStats() sink.SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)
	return sink.SinkStats{
		ID:                t.id,
		Type:              "tcp",
		TotalProcessed:    t.totalProcessed.Load(),
		ActiveConnections: t.activeConns.Load(),
		StartTime:         t.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"host":           t.config.Host,
			"port":           t.config.Port,
			"buffer_size":    t.config.BufferSize,
			"write_errors":   t.writeErrors.Load(),
			"dropped_writes": t.droppedWrites.Load(),
			"rejected_conns": t.rejectedConns.Load(),
		},
	}
}
