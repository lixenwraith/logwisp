package tcp

import (
	"bytes"
	"context"
	"fmt"
	"net"
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
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

func init() {
	if err := plugin.RegisterSink("tcp", NewTCPSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register tcp sink: %v", err))
	}
}

// TCPSink streams log entries to connected TCP clients
type TCPSink struct {
	// Plugin identity and session management
	id    string
	proxy *session.Proxy

	// Configuration
	config *config.TCPSinkOptions

	// Network
	server   *tcpServer
	engine   *gnet.Engine
	engineMu sync.Mutex
	booted   chan struct{}

	// Application
	input  chan core.TransportEvent
	logger *log.Logger

	// Runtime
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time

	// Statistics
	activeConns    atomic.Int64
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time

	// Error tracking
	writeErrors            atomic.Uint64
	consecutiveWriteErrors map[gnet.Conn]int
	errorMu                sync.Mutex
}

const (
	// Server lifecycle
	TCPServerStartTimeout    = 2 * time.Second
	TCPServerShutdownTimeout = 2 * time.Second

	// Connection management
	TCPMaxConsecutiveWriteErrors = 3
	TCPMaxPort                   = 65535

	// Defaults
	DefaultTCPHost            = "0.0.0.0"
	DefaultTCPBufferSize      = 1000
	DefaultTCPWriteTimeoutMS  = 5000
	DefaultTCPKeepAlivePeriod = 30000
)

// NewTCPSinkPlugin creates a TCP sink through plugin factory
func NewTCPSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	// Create config struct with defaults
	opts := &config.TCPSinkOptions{
		Host:      DefaultTCPHost,
		Port:      0,
		KeepAlive: true,
	}

	// Parse config map into struct
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}

	// Defaults
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultTCPBufferSize
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = DefaultTCPWriteTimeoutMS
	}
	if opts.KeepAlivePeriod <= 0 {
		opts.KeepAlivePeriod = DefaultTCPKeepAlivePeriod
	}

	t := &TCPSink{
		id:                     id,
		proxy:                  proxy,
		config:                 opts,
		input:                  make(chan core.TransportEvent, opts.BufferSize),
		done:                   make(chan struct{}),
		logger:                 logger,
		consecutiveWriteErrors: make(map[gnet.Conn]int),
	}
	t.lastProcessed.Store(time.Time{})

	logger.Info("msg", "TCP sink initialized",
		"component", "tcp_sink",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port)

	return t, nil
}

// Capabilities returns supported capabilities
func (t *TCPSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
		core.CapMultiSession,
	}
}

// Input returns the channel for sending transport events
func (t *TCPSink) Input() chan<- core.TransportEvent {
	return t.input
}

// Start initializes the TCP server and begins the broadcast loop
func (t *TCPSink) Start(ctx context.Context) error {
	t.server = &tcpServer{
		sink:    t,
		clients: make(map[gnet.Conn]*tcpClient),
	}
	// Fresh channel per Start
	t.booted = make(chan struct{})

	t.startTime = time.Now()

	// Start broadcast loop
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.broadcastLoop(ctx)
	}()

	// Configure gnet
	addr := fmt.Sprintf("tcp://%s:%d", t.config.Host, t.config.Port)
	gnetLogger := compat.NewGnetAdapter(t.logger)

	opts := []gnet.Option{
		gnet.WithLogger(gnetLogger),
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
	}

	// Apply TCP keep-alive settings from config
	if t.config.KeepAlive {
		opts = append(opts,
			gnet.WithTCPKeepAlive(time.Duration(t.config.KeepAlivePeriod)*time.Millisecond),
		)
	}

	// Start gnet server
	errChan := make(chan error, 1)
	go func() {
		t.logger.Info("msg", "Starting TCP server",
			"component", "tcp_sink",
			"host", t.config.Host,
			"port", t.config.Port)

		err := gnet.Run(t.server, addr, opts...)
		if err != nil {
			t.logger.Error("msg", "TCP server failed",
				"component", "tcp_sink",
				"error", err)
		}
		errChan <- err
	}()

	// Monitor context for shutdown
	go func() {
		<-ctx.Done()
		t.engineMu.Lock()
		if t.engine != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			(*t.engine).Stop(shutdownCtx)
		}
		t.engineMu.Unlock()
	}()

	// Wait briefly for server to start or fail
	select {
	case err := <-errChan:
		close(t.done)
		t.wg.Wait()
		return err
	// Bind confirmation via OnBoot
	case <-t.booted:
		t.logger.Info("msg", "TCP server started",
			"component", "tcp_sink",
			"instance_id", t.id,
			"port", t.config.Port)
		return nil
	// Timeout failure
	case <-time.After(TCPServerStartTimeout):
		t.engineMu.Lock()
		if t.engine != nil {
			stopCtx, cancel := context.WithTimeout(context.Background(), TCPServerShutdownTimeout)
			(*t.engine).Stop(stopCtx)
			cancel()
		}
		t.engineMu.Unlock()
		close(t.done)
		t.wg.Wait()
		return fmt.Errorf("tcp sink start timeout on %s", addr)
	}
}

// Stop gracefully shuts down the TCP sink
func (t *TCPSink) Stop() {
	t.logger.Info("msg", "Stopping TCP sink",
		"component", "tcp_sink",
		"instance_id", t.id)

	close(t.done)

	// Stop gnet engine
	t.engineMu.Lock()
	engine := t.engine
	t.engineMu.Unlock()

	if engine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), TCPServerShutdownTimeout)
		defer cancel()
		(*engine).Stop(ctx)
	}

	t.wg.Wait()

	t.logger.Info("msg", "TCP sink stopped",
		"component", "tcp_sink",
		"instance_id", t.id,
		"total_processed", t.totalProcessed.Load())
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
			"host":         t.config.Host,
			"port":         t.config.Port,
			"buffer_size":  t.config.BufferSize,
			"write_errors": t.writeErrors.Load(),
		},
	}
}

// tcpServer implements gnet.EventHandler
type tcpServer struct {
	gnet.BuiltinEventEngine
	sink    *TCPSink
	clients map[gnet.Conn]*tcpClient
	mu      sync.RWMutex
}

// tcpClient represents a connected TCP client
type tcpClient struct {
	conn      gnet.Conn
	buffer    bytes.Buffer
	sessionID string
}

// broadcastLoop sends transport events to all connected clients
func (t *TCPSink) broadcastLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-t.input:
			if !ok {
				return
			}
			t.totalProcessed.Add(1)
			t.lastProcessed.Store(time.Now())
			t.broadcastData(event.Payload)
		case <-t.done:
			return
		}
	}
}

// OnBoot is called when the server starts
func (s *tcpServer) OnBoot(eng gnet.Engine) gnet.Action {
	s.sink.engineMu.Lock()
	s.sink.engine = &eng
	s.sink.engineMu.Unlock()

	// Listener is bound at this point; unblock Start
	close(s.sink.booted)

	s.sink.logger.Debug("msg", "TCP server booted",
		"component", "tcp_sink",
		"instance_id", s.sink.id)
	return gnet.None
}

// OnOpen is called when a new connection is established
func (s *tcpServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	remoteAddr := c.RemoteAddr()
	remoteAddrStr := remoteAddr.String()

	s.sink.logger.Debug("msg", "TCP connection attempt",
		"component", "tcp_sink",
		"remote_addr", remoteAddrStr)

	// Reject IPv6 connections
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		if tcpAddr.IP.To4() == nil {
			s.sink.logger.Warn("msg", "IPv6 connection rejected",
				"component", "tcp_sink",
				"remote_addr", remoteAddrStr)
			return []byte("IPv4-only (IPv6 not supported)\n"), gnet.Close
		}
	}

	// Apply write timeout from config
	if s.sink.config.WriteTimeout > 0 {
		c.SetWriteDeadline(time.Now().Add(time.Duration(s.sink.config.WriteTimeout) * time.Millisecond))
	}

	// Create session via proxy
	sess := s.sink.proxy.CreateSession(remoteAddrStr, map[string]any{
		"type":        "tcp_client",
		"remote_addr": remoteAddrStr,
	})

	client := &tcpClient{
		conn:      c,
		sessionID: sess.ID,
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	newCount := s.sink.activeConns.Add(1)
	s.sink.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_sink",
		"remote_addr", remoteAddrStr,
		"session_id", sess.ID,
		"active_connections", newCount)

	return nil, gnet.None
}

// OnClose is called when a connection is closed
func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddrStr := c.RemoteAddr().String()

	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	if exists && client.sessionID != "" {
		s.sink.proxy.RemoveSession(client.sessionID)
		s.sink.logger.Debug("msg", "Session removed",
			"component", "tcp_sink",
			"session_id", client.sessionID,
			"remote_addr", remoteAddrStr)
	}

	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

	s.sink.errorMu.Lock()
	delete(s.sink.consecutiveWriteErrors, c)
	s.sink.errorMu.Unlock()

	newCount := s.sink.activeConns.Add(-1)
	s.sink.logger.Debug("msg", "TCP connection closed",
		"component", "tcp_sink",
		"remote_addr", remoteAddrStr,
		"active_connections", newCount,
		"error", err)

	return gnet.None
}

// OnTraffic is called when data is received from a connection
func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	// Update session activity
	if exists && client.sessionID != "" {
		s.sink.proxy.UpdateActivity(client.sessionID)
	}

	// TCP sink doesn't expect data from clients, discard safely
	if bufLen := c.InboundBuffered(); bufLen > 0 {
		c.Next(bufLen)
	}
	return gnet.None
}

// broadcastData sends data to all connected clients
func (t *TCPSink) broadcastData(data []byte) {
	t.server.mu.RLock()
	defer t.server.mu.RUnlock()

	for conn, client := range t.server.clients {
		// Update session activity
		if client.sessionID != "" {
			t.proxy.UpdateActivity(client.sessionID)
		}

		// Refresh write deadline on each write if configured
		if t.config.WriteTimeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(time.Duration(t.config.WriteTimeout) * time.Millisecond))
		}

		conn.AsyncWrite(data, func(c gnet.Conn, err error) error {
			if err != nil {
				t.writeErrors.Add(1)
				t.handleWriteError(c, err)
			} else {
				t.errorMu.Lock()
				delete(t.consecutiveWriteErrors, c)
				t.errorMu.Unlock()
			}
			return nil
		})
	}
}

// handleWriteError manages errors during async writes
func (t *TCPSink) handleWriteError(c gnet.Conn, err error) {
	remoteAddrStr := c.RemoteAddr().String()

	t.errorMu.Lock()
	defer t.errorMu.Unlock()

	t.consecutiveWriteErrors[c]++
	errorCount := t.consecutiveWriteErrors[c]

	t.logger.Debug("msg", "AsyncWrite error",
		"component", "tcp_sink",
		"remote_addr", remoteAddrStr,
		"error", err,
		"consecutive_errors", errorCount)

	// Close connection max consecutive write errors
	if errorCount >= TCPMaxConsecutiveWriteErrors {
		t.logger.Warn("msg", "Closing connection due to repeated write errors",
			"component", "tcp_sink",
			"remote_addr", remoteAddrStr,
			"error_count", errorCount)
		delete(t.consecutiveWriteErrors, c)
		c.Close()
	}
}
