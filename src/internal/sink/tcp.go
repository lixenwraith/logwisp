// FILE: logwisp/src/internal/sink/tcp.go
package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	"logwisp/src/internal/network"
	"logwisp/src/internal/session"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

// TCPSink streams log entries to connected TCP clients.
type TCPSink struct {
	// Configuration
	config *config.TCPSinkOptions

	// Network
	server     *tcpServer
	engine     *gnet.Engine
	engineMu   sync.Mutex
	netLimiter *network.NetLimiter

	// Application
	input     chan core.LogEntry
	formatter format.Formatter
	logger    *log.Logger

	// Runtime
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time

	// Security & Session
	sessionManager *session.Manager

	// Statistics
	activeConns    atomic.Int64
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time

	// Error tracking
	writeErrors            atomic.Uint64
	consecutiveWriteErrors map[gnet.Conn]int
	errorMu                sync.Mutex
}

// TCPConfig holds configuration for the TCPSink.
type TCPConfig struct {
	Host       string
	Port       int64
	BufferSize int64
	Heartbeat  *config.HeartbeatConfig
	ACL        *config.ACLConfig
}

// NewTCPSink creates a new TCP streaming sink.
func NewTCPSink(opts *config.TCPSinkOptions, logger *log.Logger, formatter format.Formatter) (*TCPSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("TCP sink options cannot be nil")
	}

	t := &TCPSink{
		config:                 opts,
		input:                  make(chan core.LogEntry, opts.BufferSize),
		done:                   make(chan struct{}),
		startTime:              time.Now(),
		logger:                 logger,
		formatter:              formatter,
		consecutiveWriteErrors: make(map[gnet.Conn]int),
		sessionManager:         session.NewManager(30 * time.Minute),
	}
	t.lastProcessed.Store(time.Time{})

	// Initialize net limiter with pointer
	if opts.ACL != nil && (opts.ACL.Enabled ||
		len(opts.ACL.IPWhitelist) > 0 ||
		len(opts.ACL.IPBlacklist) > 0) {
		t.netLimiter = network.NewNetLimiter(opts.ACL, logger)
	}

	return t, nil
}

// Input returns the channel for sending log entries.
func (t *TCPSink) Input() chan<- core.LogEntry {
	return t.input
}

// Start initializes the TCP server and begins the broadcast loop.
func (t *TCPSink) Start(ctx context.Context) error {
	t.server = &tcpServer{
		sink:    t,
		clients: make(map[gnet.Conn]*tcpClient),
	}

	// Register expiry callback
	t.sessionManager.RegisterExpiryCallback("tcp_sink", func(sessionID, remoteAddr string) {
		t.handleSessionExpiry(sessionID, remoteAddr)
	})

	// Start log broadcast loop
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.broadcastLoop(ctx)
	}()

	// Configure gnet options
	addr := fmt.Sprintf("tcp://%s:%d", t.config.Host, t.config.Port)

	// Create a gnet adapter using the existing logger instance
	gnetLogger := compat.NewGnetAdapter(t.logger)

	var opts []gnet.Option
	opts = append(opts,
		gnet.WithLogger(gnetLogger),
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
	)

	// Start gnet server
	errChan := make(chan error, 1)
	go func() {
		t.logger.Info("msg", "Starting TCP server",
			"component", "tcp_sink",
			"port", t.config.Port)

		err := gnet.Run(t.server, addr, opts...)
		if err != nil {
			t.logger.Error("msg", "TCP server failed",
				"component", "tcp_sink",
				"port", t.config.Port,
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
		// Server failed immediately
		close(t.done)
		t.wg.Wait()
		return err
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
		t.logger.Info("msg", "TCP server started", "port", t.config.Port)
		return nil
	}
}

// Stop gracefully shuts down the TCP server.
func (t *TCPSink) Stop() {
	t.logger.Info("msg", "Stopping TCP sink")

	// Unregister callback
	t.sessionManager.UnregisterExpiryCallback("tcp_sink")

	// Signal broadcast loop to stop
	close(t.done)

	// Stop gnet engine if running
	t.engineMu.Lock()
	engine := t.engine
	t.engineMu.Unlock()

	if engine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		(*engine).Stop(ctx) // Dereference the pointer
	}

	// Wait for broadcast loop to finish
	t.wg.Wait()

	// Stop session manager
	if t.sessionManager != nil {
		t.sessionManager.Stop()
	}

	t.logger.Info("msg", "TCP sink stopped")
}

// GetStats returns the sink's statistics.
func (t *TCPSink) GetStats() SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)

	var netLimitStats map[string]any
	if t.netLimiter != nil {
		netLimitStats = t.netLimiter.GetStats()
	}

	var sessionStats map[string]any
	if t.sessionManager != nil {
		sessionStats = t.sessionManager.GetStats()
	}

	return SinkStats{
		Type:              "tcp",
		TotalProcessed:    t.totalProcessed.Load(),
		ActiveConnections: t.activeConns.Load(),
		StartTime:         t.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"port":        t.config.Port,
			"buffer_size": t.config.BufferSize,
			"net_limit":   netLimitStats,
			"sessions":    sessionStats,
		},
	}
}

// GetActiveConnections returns the current number of active connections.
func (t *TCPSink) GetActiveConnections() int64 {
	return t.activeConns.Load()
}

// tcpServer implements the gnet.EventHandler interface for the TCP sink.
type tcpServer struct {
	gnet.BuiltinEventEngine
	sink    *TCPSink
	clients map[gnet.Conn]*tcpClient
	mu      sync.RWMutex
}

// tcpClient represents a connected TCP client.
type tcpClient struct {
	conn      gnet.Conn
	buffer    bytes.Buffer
	sessionID string
}

// broadcastLoop manages the central broadcasting of log entries to all clients.
func (t *TCPSink) broadcastLoop(ctx context.Context) {
	var ticker *time.Ticker
	var tickerChan <-chan time.Time

	if t.config.Heartbeat != nil && t.config.Heartbeat.Enabled {
		ticker = time.NewTicker(time.Duration(t.config.Heartbeat.IntervalMS) * time.Millisecond)
		tickerChan = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-t.input:
			if !ok {
				return
			}
			t.totalProcessed.Add(1)
			t.lastProcessed.Store(time.Now())

			data, err := t.formatter.Format(entry)
			if err != nil {
				t.logger.Error("msg", "Failed to format log entry",
					"component", "tcp_sink",
					"error", err,
					"entry_source", entry.Source)
				continue
			}
			t.broadcastData(data)

		case <-tickerChan:
			heartbeatEntry := t.createHeartbeatEntry()
			data, err := t.formatter.Format(heartbeatEntry)
			if err != nil {
				t.logger.Error("msg", "Failed to format heartbeat",
					"component", "tcp_sink",
					"error", err)
				continue
			}
			t.broadcastData(data)

		case <-t.done:
			return
		}
	}
}

// OnBoot is called when the server starts.
func (s *tcpServer) OnBoot(eng gnet.Engine) gnet.Action {
	// Store engine reference for shutdown
	s.sink.engineMu.Lock()
	s.sink.engine = &eng
	s.sink.engineMu.Unlock()

	s.sink.logger.Debug("msg", "TCP server booted",
		"component", "tcp_sink",
		"port", s.sink.config.Port)
	return gnet.None
}

// OnOpen is called when a new connection is established.
func (s *tcpServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	remoteAddr := c.RemoteAddr()
	remoteAddrStr := remoteAddr.String()
	s.sink.logger.Debug("msg", "TCP connection attempt", "remote_addr", remoteAddrStr)

	// Reject IPv6 connections
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		if tcpAddr.IP.To4() == nil {
			return []byte("IPv4-only (IPv6 not supported)\n"), gnet.Close
		}
	}

	// Check net limit
	if s.sink.netLimiter != nil {
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteAddrStr)
		if err != nil {
			s.sink.logger.Warn("msg", "Failed to parse TCP address",
				"remote_addr", remoteAddrStr,
				"error", err)
			return nil, gnet.Close
		}

		if !s.sink.netLimiter.CheckTCP(tcpAddr) {
			s.sink.logger.Warn("msg", "TCP connection net limited",
				"remote_addr", remoteAddrStr)
			return nil, gnet.Close
		}

		// Register connection post-establishment
		s.sink.netLimiter.RegisterConnection(remoteAddrStr)
	}

	// Create session for tracking
	sess := s.sink.sessionManager.CreateSession(remoteAddrStr, "tcp_sink", nil)

	// TCP Sink accepts all connections without authentication
	client := &tcpClient{
		conn:      c,
		buffer:    bytes.Buffer{},
		sessionID: sess.ID,
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	newCount := s.sink.activeConns.Add(1)
	s.sink.logger.Debug("msg", "TCP connection opened",
		"remote_addr", remoteAddr,
		"session_id", sess.ID,
		"active_connections", newCount)

	return nil, gnet.None
}

// OnClose is called when a connection is closed.
func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddrStr := c.RemoteAddr().String()

	// Get client to retrieve session ID
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	if exists && client.sessionID != "" {
		// Remove session
		s.sink.sessionManager.RemoveSession(client.sessionID)
		s.sink.logger.Debug("msg", "Session removed",
			"component", "tcp_sink",
			"session_id", client.sessionID,
			"remote_addr", remoteAddrStr)
	}

	// Remove client state
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

	// Clean up write error tracking
	s.sink.errorMu.Lock()
	delete(s.sink.consecutiveWriteErrors, c)
	s.sink.errorMu.Unlock()

	// Release connection
	if s.sink.netLimiter != nil {
		s.sink.netLimiter.ReleaseConnection(remoteAddrStr)
	}

	newCount := s.sink.activeConns.Add(-1)
	s.sink.logger.Debug("msg", "TCP connection closed",
		"remote_addr", remoteAddrStr,
		"active_connections", newCount,
		"error", err)
	return gnet.None
}

// OnTraffic is called when data is received from a connection.
func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	// Update session activity when client sends data
	if exists && client.sessionID != "" {
		s.sink.sessionManager.UpdateActivity(client.sessionID)
	}

	// TCP Sink doesn't expect any data from clients, discard all
	c.Discard(-1)
	return gnet.None
}

// handleSessionExpiry is the callback for cleaning up expired sessions.
func (t *TCPSink) handleSessionExpiry(sessionID, remoteAddr string) {
	t.server.mu.RLock()
	defer t.server.mu.RUnlock()

	// Find connection by session ID
	for conn, client := range t.server.clients {
		if client.sessionID == sessionID {
			t.logger.Info("msg", "Closing expired session connection",
				"component", "tcp_sink",
				"session_id", sessionID,
				"remote_addr", remoteAddr)

			// Close connection
			conn.Close()
			return
		}
	}
}

// broadcastData sends a formatted byte slice to all connected clients.
func (t *TCPSink) broadcastData(data []byte) {
	t.server.mu.RLock()
	defer t.server.mu.RUnlock()

	// Track clients to remove after iteration
	var staleClients []gnet.Conn

	for conn, client := range t.server.clients {
		// Update session activity before sending data
		if client.sessionID != "" {
			if !t.sessionManager.IsSessionActive(client.sessionID) {
				// Session expired, mark for cleanup
				staleClients = append(staleClients, conn)
				continue
			}
			t.sessionManager.UpdateActivity(client.sessionID)
		}

		conn.AsyncWrite(data, func(c gnet.Conn, err error) error {
			if err != nil {
				t.writeErrors.Add(1)
				t.handleWriteError(c, err)
			} else {
				// Reset consecutive error count on success
				t.errorMu.Lock()
				delete(t.consecutiveWriteErrors, c)
				t.errorMu.Unlock()
			}
			return nil
		})
	}

	// Clean up stale connections outside the read lock
	if len(staleClients) > 0 {
		go t.cleanupStaleConnections(staleClients)
	}
}

// handleWriteError manages errors during async writes, closing faulty connections.
func (t *TCPSink) handleWriteError(c gnet.Conn, err error) {
	remoteAddrStr := c.RemoteAddr().String()

	t.errorMu.Lock()
	defer t.errorMu.Unlock()

	// Track consecutive errors per connection
	if t.consecutiveWriteErrors == nil {
		t.consecutiveWriteErrors = make(map[gnet.Conn]int)
	}

	t.consecutiveWriteErrors[c]++
	errorCount := t.consecutiveWriteErrors[c]

	t.logger.Debug("msg", "AsyncWrite error",
		"component", "tcp_sink",
		"remote_addr", remoteAddrStr,
		"error", err,
		"consecutive_errors", errorCount)

	// Close connection after 3 consecutive write errors
	if errorCount >= 3 {
		t.logger.Warn("msg", "Closing connection due to repeated write errors",
			"component", "tcp_sink",
			"remote_addr", remoteAddrStr,
			"error_count", errorCount)
		delete(t.consecutiveWriteErrors, c)
		c.Close()
	}
}

// createHeartbeatEntry generates a new heartbeat log entry.
func (t *TCPSink) createHeartbeatEntry() core.LogEntry {
	message := "heartbeat"

	// Build fields for heartbeat metadata
	fields := make(map[string]any)
	fields["type"] = "heartbeat"

	if t.config.Heartbeat.IncludeStats {
		fields["active_connections"] = t.activeConns.Load()
		fields["uptime_seconds"] = int64(time.Since(t.startTime).Seconds())
	}

	fieldsJSON, _ := json.Marshal(fields)

	return core.LogEntry{
		Time:    time.Now(),
		Source:  "logwisp-tcp",
		Level:   "INFO",
		Message: message,
		Fields:  fieldsJSON,
	}
}

// cleanupStaleConnections closes connections associated with expired sessions.
func (t *TCPSink) cleanupStaleConnections(staleConns []gnet.Conn) {
	for _, conn := range staleConns {
		t.logger.Info("msg", "Closing stale connection",
			"component", "tcp_sink",
			"remote_addr", conn.RemoteAddr().String())
		conn.Close()
	}
}