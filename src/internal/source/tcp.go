// FILE: logwisp/src/internal/source/tcp.go
package source

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
	"logwisp/src/internal/limit"
	"logwisp/src/internal/session"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

const (
	maxClientBufferSize = 10 * 1024 * 1024 // 10MB max per client
	maxLineLength       = 1 * 1024 * 1024  // 1MB max per log line
)

// TCPSource receives log entries via TCP connections.
type TCPSource struct {
	config         *config.TCPSourceOptions
	server         *tcpSourceServer
	subscribers    []chan core.LogEntry
	mu             sync.RWMutex
	done           chan struct{}
	engine         *gnet.Engine
	engineMu       sync.Mutex
	wg             sync.WaitGroup
	sessionManager *session.Manager
	netLimiter     *limit.NetLimiter
	logger         *log.Logger

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	activeConns    atomic.Int64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// NewTCPSource creates a new TCP server source.
func NewTCPSource(opts *config.TCPSourceOptions, logger *log.Logger) (*TCPSource, error) {
	// Accept typed config - validation done in config package
	if opts == nil {
		return nil, fmt.Errorf("TCP source options cannot be nil")
	}

	t := &TCPSource{
		config:         opts,
		done:           make(chan struct{}),
		startTime:      time.Now(),
		logger:         logger,
		sessionManager: session.NewManager(core.MaxSessionTime),
	}
	t.lastEntryTime.Store(time.Time{})

	// Initialize net limiter if configured
	if opts.NetLimit != nil && (opts.NetLimit.Enabled ||
		len(opts.NetLimit.IPWhitelist) > 0 ||
		len(opts.NetLimit.IPBlacklist) > 0) {
		t.netLimiter = limit.NewNetLimiter(opts.NetLimit, logger)
	}

	return t, nil
}

// Subscribe returns a channel for receiving log entries.
func (t *TCPSource) Subscribe() <-chan core.LogEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch := make(chan core.LogEntry, t.config.BufferSize)
	t.subscribers = append(t.subscribers, ch)
	return ch
}

// Start initializes and starts the TCP server.
func (t *TCPSource) Start() error {
	t.server = &tcpSourceServer{
		source:  t,
		clients: make(map[gnet.Conn]*tcpClient),
	}

	// Register expiry callback
	t.sessionManager.RegisterExpiryCallback("tcp_source", func(sessionID, remoteAddr string) {
		t.handleSessionExpiry(sessionID, remoteAddr)
	})

	// Use configured host and port
	addr := fmt.Sprintf("tcp://%s:%d", t.config.Host, t.config.Port)

	// Create a gnet adapter using the existing logger instance
	gnetLogger := compat.NewGnetAdapter(t.logger)

	// Start gnet server
	errChan := make(chan error, 1)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.logger.Info("msg", "TCP source server starting",
			"component", "tcp_source",
			"port", t.config.Port,
		)

		err := gnet.Run(t.server, addr,
			gnet.WithLogger(gnetLogger),
			gnet.WithMulticore(true),
			gnet.WithReusePort(true),
			gnet.WithTCPKeepAlive(time.Duration(t.config.KeepAlivePeriod)*time.Millisecond),
		)
		if err != nil {
			t.logger.Error("msg", "TCP source server failed",
				"component", "tcp_source",
				"port", t.config.Port,
				"error", err)
		}
		errChan <- err
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
func (t *TCPSource) Stop() {
	t.logger.Info("msg", "Stopping TCP source")

	// Unregister callback
	t.sessionManager.UnregisterExpiryCallback("tcp_source")

	close(t.done)

	// Stop gnet engine if running
	t.engineMu.Lock()
	engine := t.engine
	t.engineMu.Unlock()

	if engine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		(*engine).Stop(ctx)
	}

	// Shutdown net limiter
	if t.netLimiter != nil {
		t.netLimiter.Shutdown()
	}

	t.wg.Wait()

	// Close subscriber channels
	t.mu.Lock()
	for _, ch := range t.subscribers {
		close(ch)
	}
	t.mu.Unlock()

	t.logger.Info("msg", "TCP source stopped")
}

// GetStats returns the source's statistics.
func (t *TCPSource) GetStats() SourceStats {
	lastEntry, _ := t.lastEntryTime.Load().(time.Time)

	var netLimitStats map[string]any
	if t.netLimiter != nil {
		netLimitStats = t.netLimiter.GetStats()
	}

	var sessionStats map[string]any
	if t.sessionManager != nil {
		sessionStats = t.sessionManager.GetStats()
	}

	return SourceStats{
		Type:           "tcp",
		TotalEntries:   t.totalEntries.Load(),
		DroppedEntries: t.droppedEntries.Load(),
		StartTime:      t.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"port":               t.config.Port,
			"active_connections": t.activeConns.Load(),
			"invalid_entries":    t.invalidEntries.Load(),
			"net_limit":          netLimitStats,
			"sessions":           sessionStats,
		},
	}
}

// tcpSourceServer implements the gnet.EventHandler interface for the source.
type tcpSourceServer struct {
	gnet.BuiltinEventEngine
	source  *TCPSource
	clients map[gnet.Conn]*tcpClient
	mu      sync.RWMutex
}

// tcpClient represents a connected TCP client and its state.
type tcpClient struct {
	conn          gnet.Conn
	buffer        *bytes.Buffer
	sessionID     string
	maxBufferSeen int
}

// OnBoot is called when the server starts.
func (s *tcpSourceServer) OnBoot(eng gnet.Engine) gnet.Action {
	// Store engine reference for shutdown
	s.source.engineMu.Lock()
	s.source.engine = &eng
	s.source.engineMu.Unlock()

	s.source.logger.Debug("msg", "TCP source server booted",
		"component", "tcp_source",
		"port", s.source.config.Port)
	return gnet.None
}

// OnOpen is called when a new connection is established.
func (s *tcpSourceServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	remoteAddr := c.RemoteAddr().String()
	s.source.logger.Debug("msg", "TCP connection attempt",
		"component", "tcp_source",
		"remote_addr", remoteAddr)

	// Check net limit
	if s.source.netLimiter != nil {
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
		if err != nil {
			s.source.logger.Warn("msg", "Failed to parse TCP address",
				"component", "tcp_source",
				"remote_addr", remoteAddr,
				"error", err)
			return nil, gnet.Close
		}

		// Check if connection is allowed
		ip := tcpAddr.IP
		if ip.To4() == nil {
			// Reject IPv6
			s.source.logger.Warn("msg", "IPv6 connection rejected",
				"component", "tcp_source",
				"remote_addr", remoteAddr)
			return []byte("IPv4-only (IPv6 not supported)\n"), gnet.Close
		}

		if !s.source.netLimiter.CheckTCP(tcpAddr) {
			s.source.logger.Warn("msg", "TCP connection net limited",
				"component", "tcp_source",
				"remote_addr", remoteAddr)
			return nil, gnet.Close
		}

		// Track connection
		if !s.source.netLimiter.TrackConnection(ip.String(), "", "") {
			s.source.logger.Warn("msg", "TCP connection limit exceeded",
				"component", "tcp_source",
				"remote_addr", remoteAddr)
			return nil, gnet.Close
		}
	}

	// Create session
	sess := s.source.sessionManager.CreateSession(remoteAddr, "tcp_source", nil)

	// Create client state
	client := &tcpClient{
		conn:      c,
		buffer:    bytes.NewBuffer(nil),
		sessionID: sess.ID,
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	s.source.activeConns.Add(1)
	s.source.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_source",
		"remote_addr", remoteAddr,
		"session_id", sess.ID)

	return out, gnet.None
}

// OnClose is called when a connection is closed.
func (s *tcpSourceServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Get client to retrieve session ID
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	if exists && client.sessionID != "" {
		// Remove session
		s.source.sessionManager.RemoveSession(client.sessionID)
	}

	// Untrack connection
	if s.source.netLimiter != nil {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", remoteAddr); err == nil {
			s.source.netLimiter.ReleaseConnection(tcpAddr.IP.String(), "", "")
		}
	}

	// Remove client state
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

	newConnectionCount := s.source.activeConns.Add(-1)
	s.source.logger.Debug("msg", "TCP connection closed",
		"component", "tcp_source",
		"remote_addr", remoteAddr,
		"active_connections", newConnectionCount,
		"error", err)
	return gnet.None
}

// OnTraffic is called when data is received from a connection.
func (s *tcpSourceServer) OnTraffic(c gnet.Conn) gnet.Action {
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	if !exists {
		return gnet.Close
	}

	// Update session activity when client sends data
	if client.sessionID != "" {
		s.source.sessionManager.UpdateActivity(client.sessionID)
	}

	// Read all available data
	data, err := c.Next(-1)
	if err != nil {
		s.source.logger.Error("msg", "Error reading from connection",
			"component", "tcp_source",
			"error", err)
		return gnet.Close
	}

	return s.processLogData(c, client, data)
}

// processLogData processes raw data from a client, parsing and publishing log entries.
func (s *tcpSourceServer) processLogData(c gnet.Conn, client *tcpClient, data []byte) gnet.Action {
	// Check if appending the new data would exceed the client buffer limit.
	if client.buffer.Len()+len(data) > maxClientBufferSize {
		s.source.logger.Warn("msg", "Client buffer limit exceeded, closing connection.",
			"component", "tcp_source",
			"remote_addr", c.RemoteAddr().String(),
			"buffer_size", client.buffer.Len(),
			"incoming_size", len(data),
			"limit", maxClientBufferSize)
		s.source.invalidEntries.Add(1)
		return gnet.Close
	}

	// Append to client buffer
	client.buffer.Write(data)

	// Track high buffer
	if client.buffer.Len() > client.maxBufferSeen {
		client.maxBufferSeen = client.buffer.Len()
	}

	// Check for suspiciously long lines before attempting to read
	if client.buffer.Len() > maxLineLength {
		// Scan for newline in current buffer
		bufBytes := client.buffer.Bytes()
		hasNewline := false
		for _, b := range bufBytes {
			if b == '\n' {
				hasNewline = true
				break
			}
		}

		if !hasNewline {
			s.source.logger.Warn("msg", "Line too long without newline",
				"component", "tcp_source",
				"remote_addr", c.RemoteAddr().String(),
				"buffer_size", client.buffer.Len())
			s.source.invalidEntries.Add(1)
			return gnet.Close
		}
	}

	// Process complete lines
	for {
		line, err := client.buffer.ReadBytes('\n')
		if err != nil {
			// No complete line available
			break
		}

		// Trim newline
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}

		// Capture raw line size before parsing
		rawSize := int64(len(line))

		// Parse JSON log entry
		var entry core.LogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			s.source.invalidEntries.Add(1)
			s.source.logger.Debug("msg", "Invalid JSON log entry",
				"component", "tcp_source",
				"error", err,
				"data", string(line))
			continue
		}

		// Validate and set defaults
		if entry.Message == "" {
			s.source.invalidEntries.Add(1)
			continue
		}
		if entry.Time.IsZero() {
			entry.Time = time.Now()
		}
		if entry.Source == "" {
			entry.Source = "tcp"
		}

		// Set raw size
		entry.RawSize = rawSize

		// Publish the entry
		s.source.publish(entry)
	}

	return gnet.None
}

// publish sends a log entry to all subscribers.
func (t *TCPSource) publish(entry core.LogEntry) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	t.totalEntries.Add(1)
	t.lastEntryTime.Store(entry.Time)

	for _, ch := range t.subscribers {
		select {
		case ch <- entry:
		default:
			t.droppedEntries.Add(1)
			t.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
				"component", "tcp_source")
		}
	}
}

// handleSessionExpiry is the callback for cleaning up expired sessions.
func (t *TCPSource) handleSessionExpiry(sessionID, remoteAddr string) {
	t.server.mu.RLock()
	defer t.server.mu.RUnlock()

	// Find connection by session ID
	for conn, client := range t.server.clients {
		if client.sessionID == sessionID {
			t.logger.Info("msg", "Closing expired session connection",
				"component", "tcp_source",
				"session_id", sessionID,
				"remote_addr", remoteAddr)

			// Close connection
			conn.Close()
			return
		}
	}
}