// FILE: logwisp/src/internal/source/tcp.go
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/limit"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

const (
	maxClientBufferSize = 10 * 1024 * 1024 // 10MB max per client
	maxLineLength       = 1 * 1024 * 1024  // 1MB max per log line
)

// Receives log entries via TCP connections
type TCPSource struct {
	host          string
	port          int64
	bufferSize    int64
	server        *tcpSourceServer
	subscribers   []chan core.LogEntry
	mu            sync.RWMutex
	done          chan struct{}
	engine        *gnet.Engine
	engineMu      sync.Mutex
	wg            sync.WaitGroup
	netLimiter    *limit.NetLimiter
	logger        *log.Logger
	authenticator *auth.Authenticator

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	activeConns    atomic.Int64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
	authFailures   atomic.Uint64
	authSuccesses  atomic.Uint64
}

// Creates a new TCP server source
func NewTCPSource(options map[string]any, logger *log.Logger) (*TCPSource, error) {
	host := "0.0.0.0"
	if h, ok := options["host"].(string); ok && h != "" {
		host = h
	}

	port, ok := options["port"].(int64)
	if !ok || port < 1 || port > 65535 {
		return nil, fmt.Errorf("tcp source requires valid 'port' option")
	}

	bufferSize := int64(1000)
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	t := &TCPSource{
		host:       host,
		port:       port,
		bufferSize: bufferSize,
		done:       make(chan struct{}),
		startTime:  time.Now(),
		logger:     logger,
	}
	t.lastEntryTime.Store(time.Time{})

	// Initialize net limiter if configured
	if nl, ok := options["net_limit"].(map[string]any); ok {
		if enabled, _ := nl["enabled"].(bool); enabled {
			cfg := config.NetLimitConfig{
				Enabled: true,
			}

			if rps, ok := nl["requests_per_second"].(float64); ok {
				cfg.RequestsPerSecond = rps
			}
			if burst, ok := nl["burst_size"].(int64); ok {
				cfg.BurstSize = burst
			}
			if maxPerIP, ok := nl["max_connections_per_ip"].(int64); ok {
				cfg.MaxConnectionsPerIP = maxPerIP
			}
			if maxPerUser, ok := nl["max_connections_per_user"].(int64); ok {
				cfg.MaxConnectionsPerUser = maxPerUser
			}
			if maxPerToken, ok := nl["max_connections_per_token"].(int64); ok {
				cfg.MaxConnectionsPerToken = maxPerToken
			}
			if maxTotal, ok := nl["max_connections_total"].(int64); ok {
				cfg.MaxConnectionsTotal = maxTotal
			}

			t.netLimiter = limit.NewNetLimiter(cfg, logger)
		}
	}

	return t, nil
}

func (t *TCPSource) Subscribe() <-chan core.LogEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch := make(chan core.LogEntry, t.bufferSize)
	t.subscribers = append(t.subscribers, ch)
	return ch
}

func (t *TCPSource) Start() error {
	t.server = &tcpSourceServer{
		source:  t,
		clients: make(map[gnet.Conn]*tcpClient),
	}

	// Use configured host and port
	addr := fmt.Sprintf("tcp://%s:%d", t.host, t.port)

	// Create a gnet adapter using the existing logger instance
	gnetLogger := compat.NewGnetAdapter(t.logger)

	// Start gnet server
	errChan := make(chan error, 1)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.logger.Info("msg", "TCP source server starting",
			"component", "tcp_source",
			"port", t.port)

		err := gnet.Run(t.server, addr,
			gnet.WithLogger(gnetLogger),
			gnet.WithMulticore(true),
			gnet.WithReusePort(true),
		)
		if err != nil {
			t.logger.Error("msg", "TCP source server failed",
				"component", "tcp_source",
				"port", t.port,
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
		t.logger.Info("msg", "TCP server started", "port", t.port)
		return nil
	}
}

func (t *TCPSource) Stop() {
	t.logger.Info("msg", "Stopping TCP source")
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

func (t *TCPSource) GetStats() SourceStats {
	lastEntry, _ := t.lastEntryTime.Load().(time.Time)

	var netLimitStats map[string]any
	if t.netLimiter != nil {
		netLimitStats = t.netLimiter.GetStats()
	}

	return SourceStats{
		Type:           "tcp",
		TotalEntries:   t.totalEntries.Load(),
		DroppedEntries: t.droppedEntries.Load(),
		StartTime:      t.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"port":               t.port,
			"active_connections": t.activeConns.Load(),
			"invalid_entries":    t.invalidEntries.Load(),
			"net_limit":          netLimitStats,
		},
	}
}

func (t *TCPSource) publish(entry core.LogEntry) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	t.totalEntries.Add(1)
	t.lastEntryTime.Store(entry.Time)

	dropped := false
	for _, ch := range t.subscribers {
		select {
		case ch <- entry:
		default:
			dropped = true
			t.droppedEntries.Add(1)
		}
	}

	if dropped {
		t.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
			"component", "tcp_source")
	}

	return true
}

// Represents a connected TCP client
type tcpClient struct {
	conn                gnet.Conn
	buffer              bytes.Buffer
	authenticated       bool
	authTimeout         time.Time
	session             *auth.Session
	maxBufferSeen       int
	cumulativeEncrypted int64
}

// Handles gnet events
type tcpSourceServer struct {
	gnet.BuiltinEventEngine
	source  *TCPSource
	clients map[gnet.Conn]*tcpClient
	mu      sync.RWMutex
}

func (s *tcpSourceServer) OnBoot(eng gnet.Engine) gnet.Action {
	// Store engine reference for shutdown
	s.source.engineMu.Lock()
	s.source.engine = &eng
	s.source.engineMu.Unlock()

	s.source.logger.Debug("msg", "TCP source server booted",
		"component", "tcp_source",
		"port", s.source.port)
	return gnet.None
}

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

		if !s.source.netLimiter.CheckTCP(tcpAddr) {
			s.source.logger.Warn("msg", "TCP connection net limited",
				"component", "tcp_source",
				"remote_addr", remoteAddr)
			return nil, gnet.Close
		}

		// Track connection
		s.source.netLimiter.AddConnection(remoteAddr)
	}

	// Create client state
	client := &tcpClient{
		conn:          c,
		authenticated: s.source.authenticator == nil,
	}

	if s.source.authenticator != nil {
		client.authTimeout = time.Now().Add(30 * time.Second)
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	newCount := s.source.activeConns.Add(1)
	s.source.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_source",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"requires_auth", s.source.authenticator != nil)

	// Send auth challenge if required
	if s.source.authenticator != nil {
		return []byte("AUTH_REQUIRED\n"), gnet.None
	}

	return nil, gnet.None
}

func (s *tcpSourceServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Remove client state
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

	// Remove connection tracking
	if s.source.netLimiter != nil {
		s.source.netLimiter.RemoveConnection(remoteAddr)
	}

	newCount := s.source.activeConns.Add(-1)
	s.source.logger.Debug("msg", "TCP connection closed",
		"component", "tcp_source",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"error", err)
	return gnet.None
}

func (s *tcpSourceServer) OnTraffic(c gnet.Conn) gnet.Action {
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	if !exists {
		return gnet.Close
	}

	// Read all available data
	data, err := c.Next(-1)
	if err != nil {
		s.source.logger.Error("msg", "Error reading from connection",
			"component", "tcp_source",
			"error", err)
		return gnet.Close
	}

	// Authentication phase
	if !client.authenticated {
		if time.Now().After(client.authTimeout) {
			s.source.logger.Warn("msg", "Authentication timeout",
				"component", "tcp_source",
				"remote_addr", c.RemoteAddr().String())
			return gnet.Close
		}

		client.buffer.Write(data)

		// Look for auth line
		if idx := bytes.IndexByte(client.buffer.Bytes(), '\n'); idx >= 0 {
			line := client.buffer.Bytes()[:idx]
			client.buffer.Next(idx + 1)

			parts := strings.SplitN(string(line), " ", 3)
			if len(parts) != 3 || parts[0] != "AUTH" {
				c.AsyncWrite([]byte("AUTH_FAIL\n"), nil)
				return gnet.Close
			}

			session, err := s.source.authenticator.AuthenticateTCP(parts[1], parts[2], c.RemoteAddr().String())
			if err != nil {
				s.source.authFailures.Add(1)
				s.source.logger.Warn("msg", "Authentication failed",
					"component", "tcp_source",
					"remote_addr", c.RemoteAddr().String(),
					"error", err)
				c.AsyncWrite([]byte("AUTH_FAIL\n"), nil)
				return gnet.Close
			}

			s.source.authSuccesses.Add(1)
			s.mu.Lock()
			client.authenticated = true
			client.session = session
			s.mu.Unlock()

			s.source.logger.Info("msg", "TCP client authenticated",
				"component", "tcp_source",
				"remote_addr", c.RemoteAddr().String(),
				"username", session.Username)

			c.AsyncWrite([]byte("AUTH_OK\n"), nil)
			client.buffer.Reset()
		}
		return gnet.None
	}

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

// Configure TCP source auth
func (t *TCPSource) SetAuth(authCfg *config.AuthConfig) {
	if authCfg == nil || authCfg.Type == "none" {
		return
	}

	authenticator, err := auth.New(authCfg, t.logger)
	if err != nil {
		t.logger.Error("msg", "Failed to initialize authenticator for TCP source",
			"component", "tcp_source",
			"error", err)
		return
	}
	t.authenticator = authenticator

	t.logger.Info("msg", "Authentication configured for TCP source",
		"component", "tcp_source",
		"auth_type", authCfg.Type)
}