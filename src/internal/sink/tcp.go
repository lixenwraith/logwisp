// FILE: logwisp/src/internal/sink/tcp.go
package sink

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
	"logwisp/src/internal/format"
	"logwisp/src/internal/limit"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

// Streams log entries via TCP
type TCPSink struct {
	// C
	input         chan core.LogEntry
	config        TCPConfig
	server        *tcpServer
	done          chan struct{}
	activeConns   atomic.Int64
	startTime     time.Time
	engine        *gnet.Engine
	engineMu      sync.Mutex
	wg            sync.WaitGroup
	netLimiter    *limit.NetLimiter
	logger        *log.Logger
	formatter     format.Formatter
	authenticator *auth.Authenticator

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
	authFailures   atomic.Uint64
	authSuccesses  atomic.Uint64

	// Write error tracking
	writeErrors            atomic.Uint64
	consecutiveWriteErrors map[gnet.Conn]int
	errorMu                sync.Mutex
}

// Holds TCP sink configuration
type TCPConfig struct {
	Host       string
	Port       int64
	BufferSize int64
	Heartbeat  *config.HeartbeatConfig
	NetLimit   *config.NetLimitConfig
}

// Creates a new TCP streaming sink
func NewTCPSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*TCPSink, error) {
	cfg := TCPConfig{
		Host:       "0.0.0.0",
		Port:       int64(9090),
		BufferSize: int64(1000),
	}

	// Extract configuration from options
	if host, ok := options["host"].(string); ok && host != "" {
		cfg.Host = host
	}
	if port, ok := options["port"].(int64); ok {
		cfg.Port = port
	}
	if bufSize, ok := options["buffer_size"].(int64); ok {
		cfg.BufferSize = bufSize
	}

	// Extract heartbeat config
	if hb, ok := options["heartbeat"].(map[string]any); ok {
		cfg.Heartbeat = &config.HeartbeatConfig{}
		cfg.Heartbeat.Enabled, _ = hb["enabled"].(bool)
		if interval, ok := hb["interval_seconds"].(int64); ok {
			cfg.Heartbeat.IntervalSeconds = interval
		}
		cfg.Heartbeat.IncludeTimestamp, _ = hb["include_timestamp"].(bool)
		cfg.Heartbeat.IncludeStats, _ = hb["include_stats"].(bool)
		if hbFormat, ok := hb["format"].(string); ok {
			cfg.Heartbeat.Format = hbFormat
		}
	}

	// Extract net limit config
	if nl, ok := options["net_limit"].(map[string]any); ok {
		cfg.NetLimit = &config.NetLimitConfig{}
		cfg.NetLimit.Enabled, _ = nl["enabled"].(bool)
		if rps, ok := nl["requests_per_second"].(float64); ok {
			cfg.NetLimit.RequestsPerSecond = rps
		}
		if burst, ok := nl["burst_size"].(int64); ok {
			cfg.NetLimit.BurstSize = burst
		}
		if respCode, ok := nl["response_code"].(int64); ok {
			cfg.NetLimit.ResponseCode = respCode
		}
		if msg, ok := nl["response_message"].(string); ok {
			cfg.NetLimit.ResponseMessage = msg
		}
		if maxPerIP, ok := nl["max_connections_per_ip"].(int64); ok {
			cfg.NetLimit.MaxConnectionsPerIP = maxPerIP
		}
		if maxPerUser, ok := nl["max_connections_per_user"].(int64); ok {
			cfg.NetLimit.MaxConnectionsPerUser = maxPerUser
		}
		if maxPerToken, ok := nl["max_connections_per_token"].(int64); ok {
			cfg.NetLimit.MaxConnectionsPerToken = maxPerToken
		}
		if maxTotal, ok := nl["max_connections_total"].(int64); ok {
			cfg.NetLimit.MaxConnectionsTotal = maxTotal
		}
		if ipWhitelist, ok := nl["ip_whitelist"].([]any); ok {
			cfg.NetLimit.IPWhitelist = make([]string, 0, len(ipWhitelist))
			for _, entry := range ipWhitelist {
				if str, ok := entry.(string); ok {
					cfg.NetLimit.IPWhitelist = append(cfg.NetLimit.IPWhitelist, str)
				}
			}
		}
		if ipBlacklist, ok := nl["ip_blacklist"].([]any); ok {
			cfg.NetLimit.IPBlacklist = make([]string, 0, len(ipBlacklist))
			for _, entry := range ipBlacklist {
				if str, ok := entry.(string); ok {
					cfg.NetLimit.IPBlacklist = append(cfg.NetLimit.IPBlacklist, str)
				}
			}
		}
	}

	t := &TCPSink{
		input:     make(chan core.LogEntry, cfg.BufferSize),
		config:    cfg,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	t.lastProcessed.Store(time.Time{})

	// Initialize net limiter
	if cfg.NetLimit != nil && cfg.NetLimit.Enabled {
		t.netLimiter = limit.NewNetLimiter(*cfg.NetLimit, logger)
	}

	return t, nil
}

func (t *TCPSink) Input() chan<- core.LogEntry {
	return t.input
}

func (t *TCPSink) Start(ctx context.Context) error {
	t.server = &tcpServer{
		sink:    t,
		clients: make(map[gnet.Conn]*tcpClient),
	}

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
			"port", t.config.Port,
			"auth", t.authenticator != nil)

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

func (t *TCPSink) Stop() {
	t.logger.Info("msg", "Stopping TCP sink")
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

	t.logger.Info("msg", "TCP sink stopped")
}

func (t *TCPSink) GetStats() SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)

	var netLimitStats map[string]any
	if t.netLimiter != nil {
		netLimitStats = t.netLimiter.GetStats()
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
			"auth":        map[string]any{"enabled": false},
		},
	}
}

func (t *TCPSink) broadcastLoop(ctx context.Context) {
	var ticker *time.Ticker
	var tickerChan <-chan time.Time

	if t.config.Heartbeat != nil && t.config.Heartbeat.Enabled {
		ticker = time.NewTicker(time.Duration(t.config.Heartbeat.IntervalSeconds) * time.Second)
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

func (t *TCPSink) broadcastData(data []byte) {
	t.server.mu.RLock()
	defer t.server.mu.RUnlock()

	for conn, client := range t.server.clients {
		if client.authenticated {
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
	}
}

// Handle write errors with threshold-based connection termination
func (t *TCPSink) handleWriteError(c gnet.Conn, err error) {
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
		"remote_addr", c.RemoteAddr(),
		"error", err,
		"consecutive_errors", errorCount)

	// Close connection after 3 consecutive write errors
	if errorCount >= 3 {
		t.logger.Warn("msg", "Closing connection due to repeated write errors",
			"component", "tcp_sink",
			"remote_addr", c.RemoteAddr(),
			"error_count", errorCount)
		delete(t.consecutiveWriteErrors, c)
		c.Close()
	}
}

// Create heartbeat as a proper LogEntry
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

// Returns the current number of connections
func (t *TCPSink) GetActiveConnections() int64 {
	return t.activeConns.Load()
}

// Represents a connected TCP client with auth state
type tcpClient struct {
	conn          gnet.Conn
	buffer        bytes.Buffer
	authenticated bool
	authTimeout   time.Time
	session       *auth.Session
}

// Handles gnet events with authentication
type tcpServer struct {
	gnet.BuiltinEventEngine
	sink    *TCPSink
	clients map[gnet.Conn]*tcpClient
	mu      sync.RWMutex
}

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

func (s *tcpServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	remoteAddr := c.RemoteAddr()
	s.sink.logger.Debug("msg", "TCP connection attempt", "remote_addr", remoteAddr)

	// Reject IPv6 connections immediately
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		if tcpAddr.IP.To4() == nil {
			return []byte("IPv4-only (IPv6 not supported)\n"), gnet.Close
		}
	}

	// Check net limit
	if s.sink.netLimiter != nil {
		remoteStr := c.RemoteAddr().String()
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteStr)
		if err != nil {
			s.sink.logger.Warn("msg", "Failed to parse TCP address",
				"remote_addr", remoteAddr,
				"error", err)
			return nil, gnet.Close
		}

		if !s.sink.netLimiter.CheckTCP(tcpAddr) {
			s.sink.logger.Warn("msg", "TCP connection net limited",
				"remote_addr", remoteAddr)
			return nil, gnet.Close
		}

		// Track connection
		s.sink.netLimiter.AddConnection(remoteStr)
	}

	// Create client state without auth timeout initially
	client := &tcpClient{
		conn:          c,
		authenticated: s.sink.authenticator == nil,
	}

	if s.sink.authenticator != nil {
		client.authTimeout = time.Now().Add(30 * time.Second)
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	newCount := s.sink.activeConns.Add(1)
	s.sink.logger.Debug("msg", "TCP connection opened",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"auth_enabled", s.sink.authenticator != nil)

	// Send auth prompt if authentication is required
	if s.sink.authenticator != nil {
		return []byte("AUTH_REQUIRED\n"), gnet.None
	}

	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Remove client state
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

	// Clean up write error tracking
	s.sink.errorMu.Lock()
	delete(s.sink.consecutiveWriteErrors, c)
	s.sink.errorMu.Unlock()

	// Remove connection tracking
	if s.sink.netLimiter != nil {
		s.sink.netLimiter.RemoveConnection(remoteAddr)
	}

	newCount := s.sink.activeConns.Add(-1)
	s.sink.logger.Debug("msg", "TCP connection closed",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"error", err)
	return gnet.None
}

func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	s.mu.RLock()
	client, exists := s.clients[c]
	s.mu.RUnlock()

	if !exists {
		return gnet.Close
	}

	// Authentication phase
	if !client.authenticated {
		// Check auth timeout
		if time.Now().After(client.authTimeout) {
			s.sink.logger.Warn("msg", "Authentication timeout",
				"component", "tcp_sink",
				"remote_addr", c.RemoteAddr().String())
			return gnet.Close
		}

		// Read auth data
		data, _ := c.Next(-1)
		if len(data) == 0 {
			return gnet.None
		}

		client.buffer.Write(data)

		// Look for complete auth line
		if idx := bytes.IndexByte(client.buffer.Bytes(), '\n'); idx >= 0 {
			line := client.buffer.Bytes()[:idx]
			client.buffer.Next(idx + 1)

			// Parse AUTH command: AUTH <method> <credentials>
			parts := strings.SplitN(string(line), " ", 3)
			if len(parts) != 3 || parts[0] != "AUTH" {
				c.AsyncWrite([]byte("AUTH_FAIL\n"), nil)
				return gnet.Close
			}

			// Authenticate
			session, err := s.sink.authenticator.AuthenticateTCP(parts[1], parts[2], c.RemoteAddr().String())
			if err != nil {
				s.sink.authFailures.Add(1)
				s.sink.logger.Warn("msg", "TCP authentication failed",
					"remote_addr", c.RemoteAddr().String(),
					"method", parts[1],
					"error", err)
				c.AsyncWrite([]byte("AUTH_FAIL\n"), nil)
				return gnet.Close
			}

			// Authentication successful
			s.sink.authSuccesses.Add(1)
			s.mu.Lock()
			client.authenticated = true
			client.session = session
			s.mu.Unlock()

			s.sink.logger.Info("msg", "TCP client authenticated",
				"component", "tcp_sink",
				"remote_addr", c.RemoteAddr().String(),
				"username", session.Username,
				"method", session.Method)

			c.AsyncWrite([]byte("AUTH_OK\n"), nil)
			client.buffer.Reset()
		}
		return gnet.None
	}

	// Clients shouldn't send data, just discard
	c.Discard(-1)
	return gnet.None
}

// Configures tcp sink auth
func (t *TCPSink) SetAuth(authCfg *config.AuthConfig) {
	if authCfg == nil || authCfg.Type == "none" {
		return
	}

	authenticator, err := auth.New(authCfg, t.logger)
	if err != nil {
		t.logger.Error("msg", "Failed to initialize authenticator for TCP sink",
			"component", "tcp_sink",
			"error", err)
		return
	}
	t.authenticator = authenticator

	t.logger.Info("msg", "Authentication configured for TCP sink",
		"component", "tcp_sink",
		"auth_type", authCfg.Type)
}