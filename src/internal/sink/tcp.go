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
	"logwisp/src/internal/tls"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

// TCPSink streams log entries via TCP
type TCPSink struct {
	input       chan core.LogEntry
	config      TCPConfig
	server      *tcpServer
	done        chan struct{}
	activeConns atomic.Int64
	startTime   time.Time
	engine      *gnet.Engine
	engineMu    sync.Mutex
	wg          sync.WaitGroup
	netLimiter  *limit.NetLimiter
	ipChecker   *limit.IPChecker
	logger      *log.Logger
	formatter   format.Formatter

	// Security components
	authenticator *auth.Authenticator
	tlsManager    *tls.Manager
	authConfig    *config.AuthConfig

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
	authFailures   atomic.Uint64
	authSuccesses  atomic.Uint64
}

// TCPConfig holds TCP sink configuration
type TCPConfig struct {
	Port       int64
	BufferSize int64
	Heartbeat  *config.HeartbeatConfig
	SSL        *config.SSLConfig
	NetLimit   *config.NetLimitConfig
}

// NewTCPSink creates a new TCP streaming sink
func NewTCPSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*TCPSink, error) {
	cfg := TCPConfig{
		Port:       int64(9090),
		BufferSize: int64(1000),
	}

	// Extract configuration from options
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

	// Extract SSL config
	if ssl, ok := options["ssl"].(map[string]any); ok {
		cfg.SSL = &config.SSLConfig{}
		cfg.SSL.Enabled, _ = ssl["enabled"].(bool)
		if certFile, ok := ssl["cert_file"].(string); ok {
			cfg.SSL.CertFile = certFile
		}
		if keyFile, ok := ssl["key_file"].(string); ok {
			cfg.SSL.KeyFile = keyFile
		}
		cfg.SSL.ClientAuth, _ = ssl["client_auth"].(bool)
		if caFile, ok := ssl["client_ca_file"].(string); ok {
			cfg.SSL.ClientCAFile = caFile
		}
		cfg.SSL.VerifyClientCert, _ = ssl["verify_client_cert"].(bool)
		if minVer, ok := ssl["min_version"].(string); ok {
			cfg.SSL.MinVersion = minVer
		}
		if maxVer, ok := ssl["max_version"].(string); ok {
			cfg.SSL.MaxVersion = maxVer
		}
		if ciphers, ok := ssl["cipher_suites"].(string); ok {
			cfg.SSL.CipherSuites = ciphers
		}
	}

	// Extract net limit config
	if rl, ok := options["net_limit"].(map[string]any); ok {
		cfg.NetLimit = &config.NetLimitConfig{}
		cfg.NetLimit.Enabled, _ = rl["enabled"].(bool)
		if rps, ok := rl["requests_per_second"].(float64); ok {
			cfg.NetLimit.RequestsPerSecond = rps
		}
		if burst, ok := rl["burst_size"].(int64); ok {
			cfg.NetLimit.BurstSize = burst
		}
		if limitBy, ok := rl["limit_by"].(string); ok {
			cfg.NetLimit.LimitBy = limitBy
		}
		if respCode, ok := rl["response_code"].(int64); ok {
			cfg.NetLimit.ResponseCode = respCode
		}
		if msg, ok := rl["response_message"].(string); ok {
			cfg.NetLimit.ResponseMessage = msg
		}
		if maxPerIP, ok := rl["max_connections_per_ip"].(int64); ok {
			cfg.NetLimit.MaxConnectionsPerIP = maxPerIP
		}
		if maxTotal, ok := rl["max_total_connections"].(int64); ok {
			cfg.NetLimit.MaxTotalConnections = maxTotal
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
	addr := fmt.Sprintf("tcp://:%d", t.config.Port)

	// Create a gnet adapter using the existing logger instance
	gnetLogger := compat.NewGnetAdapter(t.logger)

	var opts []gnet.Option
	opts = append(opts,
		gnet.WithLogger(gnetLogger),
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
	)

	// Add TLS if configured
	if t.tlsManager != nil {
		//		tlsConfig := t.tlsManager.GetTCPConfig()
		// TODO: tlsConfig is not used, wrapper to be implemented, non-TLS stream to be available without wrapper
		// ☢ SECURITY: gnet doesn't support TLS natively - would need wrapper
		// This is a limitation that requires implementing TLS at application layer
		t.logger.Warn("msg", "TLS configured but gnet doesn't support native TLS",
			"component", "tcp_sink",
			"workaround", "Use stunnel or nginx TCP proxy for TLS termination")
	}

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

	var authStats map[string]any
	if t.authenticator != nil {
		authStats = t.authenticator.GetStats()
		authStats["failures"] = t.authFailures.Load()
		authStats["successes"] = t.authSuccesses.Load()
	}

	var tlsStats map[string]any
	if t.tlsManager != nil {
		tlsStats = t.tlsManager.GetStats()
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
			"auth":        authStats,
			"tls":         tlsStats,
		},
	}
}

func (t *TCPSink) broadcastLoop(ctx context.Context) {
	var ticker *time.Ticker
	var tickerChan <-chan time.Time

	if t.config.Heartbeat.Enabled {
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

			// Broadcast only to authenticated clients
			t.server.mu.RLock()
			for conn, client := range t.server.clients {
				if client.authenticated {
					conn.AsyncWrite(data, nil)
				}
			}
			t.server.mu.RUnlock()

		case <-tickerChan:
			heartbeatEntry := t.createHeartbeatEntry()
			data, err := t.formatter.Format(heartbeatEntry)
			if err != nil {
				t.logger.Error("msg", "Failed to format heartbeat",
					"component", "tcp_sink",
					"error", err)
				continue
			}

			t.server.mu.RLock()
			for conn, client := range t.server.clients {
				if client.authenticated {
					// Validate session is still active
					if t.authenticator != nil && client.session != nil {
						if !t.authenticator.ValidateSession(client.session.ID) {
							// Session expired, close connection
							conn.Close()
							continue
						}
					}
					conn.AsyncWrite(data, nil)
				}
			}
			t.server.mu.RUnlock()

		case <-t.done:
			return
		}
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

// GetActiveConnections returns the current number of connections
func (t *TCPSink) GetActiveConnections() int64 {
	return t.activeConns.Load()
}

// tcpClient represents a connected TCP client with auth state
type tcpClient struct {
	conn          gnet.Conn
	buffer        bytes.Buffer
	authenticated bool
	session       *auth.Session
	authTimeout   time.Time
}

// tcpServer handles gnet events with authentication
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
	remoteAddr := c.RemoteAddr().String()
	s.sink.logger.Debug("msg", "TCP connection attempt", "remote_addr", remoteAddr)

	// Check IP access control first
	if s.sink.ipChecker != nil {
		if !s.sink.ipChecker.IsAllowed(c.RemoteAddr()) {
			s.sink.logger.Warn("msg", "TCP connection denied by IP filter",
				"remote_addr", remoteAddr)
			return nil, gnet.Close
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

	// Create client state
	client := &tcpClient{
		conn:          c,
		authenticated: s.sink.authenticator == nil,      // No auth = auto authenticated
		authTimeout:   time.Now().Add(30 * time.Second), // 30s to authenticate
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	newCount := s.sink.activeConns.Add(1)
	s.sink.logger.Debug("msg", "TCP connection opened",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"requires_auth", s.sink.authenticator != nil)

	// Send auth prompt if authentication is required
	if s.sink.authenticator != nil {
		authPrompt := []byte("AUTH REQUIRED\nFormat: AUTH <method> <credentials>\nMethods: basic, token\n")
		return authPrompt, gnet.None
	}

	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Remove client state
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

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

	// Check auth timeout
	if !client.authenticated && time.Now().After(client.authTimeout) {
		s.sink.logger.Warn("msg", "Authentication timeout",
			"remote_addr", c.RemoteAddr().String())
		c.AsyncWrite([]byte("AUTH TIMEOUT\n"), nil)
		return gnet.Close
	}

	// Read all available data
	data, err := c.Next(-1)
	if err != nil {
		s.sink.logger.Error("msg", "Error reading from connection",
			"component", "tcp_sink",
			"error", err)
		return gnet.Close
	}

	// If not authenticated, expect auth command
	if !client.authenticated {
		client.buffer.Write(data)

		// Look for complete auth line
		if line, err := client.buffer.ReadBytes('\n'); err == nil {
			line = bytes.TrimSpace(line)

			// Parse AUTH command: AUTH <method> <credentials>
			parts := strings.SplitN(string(line), " ", 3)
			if len(parts) != 3 || parts[0] != "AUTH" {
				c.AsyncWrite([]byte("ERROR: Invalid auth format\n"), nil)
				return gnet.None
			}

			// Authenticate
			session, err := s.sink.authenticator.AuthenticateTCP(parts[1], parts[2], c.RemoteAddr().String())
			if err != nil {
				s.sink.authFailures.Add(1)
				s.sink.logger.Warn("msg", "TCP authentication failed",
					"remote_addr", c.RemoteAddr().String(),
					"method", parts[1],
					"error", err)
				c.AsyncWrite([]byte(fmt.Sprintf("AUTH FAILED: %v\n", err)), nil)
				return gnet.Close
			}

			// Authentication successful
			s.sink.authSuccesses.Add(1)
			s.mu.Lock()
			client.authenticated = true
			client.session = session
			s.mu.Unlock()

			s.sink.logger.Info("msg", "TCP client authenticated",
				"remote_addr", c.RemoteAddr().String(),
				"username", session.Username,
				"method", session.Method)

			c.AsyncWrite([]byte("AUTH OK\n"), nil)

			// Clear buffer after auth
			client.buffer.Reset()
		}
		return gnet.None
	}

	// Authenticated clients shouldn't send data, just discard
	c.Discard(-1)
	return gnet.None
}

// SetAuthConfig configures tcp sink authentication
func (t *TCPSink) SetAuthConfig(authCfg *config.AuthConfig) {
	if authCfg == nil || authCfg.Type == "none" {
		return
	}

	t.authConfig = authCfg
	authenticator, err := auth.New(authCfg, t.logger)
	if err != nil {
		t.logger.Error("msg", "Failed to initialize authenticator for TCP sink",
			"component", "tcp_sink",
			"error", err)
		return
	}
	t.authenticator = authenticator

	// Initialize TLS manager if SSL is configured
	if t.config.SSL != nil && t.config.SSL.Enabled {
		tlsManager, err := tls.New(t.config.SSL, t.logger)
		if err != nil {
			t.logger.Error("msg", "Failed to create TLS manager",
				"component", "tcp_sink",
				"error", err)
			// Continue without TLS
			return
		}
		t.tlsManager = tlsManager
	}

	t.logger.Info("msg", "Authentication configured for TCP sink",
		"component", "tcp_sink",
		"auth_type", authCfg.Type,
		"tls_enabled", t.tlsManager != nil)
}