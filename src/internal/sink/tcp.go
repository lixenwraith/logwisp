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

	// Write error tracking
	writeErrors            atomic.Uint64
	consecutiveWriteErrors map[gnet.Conn]int
	errorMu                sync.Mutex
}

// TCPConfig holds TCP sink configuration
type TCPConfig struct {
	Port       int64
	BufferSize int64
	Heartbeat  *config.HeartbeatConfig
	TLS        *config.TLSConfig
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

	// Extract TLS config
	if tc, ok := options["tls"].(map[string]any); ok {
		cfg.TLS = &config.TLSConfig{}
		cfg.TLS.Enabled, _ = tc["enabled"].(bool)
		if certFile, ok := tc["cert_file"].(string); ok {
			cfg.TLS.CertFile = certFile
		}
		if keyFile, ok := tc["key_file"].(string); ok {
			cfg.TLS.KeyFile = keyFile
		}
		cfg.TLS.ClientAuth, _ = tc["client_auth"].(bool)
		if caFile, ok := tc["client_ca_file"].(string); ok {
			cfg.TLS.ClientCAFile = caFile
		}
		cfg.TLS.VerifyClientCert, _ = tc["verify_client_cert"].(bool)
		if minVer, ok := tc["min_version"].(string); ok {
			cfg.TLS.MinVersion = minVer
		}
		if maxVer, ok := tc["max_version"].(string); ok {
			cfg.TLS.MaxVersion = maxVer
		}
		if ciphers, ok := tc["cipher_suites"].(string); ok {
			cfg.TLS.CipherSuites = ciphers
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
		if ipWhitelist, ok := rl["ip_whitelist"].([]any); ok {
			cfg.NetLimit.IPWhitelist = make([]string, 0, len(ipWhitelist))
			for _, entry := range ipWhitelist {
				if str, ok := entry.(string); ok {
					cfg.NetLimit.IPWhitelist = append(cfg.NetLimit.IPWhitelist, str)
				}
			}
		}
		if ipBlacklist, ok := rl["ip_blacklist"].([]any); ok {
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
	addr := fmt.Sprintf("tcp://:%d", t.config.Port)

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
					// Send through TLS bridge if present
					if client.tlsBridge != nil {
						if _, err := client.tlsBridge.Write(data); err != nil {
							// TLS write failed, connection likely dead
							t.logger.Debug("msg", "TLS write failed",
								"component", "tcp_sink",
								"error", err)
							conn.Close()
						}
					} else {
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
					if client.tlsBridge != nil {
						if _, err := client.tlsBridge.Write(data); err != nil {
							t.logger.Debug("msg", "TLS heartbeat write failed",
								"component", "tcp_sink",
								"error", err)
							conn.Close()
						}
					} else {
						conn.AsyncWrite(data, func(c gnet.Conn, err error) error {
							if err != nil {
								t.writeErrors.Add(1)
								t.handleWriteError(c, err)
							}
							return nil
						})
					}
				}
			}
			t.server.mu.RUnlock()

		case <-t.done:
			return
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

// GetActiveConnections returns the current number of connections
func (t *TCPSink) GetActiveConnections() int64 {
	return t.activeConns.Load()
}

// tcpClient represents a connected TCP client with auth state
type tcpClient struct {
	conn           gnet.Conn
	buffer         bytes.Buffer
	authenticated  bool
	session        *auth.Session
	authTimeout    time.Time
	tlsBridge      *tls.GNetTLSConn
	authTimeoutSet bool
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
		conn:           c,
		authenticated:  s.sink.authenticator == nil, // No auth = auto authenticated
		authTimeoutSet: false,                       // Auth timeout not started yet
	}

	// Initialize TLS bridge if enabled
	if s.sink.tlsManager != nil {
		tlsConfig := s.sink.tlsManager.GetTCPConfig()
		client.tlsBridge = tls.NewServerConn(c, tlsConfig)
		client.tlsBridge.Handshake() // Start async handshake

		s.sink.logger.Debug("msg", "TLS handshake initiated",
			"component", "tcp_sink",
			"remote_addr", remoteAddr)
	} else if s.sink.authenticator != nil {
		// Only set auth timeout if no TLS (plain connection)
		client.authTimeout = time.Now().Add(30 * time.Second) // TODO: configurable or non-hardcoded timer
		client.authTimeoutSet = true
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
	if s.sink.authenticator != nil && s.sink.tlsManager == nil {
		authPrompt := []byte("AUTH REQUIRED\nFormat: AUTH <method> <credentials>\nMethods: basic, token\n")
		return authPrompt, gnet.None
	}

	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Remove client state
	s.mu.Lock()
	client := s.clients[c]
	delete(s.clients, c)
	s.mu.Unlock()

	// Clean up TLS bridge if present
	if client != nil && client.tlsBridge != nil {
		client.tlsBridge.Close()
		s.sink.logger.Debug("msg", "TLS connection closed",
			"remote_addr", remoteAddr)
	}

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

	// Read all available data
	data, err := c.Next(-1)
	if err != nil {
		s.sink.logger.Error("msg", "Error reading from connection",
			"component", "tcp_sink",
			"error", err)
		return gnet.Close
	}

	// Process through TLS bridge if present
	if client.tlsBridge != nil {
		// Feed encrypted data into TLS engine
		if err := client.tlsBridge.ProcessIncoming(data); err != nil {
			s.sink.logger.Error("msg", "TLS processing error",
				"component", "tcp_sink",
				"remote_addr", c.RemoteAddr().String(),
				"error", err)
			return gnet.Close
		}

		// Check if handshake is complete
		if !client.tlsBridge.IsHandshakeDone() {
			// Still handshaking, wait for more data
			return gnet.None
		}

		// Check handshake result
		_, hsErr := client.tlsBridge.HandshakeComplete()
		if hsErr != nil {
			s.sink.logger.Error("msg", "TLS handshake failed",
				"component", "tcp_sink",
				"remote_addr", c.RemoteAddr().String(),
				"error", hsErr)
			return gnet.Close
		}

		// Set auth timeout only after TLS handshake completes
		if !client.authTimeoutSet && s.sink.authenticator != nil && !client.authenticated {
			client.authTimeout = time.Now().Add(30 * time.Second)
			client.authTimeoutSet = true
			s.sink.logger.Debug("msg", "Auth timeout started after TLS handshake",
				"component", "tcp_sink",
				"remote_addr", c.RemoteAddr().String())
		}

		// Read decrypted plaintext
		data = client.tlsBridge.Read()
		if data == nil || len(data) == 0 {
			// No plaintext available yet
			return gnet.None
		}

		// First data after TLS handshake - send auth prompt if needed
		if s.sink.authenticator != nil && !client.authenticated &&
			len(client.buffer.Bytes()) == 0 {
			authPrompt := []byte("AUTH REQUIRED\n")
			client.tlsBridge.Write(authPrompt)
		}
	}

	// Only check auth timeout if it has been set
	if !client.authenticated && client.authTimeoutSet && time.Now().After(client.authTimeout) {
		s.sink.logger.Warn("msg", "Authentication timeout",
			"component", "tcp_sink",
			"remote_addr", c.RemoteAddr().String())
		if client.tlsBridge != nil && client.tlsBridge.IsHandshakeDone() {
			client.tlsBridge.Write([]byte("AUTH TIMEOUT\n"))
		} else if client.tlsBridge == nil {
			c.AsyncWrite([]byte("AUTH TIMEOUT\n"), nil)
		}
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
				// Send error through TLS if enabled
				errMsg := []byte("AUTH FAILED\n")
				if client.tlsBridge != nil {
					client.tlsBridge.Write(errMsg)
				} else {
					c.AsyncWrite(errMsg, nil)
				}
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
				// Send error through TLS if enabled
				errMsg := []byte("AUTH FAILED\n")
				if client.tlsBridge != nil {
					client.tlsBridge.Write(errMsg)
				} else {
					c.AsyncWrite(errMsg, nil)
				}
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
				"method", session.Method,
				"tls", client.tlsBridge != nil)

			// Send success through TLS if enabled
			successMsg := []byte("AUTH OK\n")
			if client.tlsBridge != nil {
				client.tlsBridge.Write(successMsg)
			} else {
				c.AsyncWrite(successMsg, nil)
			}

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

	// Initialize TLS manager if TLS is configured
	if t.config.TLS != nil && t.config.TLS.Enabled {
		tlsManager, err := tls.NewManager(t.config.TLS, t.logger)
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
		"tls_enabled", t.tlsManager != nil,
		"tls_bridge", t.tlsManager != nil)
}