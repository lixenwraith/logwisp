// FILE: logwisp/src/internal/source/tcp.go
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/limit"
	"logwisp/src/internal/tls"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/panjf2000/gnet/v2"
)

const (
	maxClientBufferSize     = 10 * 1024 * 1024 // 10MB max per client
	maxLineLength           = 1 * 1024 * 1024  // 1MB max per log line
	maxEncryptedDataPerRead = 1 * 1024 * 1024  // 1MB max encrypted data per read
	maxCumulativeEncrypted  = 20 * 1024 * 1024 // 20MB total encrypted before processing
)

// TCPSource receives log entries via TCP connections
type TCPSource struct {
	port        int64
	bufferSize  int64
	server      *tcpSourceServer
	subscribers []chan core.LogEntry
	mu          sync.RWMutex
	done        chan struct{}
	engine      *gnet.Engine
	engineMu    sync.Mutex
	wg          sync.WaitGroup
	netLimiter  *limit.NetLimiter
	tlsManager  *tls.Manager
	sslConfig   *config.SSLConfig
	logger      *log.Logger

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	activeConns    atomic.Int64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// NewTCPSource creates a new TCP server source
func NewTCPSource(options map[string]any, logger *log.Logger) (*TCPSource, error) {
	port, ok := options["port"].(int64)
	if !ok || port < 1 || port > 65535 {
		return nil, fmt.Errorf("tcp source requires valid 'port' option")
	}

	bufferSize := int64(1000)
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	t := &TCPSource{
		port:       port,
		bufferSize: bufferSize,
		done:       make(chan struct{}),
		startTime:  time.Now(),
		logger:     logger,
	}
	t.lastEntryTime.Store(time.Time{})

	// Initialize net limiter if configured
	if rl, ok := options["net_limit"].(map[string]any); ok {
		if enabled, _ := rl["enabled"].(bool); enabled {
			cfg := config.NetLimitConfig{
				Enabled: true,
			}

			if rps, ok := toFloat(rl["requests_per_second"]); ok {
				cfg.RequestsPerSecond = rps
			}
			if burst, ok := rl["burst_size"].(int64); ok {
				cfg.BurstSize = burst
			}
			if limitBy, ok := rl["limit_by"].(string); ok {
				cfg.LimitBy = limitBy
			}
			if maxPerIP, ok := rl["max_connections_per_ip"].(int64); ok {
				cfg.MaxConnectionsPerIP = maxPerIP
			}
			if maxTotal, ok := rl["max_total_connections"].(int64); ok {
				cfg.MaxTotalConnections = maxTotal
			}

			t.netLimiter = limit.NewNetLimiter(cfg, logger)
		}
	}

	// Extract SSL config and initialize TLS manager
	if ssl, ok := options["ssl"].(map[string]any); ok {
		t.sslConfig = &config.SSLConfig{}
		t.sslConfig.Enabled, _ = ssl["enabled"].(bool)
		if certFile, ok := ssl["cert_file"].(string); ok {
			t.sslConfig.CertFile = certFile
		}
		if keyFile, ok := ssl["key_file"].(string); ok {
			t.sslConfig.KeyFile = keyFile
		}
		t.sslConfig.ClientAuth, _ = ssl["client_auth"].(bool)
		if caFile, ok := ssl["client_ca_file"].(string); ok {
			t.sslConfig.ClientCAFile = caFile
		}
		t.sslConfig.VerifyClientCert, _ = ssl["verify_client_cert"].(bool)

		// Create TLS manager if enabled
		if t.sslConfig.Enabled {
			tlsManager, err := tls.NewManager(t.sslConfig, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS manager: %w", err)
			}
			t.tlsManager = tlsManager
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

	addr := fmt.Sprintf("tcp://:%d", t.port)

	// Create a gnet adapter using the existing logger instance
	gnetLogger := compat.NewGnetAdapter(t.logger)

	// Start gnet server
	errChan := make(chan error, 1)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.logger.Info("msg", "TCP source server starting",
			"component", "tcp_source",
			"port", t.port,
			"tls_enabled", t.tlsManager != nil)

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

// tcpClient represents a connected TCP client
type tcpClient struct {
	conn                gnet.Conn
	buffer              bytes.Buffer
	authenticated       bool
	session             *auth.Session
	authTimeout         time.Time
	tlsBridge           *tls.GNetTLSConn
	maxBufferSeen       int
	cumulativeEncrypted int64
}

// tcpSourceServer handles gnet events
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
	client := &tcpClient{conn: c}

	// Initialize TLS bridge if enabled
	if s.source.tlsManager != nil {
		tlsConfig := s.source.tlsManager.GetTCPConfig()
		client.tlsBridge = tls.NewServerConn(c, tlsConfig)
		client.tlsBridge.Handshake() // Start async handshake

		s.source.logger.Debug("msg", "TLS handshake initiated",
			"component", "tcp_source",
			"remote_addr", remoteAddr)
	}

	// Create client state
	s.mu.Lock()
	s.clients[c] = &tcpClient{conn: c}
	s.mu.Unlock()

	newCount := s.source.activeConns.Add(1)
	s.source.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_source",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"tls_enabled", s.source.tlsManager != nil)

	return nil, gnet.None
}

func (s *tcpSourceServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Remove client state
	s.mu.Lock()
	client := s.clients[c]
	delete(s.clients, c)
	s.mu.Unlock()

	// Clean up TLS bridge if present
	if client != nil && client.tlsBridge != nil {
		client.tlsBridge.Close()
		s.source.logger.Debug("msg", "TLS connection closed",
			"component", "tcp_source",
			"remote_addr", remoteAddr)
	}

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

	// Check encrypted data size BEFORE processing through TLS
	if len(data) > maxEncryptedDataPerRead {
		s.source.logger.Warn("msg", "Encrypted data per read limit exceeded",
			"component", "tcp_source",
			"remote_addr", c.RemoteAddr().String(),
			"data_size", len(data),
			"limit", maxEncryptedDataPerRead)
		s.source.invalidEntries.Add(1)
		return gnet.Close
	}

	// Track cumulative encrypted data to prevent slow accumulation
	client.cumulativeEncrypted += int64(len(data))
	if client.cumulativeEncrypted > maxCumulativeEncrypted {
		s.source.logger.Warn("msg", "Cumulative encrypted data limit exceeded",
			"component", "tcp_source",
			"remote_addr", c.RemoteAddr().String(),
			"total_encrypted", client.cumulativeEncrypted,
			"limit", maxCumulativeEncrypted)
		s.source.invalidEntries.Add(1)
		return gnet.Close
	}

	// Process through TLS bridge if present
	if client.tlsBridge != nil {
		// Feed encrypted data into TLS engine
		if err := client.tlsBridge.ProcessIncoming(data); err != nil {
			if errors.Is(err, tls.ErrTLSBackpressure) {
				s.source.logger.Warn("msg", "TLS backpressure, closing slow client",
					"component", "tcp_source",
					"remote_addr", c.RemoteAddr().String())
			} else {
				s.source.logger.Error("msg", "TLS processing error",
					"component", "tcp_source",
					"remote_addr", c.RemoteAddr().String(),
					"error", err)
			}
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
			s.source.logger.Error("msg", "TLS handshake failed",
				"component", "tcp_source",
				"remote_addr", c.RemoteAddr().String(),
				"error", hsErr)
			return gnet.Close
		}

		// Read decrypted plaintext
		data = client.tlsBridge.Read()
		if data == nil || len(data) == 0 {
			// No plaintext available yet
			return gnet.None
		}
		// Reset cumulative counter after successful decryption and processing
		client.cumulativeEncrypted = 0
	}

	// Check buffer size before appending
	if client.buffer.Len()+len(data) > maxClientBufferSize {
		s.source.logger.Warn("msg", "Client buffer limit exceeded",
			"component", "tcp_source",
			"remote_addr", c.RemoteAddr().String(),
			"buffer_size", client.buffer.Len(),
			"incoming_size", len(data))
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

// noopLogger implements gnet's Logger interface but discards everything
// type noopLogger struct{}
// func (n noopLogger) Debugf(format string, args ...any) {}
// func (n noopLogger) Infof(format string, args ...any)  {}
// func (n noopLogger) Warnf(format string, args ...any)  {}
// func (n noopLogger) Errorf(format string, args ...any) {}
// func (n noopLogger) Fatalf(format string, args ...any) {}

// Usage: gnet.Run(..., gnet.WithLogger(noopLogger{}), ...)