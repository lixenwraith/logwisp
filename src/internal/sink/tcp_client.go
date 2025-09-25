// FILE: logwisp/src/internal/sink/tcp_client.go
package sink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	tlspkg "logwisp/src/internal/tls"

	"github.com/lixenwraith/log"
)

// TCPClientSink forwards log entries to a remote TCP endpoint
type TCPClientSink struct {
	input     chan core.LogEntry
	config    TCPClientConfig
	conn      net.Conn
	connMu    sync.RWMutex
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time
	logger    *log.Logger
	formatter format.Formatter

	// TLS support
	tlsManager *tlspkg.Manager
	tlsConfig  *tls.Config

	// Reconnection state
	reconnecting   atomic.Bool
	lastConnectErr error
	connectTime    time.Time

	// Statistics
	totalProcessed   atomic.Uint64
	totalFailed      atomic.Uint64
	totalReconnects  atomic.Uint64
	lastProcessed    atomic.Value // time.Time
	connectionUptime atomic.Value // time.Duration
}

// TCPClientConfig holds TCP client sink configuration
type TCPClientConfig struct {
	Address      string
	BufferSize   int64
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	KeepAlive    time.Duration

	// Reconnection settings
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
	ReconnectBackoff  float64

	// TLS config
	TLS *config.TLSConfig
}

// NewTCPClientSink creates a new TCP client sink
func NewTCPClientSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*TCPClientSink, error) {
	cfg := TCPClientConfig{
		BufferSize:        int64(1000),
		DialTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadTimeout:       10 * time.Second,
		KeepAlive:         30 * time.Second,
		ReconnectDelay:    time.Second,
		MaxReconnectDelay: 30 * time.Second,
		ReconnectBackoff:  float64(1.5),
	}

	// Extract address
	address, ok := options["address"].(string)
	if !ok || address == "" {
		return nil, fmt.Errorf("tcp_client sink requires 'address' option")
	}

	// Validate address format
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format (expected host:port): %w", err)
	}
	cfg.Address = address

	// Extract other options
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		cfg.BufferSize = bufSize
	}
	if dialTimeout, ok := options["dial_timeout_seconds"].(int64); ok && dialTimeout > 0 {
		cfg.DialTimeout = time.Duration(dialTimeout) * time.Second
	}
	if writeTimeout, ok := options["write_timeout_seconds"].(int64); ok && writeTimeout > 0 {
		cfg.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}
	if readTimeout, ok := options["read_timeout_seconds"].(int64); ok && readTimeout > 0 {
		cfg.ReadTimeout = time.Duration(readTimeout) * time.Second
	}
	if keepAlive, ok := options["keep_alive_seconds"].(int64); ok && keepAlive > 0 {
		cfg.KeepAlive = time.Duration(keepAlive) * time.Second
	}
	if reconnectDelay, ok := options["reconnect_delay_ms"].(int64); ok && reconnectDelay > 0 {
		cfg.ReconnectDelay = time.Duration(reconnectDelay) * time.Millisecond
	}
	if maxReconnectDelay, ok := options["max_reconnect_delay_seconds"].(int64); ok && maxReconnectDelay > 0 {
		cfg.MaxReconnectDelay = time.Duration(maxReconnectDelay) * time.Second
	}
	if backoff, ok := options["reconnect_backoff"].(float64); ok && backoff >= 1.0 {
		cfg.ReconnectBackoff = backoff
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
		if insecure, ok := tc["insecure_skip_verify"].(bool); ok {
			cfg.TLS.InsecureSkipVerify = insecure
		}
		if caFile, ok := tc["ca_file"].(string); ok {
			cfg.TLS.CAFile = caFile
		}
	}

	t := &TCPClientSink{
		input:     make(chan core.LogEntry, cfg.BufferSize),
		config:    cfg,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	t.lastProcessed.Store(time.Time{})
	t.connectionUptime.Store(time.Duration(0))

	// Initialize TLS manager if TLS is configured
	if cfg.TLS != nil && cfg.TLS.Enabled {
		// Build custom TLS config for client
		t.tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
		}

		// Extract server name from address for SNI
		host, _, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address for SNI: %w", err)
		}
		t.tlsConfig.ServerName = host

		// Load custom CA for server verification
		if cfg.TLS.CAFile != "" {
			caCert, err := os.ReadFile(cfg.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file '%s': %w", cfg.TLS.CAFile, err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate from '%s'", cfg.TLS.CAFile)
			}
			t.tlsConfig.RootCAs = caCertPool
			logger.Debug("msg", "Custom CA loaded for server verification",
				"component", "tcp_client_sink",
				"ca_file", cfg.TLS.CAFile)
		}

		// Load client certificate for mTLS
		if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			t.tlsConfig.Certificates = []tls.Certificate{cert}
			logger.Info("msg", "Client certificate loaded for mTLS",
				"component", "tcp_client_sink",
				"cert_file", cfg.TLS.CertFile)
		}

		// Set minimum TLS version if configured
		if cfg.TLS.MinVersion != "" {
			t.tlsConfig.MinVersion = parseTLSVersion(cfg.TLS.MinVersion, tls.VersionTLS12)
		} else {
			t.tlsConfig.MinVersion = tls.VersionTLS12 // Default minimum
		}

		logger.Info("msg", "TLS enabled for TCP client",
			"component", "tcp_client_sink",
			"address", cfg.Address,
			"server_name", host,
			"insecure", cfg.TLS.InsecureSkipVerify,
			"mtls", cfg.TLS.CertFile != "")
	}
	return t, nil
}

func (t *TCPClientSink) Input() chan<- core.LogEntry {
	return t.input
}

func (t *TCPClientSink) Start(ctx context.Context) error {
	// Start connection manager
	t.wg.Add(1)
	go t.connectionManager(ctx)

	// Start processing loop
	t.wg.Add(1)
	go t.processLoop(ctx)

	t.logger.Info("msg", "TCP client sink started",
		"component", "tcp_client_sink",
		"address", t.config.Address)
	return nil
}

func (t *TCPClientSink) Stop() {
	t.logger.Info("msg", "Stopping TCP client sink")
	close(t.done)
	t.wg.Wait()

	// Close connection
	t.connMu.Lock()
	if t.conn != nil {
		_ = t.conn.Close()
	}
	t.connMu.Unlock()

	t.logger.Info("msg", "TCP client sink stopped",
		"total_processed", t.totalProcessed.Load(),
		"total_failed", t.totalFailed.Load(),
		"total_reconnects", t.totalReconnects.Load())
}

func (t *TCPClientSink) GetStats() SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)
	uptime, _ := t.connectionUptime.Load().(time.Duration)

	t.connMu.RLock()
	connected := t.conn != nil
	t.connMu.RUnlock()

	activeConns := int64(0)
	if connected {
		activeConns = 1
	}

	return SinkStats{
		Type:              "tcp_client",
		TotalProcessed:    t.totalProcessed.Load(),
		ActiveConnections: activeConns,
		StartTime:         t.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"address":           t.config.Address,
			"connected":         connected,
			"reconnecting":      t.reconnecting.Load(),
			"total_failed":      t.totalFailed.Load(),
			"total_reconnects":  t.totalReconnects.Load(),
			"connection_uptime": uptime.Seconds(),
			"last_error":        fmt.Sprintf("%v", t.lastConnectErr),
		},
	}
}

func (t *TCPClientSink) connectionManager(ctx context.Context) {
	defer t.wg.Done()

	reconnectDelay := t.config.ReconnectDelay

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		default:
		}

		// Attempt to connect
		t.reconnecting.Store(true)
		conn, err := t.connect()
		t.reconnecting.Store(false)

		if err != nil {
			t.lastConnectErr = err
			t.logger.Warn("msg", "Failed to connect to TCP server",
				"component", "tcp_client_sink",
				"address", t.config.Address,
				"error", err,
				"retry_delay", reconnectDelay)

			// Wait before retry
			select {
			case <-ctx.Done():
				return
			case <-t.done:
				return
			case <-time.After(reconnectDelay):
			}

			// Exponential backoff
			reconnectDelay = time.Duration(float64(reconnectDelay) * t.config.ReconnectBackoff)
			if reconnectDelay > t.config.MaxReconnectDelay {
				reconnectDelay = t.config.MaxReconnectDelay
			}
			continue
		}

		// Connection successful
		t.lastConnectErr = nil
		reconnectDelay = t.config.ReconnectDelay // Reset backoff
		t.connectTime = time.Now()
		t.totalReconnects.Add(1)

		t.connMu.Lock()
		t.conn = conn
		t.connMu.Unlock()

		t.logger.Info("msg", "Connected to TCP server",
			"component", "tcp_client_sink",
			"address", t.config.Address,
			"local_addr", conn.LocalAddr())

		// Monitor connection
		t.monitorConnection(conn)

		// Connection lost, clear it
		t.connMu.Lock()
		t.conn = nil
		t.connMu.Unlock()

		// Update connection uptime
		uptime := time.Since(t.connectTime)
		t.connectionUptime.Store(uptime)

		t.logger.Warn("msg", "Lost connection to TCP server",
			"component", "tcp_client_sink",
			"address", t.config.Address,
			"uptime", uptime)
	}
}

func (t *TCPClientSink) connect() (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   t.config.DialTimeout,
		KeepAlive: t.config.KeepAlive,
	}

	conn, err := dialer.Dial("tcp", t.config.Address)
	if err != nil {
		return nil, err
	}

	// Set TCP keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(t.config.KeepAlive)
	}

	// Wrap with TLS if configured
	if t.tlsConfig != nil {
		t.logger.Debug("msg", "Initiating TLS handshake",
			"component", "tcp_client_sink",
			"address", t.config.Address)

		tlsConn := tls.Client(conn, t.tlsConfig)

		// Perform handshake with timeout
		handshakeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		// Log connection details
		state := tlsConn.ConnectionState()
		t.logger.Info("msg", "TLS connection established",
			"component", "tcp_client_sink",
			"address", t.config.Address,
			"tls_version", tlsVersionString(state.Version),
			"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
			"server_name", state.ServerName)

		return tlsConn, nil
	}

	return conn, nil
}

func (t *TCPClientSink) monitorConnection(conn net.Conn) {
	// Simple connection monitoring by periodic zero-byte reads
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	buf := make([]byte, 1)
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			// Set read deadline
			if err := conn.SetReadDeadline(time.Now().Add(t.config.ReadTimeout)); err != nil {
				t.logger.Debug("msg", "Failed to set read deadline", "error", err)
				return
			}

			// Try to read (we don't expect any data)
			_, err := conn.Read(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					// Timeout is expected, connection is still alive
					continue
				}
				// Real error, connection is dead
				return
			}
		}
	}
}

func (t *TCPClientSink) processLoop(ctx context.Context) {
	defer t.wg.Done()

	for {
		select {
		case entry, ok := <-t.input:
			if !ok {
				return
			}

			t.totalProcessed.Add(1)
			t.lastProcessed.Store(time.Now())

			// Send entry
			if err := t.sendEntry(entry); err != nil {
				t.totalFailed.Add(1)
				t.logger.Debug("msg", "Failed to send log entry",
					"component", "tcp_client_sink",
					"error", err)
			}

		case <-ctx.Done():
			return
		case <-t.done:
			return
		}
	}
}

func (t *TCPClientSink) sendEntry(entry core.LogEntry) error {
	// Get current connection
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Format data
	data, err := t.formatter.Format(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	// Set write deadline
	if err := conn.SetWriteDeadline(time.Now().Add(t.config.WriteTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Write data
	n, err := conn.Write(data)
	if err != nil {
		// Connection error, it will be reconnected
		return fmt.Errorf("write failed: %w", err)
	}

	if n != len(data) {
		return fmt.Errorf("partial write: %d/%d bytes", n, len(data))
	}

	return nil
}

// tlsVersionString returns human-readable TLS version
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// parseTLSVersion converts string to TLS version constant
func parseTLSVersion(version string, defaultVersion uint16) uint16 {
	switch strings.ToUpper(version) {
	case "TLS1.0", "TLS10":
		return tls.VersionTLS10
	case "TLS1.1", "TLS11":
		return tls.VersionTLS11
	case "TLS1.2", "TLS12":
		return tls.VersionTLS12
	case "TLS1.3", "TLS13":
		return tls.VersionTLS13
	default:
		return defaultVersion
	}
}