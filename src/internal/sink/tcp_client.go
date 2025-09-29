// FILE: logwisp/src/internal/sink/tcp_client.go
package sink

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
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

	"github.com/lixenwraith/log"
)

// Forwards log entries to a remote TCP endpoint
type TCPClientSink struct {
	input         chan core.LogEntry
	config        TCPClientConfig
	conn          net.Conn
	connMu        sync.RWMutex
	done          chan struct{}
	wg            sync.WaitGroup
	startTime     time.Time
	logger        *log.Logger
	formatter     format.Formatter
	authenticator *auth.Authenticator

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

// Holds TCP client sink configuration
type TCPClientConfig struct {
	Address      string
	BufferSize   int64
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	KeepAlive    time.Duration

	// Security
	Username string
	Password string

	// Reconnection settings
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
	ReconnectBackoff  float64

	// TLS config
	TLS *config.TLSConfig
}

// Creates a new TCP client sink
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
	if username, ok := options["username"].(string); ok {
		cfg.Username = username
	}
	if password, ok := options["password"].(string); ok {
		cfg.Password = password
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

	// Handle authentication if credentials configured
	if t.config.Username != "" && t.config.Password != "" {
		// Read auth challenge
		reader := bufio.NewReader(conn)
		challenge, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read auth challenge: %w", err)
		}

		if strings.TrimSpace(challenge) == "AUTH_REQUIRED" {
			// Send credentials
			creds := t.config.Username + ":" + t.config.Password
			encodedCreds := base64.StdEncoding.EncodeToString([]byte(creds))
			authCmd := fmt.Sprintf("AUTH basic %s\n", encodedCreds)

			if _, err := conn.Write([]byte(authCmd)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to send auth: %w", err)
			}

			// Read response
			response, err := reader.ReadString('\n')
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to read auth response: %w", err)
			}

			if strings.TrimSpace(response) != "AUTH_OK" {
				conn.Close()
				return nil, fmt.Errorf("authentication failed: %s", response)
			}

			t.logger.Debug("msg", "TCP authentication successful",
				"component", "tcp_client_sink",
				"address", t.config.Address,
				"username", t.config.Username)
		}
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

// Not applicable, Clients authenticate to remote servers using Username/Password in config
func (h *TCPClientSink) SetAuth(authCfg *config.AuthConfig) {
	// No-op: client sinks don't validate incoming connections
	// They authenticate to remote servers using Username/Password fields
}