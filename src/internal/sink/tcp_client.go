// FILE: logwisp/src/internal/sink/tcp_client.go
package sink

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"logwisp/src/internal/auth"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
)

// Forwards log entries to a remote TCP endpoint
type TCPClientSink struct {
	input     chan core.LogEntry
	config    *config.TCPClientSinkOptions
	address   string
	conn      net.Conn
	connMu    sync.RWMutex
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time
	logger    *log.Logger
	formatter format.Formatter

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

// Creates a new TCP client sink
func NewTCPClientSink(opts *config.TCPClientSinkOptions, logger *log.Logger, formatter format.Formatter) (*TCPClientSink, error) {
	// Validation and defaults are handled in config package
	if opts == nil {
		return nil, fmt.Errorf("TCP client sink options cannot be nil")
	}

	t := &TCPClientSink{
		config:    opts,
		address:   opts.Host + ":" + strconv.Itoa(int(opts.Port)),
		input:     make(chan core.LogEntry, opts.BufferSize),
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
		"host", t.config.Host,
		"port", t.config.Port)
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
			"address":           t.address,
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

	reconnectDelay := time.Duration(t.config.ReconnectDelayMS) * time.Millisecond

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
				"address", t.address,
				"error", err,
				"retry_delay_ms", reconnectDelay)

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
			if reconnectDelay > time.Duration(t.config.MaxReconnectDelayMS)*time.Millisecond {
				reconnectDelay = time.Duration(t.config.MaxReconnectDelayMS)
			}
			continue
		}

		// Connection successful
		t.lastConnectErr = nil
		reconnectDelay = time.Duration(t.config.ReconnectDelayMS) * time.Millisecond // Reset backoff
		t.connectTime = time.Now()
		t.totalReconnects.Add(1)

		t.connMu.Lock()
		t.conn = conn
		t.connMu.Unlock()

		t.logger.Info("msg", "Connected to TCP server",
			"component", "tcp_client_sink",
			"address", t.address,
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
			"address", t.address,
			"uptime", uptime)
	}
}

func (t *TCPClientSink) connect() (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   time.Duration(t.config.DialTimeout) * time.Second,
		KeepAlive: time.Duration(t.config.KeepAlive) * time.Second,
	}

	conn, err := dialer.Dial("tcp", t.address)
	if err != nil {
		return nil, err
	}

	// Set TCP keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(time.Duration(t.config.KeepAlive) * time.Second)
	}

	// SCRAM authentication if credentials configured
	if t.config.Auth != nil && t.config.Auth.Type == "scram" {
		if err := t.performSCRAMAuth(conn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SCRAM authentication failed: %w", err)
		}
		t.logger.Debug("msg", "SCRAM authentication completed",
			"component", "tcp_client_sink",
			"address", t.address)
	}

	return conn, nil
}

func (t *TCPClientSink) performSCRAMAuth(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Create SCRAM client
	scramClient := auth.NewScramClient(t.config.Auth.Username, t.config.Auth.Password)

	// Wait for AUTH_REQUIRED from server
	authPrompt, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read auth prompt: %w", err)
	}

	if strings.TrimSpace(authPrompt) != "AUTH_REQUIRED" {
		return fmt.Errorf("unexpected server greeting: %s", authPrompt)
	}

	// Step 1: Send ClientFirst
	clientFirst, err := scramClient.StartAuthentication()
	if err != nil {
		return fmt.Errorf("failed to start SCRAM: %w", err)
	}

	msg, err := auth.FormatSCRAMRequest("SCRAM-FIRST", clientFirst)
	if err != nil {
		return err
	}

	if _, err := conn.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to send SCRAM-FIRST: %w", err)
	}

	// Step 2: Receive ServerFirst challenge
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read SCRAM challenge: %w", err)
	}

	command, data, err := auth.ParseSCRAMResponse(response)
	if err != nil {
		return err
	}

	if command != "SCRAM-CHALLENGE" {
		return fmt.Errorf("unexpected server response: %s", command)
	}

	var serverFirst auth.ServerFirst
	if err := json.Unmarshal([]byte(data), &serverFirst); err != nil {
		return fmt.Errorf("failed to parse server challenge: %w", err)
	}

	// Step 3: Process challenge and send proof
	clientFinal, err := scramClient.ProcessServerFirst(&serverFirst)
	if err != nil {
		return fmt.Errorf("failed to process challenge: %w", err)
	}

	msg, err = auth.FormatSCRAMRequest("SCRAM-PROOF", clientFinal)
	if err != nil {
		return err
	}

	if _, err := conn.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to send SCRAM-PROOF: %w", err)
	}

	// Step 4: Receive ServerFinal
	response, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read SCRAM result: %w", err)
	}

	command, data, err = auth.ParseSCRAMResponse(response)
	if err != nil {
		return err
	}

	switch command {
	case "SCRAM-OK":
		var serverFinal auth.ServerFinal
		if err := json.Unmarshal([]byte(data), &serverFinal); err != nil {
			return fmt.Errorf("failed to parse server signature: %w", err)
		}

		// Verify server signature
		if err := scramClient.VerifyServerFinal(&serverFinal); err != nil {
			return fmt.Errorf("server signature verification failed: %w", err)
		}

		t.logger.Info("msg", "SCRAM authentication successful",
			"component", "tcp_client_sink",
			"address", t.address,
			"username", t.config.Auth.Username,
			"session_id", serverFinal.SessionID)

		return nil

	case "SCRAM-FAIL":
		reason := data
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("authentication failed: %s", reason)

	default:
		return fmt.Errorf("unexpected response: %s", command)
	}
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
			if err := conn.SetReadDeadline(time.Now().Add(time.Duration(t.config.ReadTimeout) * time.Second)); err != nil {
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
	if err := conn.SetWriteDeadline(time.Now().Add(time.Duration(t.config.WriteTimeout) * time.Second)); err != nil {
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