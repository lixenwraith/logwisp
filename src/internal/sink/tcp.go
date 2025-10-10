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
	input       chan core.LogEntry
	config      *config.TCPSinkOptions
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

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time

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
func NewTCPSink(opts *config.TCPSinkOptions, logger *log.Logger, formatter format.Formatter) (*TCPSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("TCP sink options cannot be nil")
	}

	t := &TCPSink{
		config:    opts, // Direct reference to config
		input:     make(chan core.LogEntry, opts.BufferSize),
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	t.lastProcessed.Store(time.Time{})

	// Initialize net limiter with pointer
	if opts.NetLimit != nil && (opts.NetLimit.Enabled ||
		len(opts.NetLimit.IPWhitelist) > 0 ||
		len(opts.NetLimit.IPBlacklist) > 0) {
		t.netLimiter = limit.NewNetLimiter(opts.NetLimit, logger)
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

func (t *TCPSink) broadcastData(data []byte) {
	t.server.mu.RLock()
	defer t.server.mu.RUnlock()

	for conn, _ := range t.server.clients {
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
	conn        gnet.Conn
	buffer      bytes.Buffer
	authTimeout time.Time
	session     *auth.Session
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

	// Reject IPv6 connections
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

	// TCP Sink accepts all connections without authentication
	client := &tcpClient{
		conn:   c,
		buffer: bytes.Buffer{},
	}

	s.mu.Lock()
	s.clients[c] = client
	s.mu.Unlock()

	newCount := s.sink.activeConns.Add(1)
	s.sink.logger.Debug("msg", "TCP connection opened",
		"remote_addr", remoteAddr,
		"active_connections", newCount)

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
	// TCP Sink doesn't expect any data from clients, discard all
	c.Discard(-1)
	return gnet.None
}