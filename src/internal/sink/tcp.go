// FILE: src/internal/sink/tcp.go
package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/format"
	"logwisp/src/internal/netlimit"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
	"github.com/panjf2000/gnet/v2"
)

// TCPSink streams log entries via TCP
type TCPSink struct {
	input       chan source.LogEntry
	config      TCPConfig
	server      *tcpServer
	done        chan struct{}
	activeConns atomic.Int64
	startTime   time.Time
	engine      *gnet.Engine
	engineMu    sync.Mutex
	wg          sync.WaitGroup
	netLimiter  *netlimit.Limiter
	logger      *log.Logger
	formatter   format.Formatter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
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
		input:     make(chan source.LogEntry, cfg.BufferSize),
		config:    cfg,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	t.lastProcessed.Store(time.Time{})

	if cfg.NetLimit != nil && cfg.NetLimit.Enabled {
		t.netLimiter = netlimit.New(*cfg.NetLimit, logger)
	}

	return t, nil
}

func (t *TCPSink) Input() chan<- source.LogEntry {
	return t.input
}

func (t *TCPSink) Start(ctx context.Context) error {
	t.server = &tcpServer{sink: t}

	// Start log broadcast loop
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.broadcastLoop()
	}()

	// Configure gnet
	addr := fmt.Sprintf("tcp://:%d", t.config.Port)

	// Run gnet in separate goroutine to avoid blocking
	errChan := make(chan error, 1)
	go func() {
		t.logger.Info("msg", "Starting TCP server",
			"component", "tcp_sink",
			"port", t.config.Port)

		err := gnet.Run(t.server, addr,
			gnet.WithLogger(noopLogger{}),
			gnet.WithMulticore(true),
			gnet.WithReusePort(true),
		)
		if err != nil {
			t.logger.Error("msg", "TCP server failed",
				"component", "tcp_sink",
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
		},
	}
}

func (t *TCPSink) broadcastLoop() {
	var ticker *time.Ticker
	var tickerChan <-chan time.Time

	if t.config.Heartbeat.Enabled {
		ticker = time.NewTicker(time.Duration(t.config.Heartbeat.IntervalSeconds) * time.Second)
		tickerChan = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
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

			t.server.connections.Range(func(key, value any) bool {
				conn := key.(gnet.Conn)
				conn.AsyncWrite(data, nil)
				return true
			})

		case <-tickerChan:
			heartbeatEntry := t.createHeartbeatEntry()
			data, err := t.formatter.Format(heartbeatEntry)
			if err != nil {
				t.logger.Error("msg", "Failed to format heartbeat",
					"component", "tcp_sink",
					"error", err)
				continue
			}

			t.server.connections.Range(func(key, value any) bool {
				conn := key.(gnet.Conn)
				conn.AsyncWrite(data, nil)
				return true
			})

		case <-t.done:
			return
		}
	}
}

// Create heartbeat as a proper LogEntry
func (t *TCPSink) createHeartbeatEntry() source.LogEntry {
	message := "heartbeat"

	// Build fields for heartbeat metadata
	fields := make(map[string]any)
	fields["type"] = "heartbeat"

	if t.config.Heartbeat.IncludeStats {
		fields["active_connections"] = t.activeConns.Load()
		fields["uptime_seconds"] = int64(time.Since(t.startTime).Seconds())
	}

	fieldsJSON, _ := json.Marshal(fields)

	return source.LogEntry{
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

// tcpServer handles gnet events
type tcpServer struct {
	gnet.BuiltinEventEngine
	sink        *TCPSink
	connections sync.Map
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

	// Check net limit
	if s.sink.netLimiter != nil {
		// Parse the remote address to get proper net.Addr
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
			// Silently close connection when net limited
			return nil, gnet.Close
		}

		// Track connection
		s.sink.netLimiter.AddConnection(remoteStr)
	}

	s.connections.Store(c, struct{}{})

	newCount := s.sink.activeConns.Add(1)
	s.sink.logger.Debug("msg", "TCP connection opened",
		"remote_addr", remoteAddr,
		"active_connections", newCount)

	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	s.connections.Delete(c)

	remoteAddr := c.RemoteAddr().String()

	// Remove connection tracking
	if s.sink.netLimiter != nil {
		s.sink.netLimiter.RemoveConnection(c.RemoteAddr().String())
	}

	newCount := s.sink.activeConns.Add(-1)
	s.sink.logger.Debug("msg", "TCP connection closed",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"error", err)
	return gnet.None
}

func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	// We don't expect input from clients, just discard
	c.Discard(-1)
	return gnet.None
}

// noopLogger implements gnet Logger interface but discards everything
type noopLogger struct{}

func (n noopLogger) Debugf(format string, args ...any) {}
func (n noopLogger) Infof(format string, args ...any)  {}
func (n noopLogger) Warnf(format string, args ...any)  {}
func (n noopLogger) Errorf(format string, args ...any) {}
func (n noopLogger) Fatalf(format string, args ...any) {}