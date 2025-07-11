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
	"logwisp/src/internal/ratelimit"
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
	activeConns atomic.Int32
	startTime   time.Time
	engine      *gnet.Engine
	engineMu    sync.Mutex
	wg          sync.WaitGroup
	rateLimiter *ratelimit.Limiter
	logger      *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// TCPConfig holds TCP sink configuration
type TCPConfig struct {
	Port       int
	BufferSize int
	Heartbeat  config.HeartbeatConfig
	SSL        *config.SSLConfig
	RateLimit  *config.RateLimitConfig
}

// NewTCPSink creates a new TCP streaming sink
func NewTCPSink(options map[string]any, logger *log.Logger) (*TCPSink, error) {
	cfg := TCPConfig{
		Port:       9090,
		BufferSize: 1000,
	}

	// Extract configuration from options
	if port, ok := toInt(options["port"]); ok {
		cfg.Port = port
	}
	if bufSize, ok := toInt(options["buffer_size"]); ok {
		cfg.BufferSize = bufSize
	}

	// Extract heartbeat config
	if hb, ok := options["heartbeat"].(map[string]any); ok {
		cfg.Heartbeat.Enabled, _ = hb["enabled"].(bool)
		if interval, ok := toInt(hb["interval_seconds"]); ok {
			cfg.Heartbeat.IntervalSeconds = interval
		}
		cfg.Heartbeat.IncludeTimestamp, _ = hb["include_timestamp"].(bool)
		cfg.Heartbeat.IncludeStats, _ = hb["include_stats"].(bool)
		if format, ok := hb["format"].(string); ok {
			cfg.Heartbeat.Format = format
		}
	}

	// Extract rate limit config
	if rl, ok := options["rate_limit"].(map[string]any); ok {
		cfg.RateLimit = &config.RateLimitConfig{}
		cfg.RateLimit.Enabled, _ = rl["enabled"].(bool)
		if rps, ok := toFloat(rl["requests_per_second"]); ok {
			cfg.RateLimit.RequestsPerSecond = rps
		}
		if burst, ok := toInt(rl["burst_size"]); ok {
			cfg.RateLimit.BurstSize = burst
		}
		if limitBy, ok := rl["limit_by"].(string); ok {
			cfg.RateLimit.LimitBy = limitBy
		}
		if respCode, ok := toInt(rl["response_code"]); ok {
			cfg.RateLimit.ResponseCode = respCode
		}
		if msg, ok := rl["response_message"].(string); ok {
			cfg.RateLimit.ResponseMessage = msg
		}
		if maxPerIP, ok := toInt(rl["max_connections_per_ip"]); ok {
			cfg.RateLimit.MaxConnectionsPerIP = maxPerIP
		}
		if maxTotal, ok := toInt(rl["max_total_connections"]); ok {
			cfg.RateLimit.MaxTotalConnections = maxTotal
		}
	}

	t := &TCPSink{
		input:     make(chan source.LogEntry, cfg.BufferSize),
		config:    cfg,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
	}
	t.lastProcessed.Store(time.Time{})

	if cfg.RateLimit != nil && cfg.RateLimit.Enabled {
		t.rateLimiter = ratelimit.New(*cfg.RateLimit, logger)
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

	var rateLimitStats map[string]any
	if t.rateLimiter != nil {
		rateLimitStats = t.rateLimiter.GetStats()
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
			"rate_limit":  rateLimitStats,
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

			data, err := json.Marshal(entry)
			if err != nil {
				t.logger.Error("msg", "Failed to marshal log entry",
					"component", "tcp_sink",
					"error", err,
					"entry_source", entry.Source)
				continue
			}
			data = append(data, '\n')

			t.server.connections.Range(func(key, value any) bool {
				conn := key.(gnet.Conn)
				conn.AsyncWrite(data, nil)
				return true
			})

		case <-tickerChan:
			if heartbeat := t.formatHeartbeat(); heartbeat != nil {
				t.server.connections.Range(func(key, value any) bool {
					conn := key.(gnet.Conn)
					conn.AsyncWrite(heartbeat, nil)
					return true
				})
			}

		case <-t.done:
			return
		}
	}
}

func (t *TCPSink) formatHeartbeat() []byte {
	if !t.config.Heartbeat.Enabled {
		return nil
	}

	data := make(map[string]any)
	data["type"] = "heartbeat"

	if t.config.Heartbeat.IncludeTimestamp {
		data["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	}

	if t.config.Heartbeat.IncludeStats {
		data["active_connections"] = t.activeConns.Load()
		data["uptime_seconds"] = int(time.Since(t.startTime).Seconds())
	}

	// For TCP, always use JSON format
	jsonData, _ := json.Marshal(data)
	return append(jsonData, '\n')
}

// GetActiveConnections returns the current number of connections
func (t *TCPSink) GetActiveConnections() int32 {
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

	// Check rate limit
	if s.sink.rateLimiter != nil {
		// Parse the remote address to get proper net.Addr
		remoteStr := c.RemoteAddr().String()
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteStr)
		if err != nil {
			s.sink.logger.Warn("msg", "Failed to parse TCP address",
				"remote_addr", remoteAddr,
				"error", err)
			return nil, gnet.Close
		}

		if !s.sink.rateLimiter.CheckTCP(tcpAddr) {
			s.sink.logger.Warn("msg", "TCP connection rate limited",
				"remote_addr", remoteAddr)
			// Silently close connection when rate limited
			return nil, gnet.Close
		}

		// Track connection
		s.sink.rateLimiter.AddConnection(remoteStr)
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
	if s.sink.rateLimiter != nil {
		s.sink.rateLimiter.RemoveConnection(c.RemoteAddr().String())
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

// noopLogger implements gnet's Logger interface but discards everything
type noopLogger struct{}

func (n noopLogger) Debugf(format string, args ...any) {}
func (n noopLogger) Infof(format string, args ...any)  {}
func (n noopLogger) Warnf(format string, args ...any)  {}
func (n noopLogger) Errorf(format string, args ...any) {}
func (n noopLogger) Fatalf(format string, args ...any) {}