// FILE: src/internal/source/tcp.go
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/netlimit"

	"github.com/lixenwraith/log"
	"github.com/panjf2000/gnet/v2"
)

// TCPSource receives log entries via TCP connections
type TCPSource struct {
	port        int64
	bufferSize  int64
	server      *tcpSourceServer
	subscribers []chan LogEntry
	mu          sync.RWMutex
	done        chan struct{}
	engine      *gnet.Engine
	engineMu    sync.Mutex
	wg          sync.WaitGroup
	netLimiter  *netlimit.Limiter
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

			t.netLimiter = netlimit.New(cfg, logger)
		}
	}

	return t, nil
}

func (t *TCPSource) Subscribe() <-chan LogEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch := make(chan LogEntry, t.bufferSize)
	t.subscribers = append(t.subscribers, ch)
	return ch
}

func (t *TCPSource) Start() error {
	t.server = &tcpSourceServer{
		source:  t,
		clients: make(map[gnet.Conn]*tcpClient),
	}

	addr := fmt.Sprintf("tcp://:%d", t.port)

	// Start gnet server in background
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.logger.Info("msg", "TCP source server starting",
			"component", "tcp_source",
			"port", t.port)

		err := gnet.Run(t.server, addr,
			gnet.WithLogger(noopLogger{}),
			gnet.WithMulticore(true),
			gnet.WithReusePort(true),
		)
		if err != nil {
			t.logger.Error("msg", "TCP source server failed",
				"component", "tcp_source",
				"port", t.port,
				"error", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	return nil
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

func (t *TCPSource) publish(entry LogEntry) bool {
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
	conn   gnet.Conn
	buffer bytes.Buffer
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
		remoteStr := c.RemoteAddr().String()
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteStr)
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
		s.source.netLimiter.AddConnection(remoteStr)
	}

	// Create client state
	s.mu.Lock()
	s.clients[c] = &tcpClient{conn: c}
	s.mu.Unlock()

	newCount := s.source.activeConns.Add(1)
	s.source.logger.Debug("msg", "TCP connection opened",
		"component", "tcp_source",
		"remote_addr", remoteAddr,
		"active_connections", newCount)

	return nil, gnet.None
}

func (s *tcpSourceServer) OnClose(c gnet.Conn, err error) gnet.Action {
	remoteAddr := c.RemoteAddr().String()

	// Remove client state
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()

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

	// Append to client buffer
	client.buffer.Write(data)

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
		var entry LogEntry
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
type noopLogger struct{}

func (n noopLogger) Debugf(format string, args ...any) {}
func (n noopLogger) Infof(format string, args ...any)  {}
func (n noopLogger) Warnf(format string, args ...any)  {}
func (n noopLogger) Errorf(format string, args ...any) {}
func (n noopLogger) Fatalf(format string, args ...any) {}