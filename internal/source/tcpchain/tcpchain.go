package tcpchain

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/source"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSource("tcp_chain", NewTCPChainSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register tcp_chain source: %v", err))
	}
}

const (
	DefaultChainSourceBufferSize     = 1000
	DefaultChainSourceHelloTimeoutMS = 10000
)

// TCPChainSource accepts connections from upstream tcp_chain sinks and ingests NDJSON entries
type TCPChainSource struct {
	id     string
	proxy  *session.Proxy
	config *config.TCPChainSourceOptions

	subscribers []chan core.LogEntry
	listener    net.Listener
	conns       map[net.Conn]struct{}
	logger      *log.Logger

	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	startTime      time.Time
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	parseErrors    atomic.Uint64
	rejectedConns  atomic.Uint64
	activeConns    atomic.Int64
	lastEntryTime  atomic.Value // time.Time
}

// NewTCPChainSourcePlugin creates a tcp_chain source through plugin factory
func NewTCPChainSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	opts := &config.TCPChainSourceOptions{
		Host:      "0.0.0.0",
		TrustNode: true,
	}
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultChainSourceBufferSize
	}
	if opts.HelloTimeoutMS <= 0 {
		opts.HelloTimeoutMS = DefaultChainSourceHelloTimeoutMS
	}

	s := &TCPChainSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		conns:       make(map[net.Conn]struct{}),
		logger:      logger,
	}
	s.lastEntryTime.Store(time.Time{})

	logger.Info("msg", "TCP chain source initialized",
		"component", "tcp_chain_source",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port)
	return s, nil
}

// Capabilities returns supported capabilities
func (s *TCPChainSource) Capabilities() []core.Capability {
	// CapTLS/CapAuth added when transport security lands
	return []core.Capability{
		core.CapSessionAware,
		core.CapMultiSession,
	}
}

// Subscribe returns a channel for receiving log entries
func (s *TCPChainSource) Subscribe() <-chan core.LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan core.LogEntry, s.config.BufferSize)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

// Start binds the listener and begins accepting connections
func (s *TCPChainSource) Start() error {
	addr := net.JoinHostPort(s.config.Host, strconv.FormatInt(s.config.Port, 10))
	// IPv4-only
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.listener = ln
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.startTime = time.Now()

	s.wg.Add(1)
	go s.acceptLoop()

	s.logger.Info("msg", "TCP chain source started",
		"component", "tcp_chain_source",
		"instance_id", s.id,
		"addr", addr)
	return nil
}

// Stop closes the listener, all connections, and subscriber channels
func (s *TCPChainSource) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	for conn := range s.conns {
		conn.Close() // unblocks per-connection reads
	}
	s.mu.Unlock()

	s.wg.Wait()

	s.mu.Lock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.mu.Unlock()

	s.logger.Info("msg", "TCP chain source stopped",
		"component", "tcp_chain_source",
		"instance_id", s.id)
}

// GetStats returns the source's statistics
func (s *TCPChainSource) GetStats() source.SourceStats {
	lastEntry, _ := s.lastEntryTime.Load().(time.Time)
	return source.SourceStats{
		ID:             s.id,
		Type:           "tcp_chain",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"host":               s.config.Host,
			"port":               s.config.Port,
			"active_connections": s.activeConns.Load(),
			"rejected_conns":     s.rejectedConns.Load(),
			"parse_errors":       s.parseErrors.Load(),
			"trust_node":         s.config.TrustNode,
		},
	}
}

// acceptLoop accepts upstream connections until listener close
func (s *TCPChainSource) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			s.logger.Warn("msg", "Accept error",
				"component", "tcp_chain_source",
				"error", err)
			continue
		}

		if s.config.MaxConnections > 0 && s.activeConns.Load() >= s.config.MaxConnections {
			s.rejectedConns.Add(1)
			conn.Close()
			continue
		}

		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn validates the hello preamble, then streams entries until EOF/error
func (s *TCPChainSource) handleConn(conn net.Conn) {
	defer s.wg.Done()
	remote := conn.RemoteAddr().String()
	s.activeConns.Add(1)

	var sessID string
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		if sessID != "" {
			s.proxy.RemoveSession(sessID)
		}
		s.activeConns.Add(-1)
	}()

	scanner := bufio.NewScanner(conn)
	// Oversized line (> MaxLogEntryBytes) is a protocol violation; scanner is
	// unrecoverable after ErrTooLong, connection terminates
	scanner.Buffer(make([]byte, 0, 64*1024), core.MaxLogEntryBytes)

	// Hello preamble
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.HelloTimeoutMS) * time.Millisecond))
	if !scanner.Scan() {
		s.logger.Warn("msg", "Connection closed before hello",
			"component", "tcp_chain_source",
			"remote_addr", remote,
			"error", scanner.Err())
		return
	}
	hello, err := chain.DecodeHello(scanner.Bytes())
	if err != nil {
		s.logger.Warn("msg", "Rejected chain connection",
			"component", "tcp_chain_source",
			"remote_addr", remote,
			"error", err)
		return
	}

	connNode := hello.Node
	if connNode == "" || !s.config.TrustNode {
		if host, _, splitErr := net.SplitHostPort(remote); splitErr == nil {
			connNode = host
		} else {
			connNode = remote
		}
	}

	sess := s.proxy.CreateSession(remote, map[string]any{
		"type": "tcp_chain",
		"node": connNode,
	})
	sessID = sess.ID

	s.logger.Info("msg", "Chain connection established",
		"component", "tcp_chain_source",
		"remote_addr", remote,
		"node", connNode)

	idle := time.Duration(s.config.ReadTimeoutMS) * time.Millisecond
	for {
		if idle > 0 {
			conn.SetReadDeadline(time.Now().Add(idle))
		} else {
			conn.SetReadDeadline(time.Time{})
		}
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.logger.Debug("msg", "Chain read terminated",
					"component", "tcp_chain_source",
					"remote_addr", remote,
					"error", err)
			}
			return
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		s.proxy.UpdateActivity(sessID)

		entry, err := chain.DecodeEntry(line, connNode, s.config.TrustNode)
		if err != nil {
			s.parseErrors.Add(1)
			s.logger.Debug("msg", "Dropped malformed chain entry",
				"component", "tcp_chain_source",
				"error", err)
			continue
		}
		s.publish(entry)
	}
}

// parseEntry decodes a canonical LogEntry line and applies the node policy
func (s *TCPChainSource) parseEntry(line []byte, connNode string) (core.LogEntry, bool) {
	var entry core.LogEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		s.parseErrors.Add(1)
		s.logger.Debug("msg", "Dropped malformed chain entry",
			"component", "tcp_chain_source",
			"error", err)
		return core.LogEntry{}, false
	}
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	if entry.Node == "" || !s.config.TrustNode {
		entry.Node = connNode
	}
	entry.RawSize = int64(len(line))
	return entry, true
}

// publish sends a log entry to all subscribers
func (s *TCPChainSource) publish(entry core.LogEntry) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.totalEntries.Add(1)
	s.lastEntryTime.Store(entry.Time)

	for _, ch := range s.subscribers {
		select {
		case ch <- entry:
		default:
			s.droppedEntries.Add(1)
		}
	}
}
