package tcpchain

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/authz"
	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/source"
	"logwisp/internal/tlsx"

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

	// TLS
	tlsConfig          *tls.Config
	tlsHandshakeErrors atomic.Uint64

	// Authorization
	auth *authz.Policy

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
	tlsCfg, err := tlsx.Server(opts.TLS)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, opts.TLS, authz.RoleChainListener)
	if err != nil {
		return nil, err
	}

	s := &TCPChainSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		conns:       make(map[net.Conn]struct{}),
		logger:      logger,
		tlsConfig:   tlsCfg,
		auth:        authPolicy,
	}
	s.lastEntryTime.Store(time.Time{})

	logger.Info("msg", "TCP chain source initialized",
		"component", "tcp_chain_source",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port,
		"tls", tlsCfg != nil,
		"mtls", tlsCfg != nil && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert,
		"auth", authPolicy.Describe())
	if authPolicy.Unrestricted() {
		logger.Warn("msg", "Auth policy admits any identity the configured CA vouches for",
			"component", "tcp_chain_source",
			"instance_id", id,
			"hint", "set auth.allow or auth.allow_patterns to authorize named peers")
	}
	if authPolicy.BindsNode() {
		logger.Info("msg", "Node labels bound to peer identity; trust_node is ignored",
			"component", "tcp_chain_source",
			"instance_id", id,
			"node_binding", authPolicy.NodeBinding(),
			"trust_node", opts.TrustNode)
	}
	return s, nil
}

// Capabilities returns supported capabilities
func (s *TCPChainSource) Capabilities() []core.Capability {
	caps := []core.Capability{core.CapSessionAware, core.CapMultiSession}
	if s.tlsConfig != nil {
		caps = append(caps, core.CapTLS)
	}
	if s.auth.Enabled() {
		caps = append(caps, core.CapAuth) // authorizes peers, not just the CA
	}
	return caps
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
	// IPv4-only. TLS-wrapped when configured; handshake runs explicitly in
	// handleConn under tlsx.HandshakeTimeout, pre-hello.
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
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
	details := map[string]any{
		"host":                 s.config.Host,
		"port":                 s.config.Port,
		"tls":                  s.tlsConfig != nil,
		"tls_handshake_errors": s.tlsHandshakeErrors.Load(),
		"active_connections":   s.activeConns.Load(),
		"rejected_conns":       s.rejectedConns.Load(),
		"parse_errors":         s.parseErrors.Load(),
		"trust_node":           s.config.TrustNode,
	}
	maps.Copy(details, s.auth.Stats())

	return source.SourceStats{
		ID:             s.id,
		Type:           "tcp_chain",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details:        details,
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

	var tlsState *tls.ConnectionState
	if tc, ok := conn.(*tls.Conn); ok {
		hctx, cancel := context.WithTimeout(s.ctx, tlsx.HandshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			s.tlsHandshakeErrors.Add(1)
			s.logger.Warn("msg", "TLS handshake failed",
				"component", "tcp_chain_source",
				"remote_addr", remote,
				"error", err)
			return // deferred cleanup closes conn
		}
		cs := tc.ConnectionState()
		tlsState = &cs
	}

	// Authorize before a preamble is parsed on an unauthorized peer's behalf
	ident, err := s.auth.Authorize(tlsState)
	if err != nil {
		s.rejectedConns.Add(1)
		s.logger.Warn("msg", "Connection rejected by auth policy",
			"component", "tcp_chain_source",
			"instance_id", s.id,
			"remote_addr", remote,
			"error", err)
		return // deferred cleanup closes conn
	}

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

	fallbackNode := remote
	if host, _, splitErr := net.SplitHostPort(remote); splitErr == nil {
		fallbackNode = host
	}
	connNode, err := s.auth.ResolveNode(hello.Node, fallbackNode, s.config.TrustNode, ident)
	if err != nil {
		s.rejectedConns.Add(1)
		s.logger.Warn("msg", "Connection rejected by node binding",
			"component", "tcp_chain_source",
			"instance_id", s.id,
			"remote_addr", remote,
			"declared_node", hello.Node,
			"error", err)
		return
	}
	// force relabels every entry, so an edge cannot smuggle a foreign origin
	// through the per-entry node field either
	trustEntryNode := s.auth.TrustsEntryNode(s.config.TrustNode)

	meta := map[string]any{
		"type": "tcp_chain",
		"node": connNode,
	}
	if tlsState != nil {
		meta["tls"] = true
		if cn := tlsx.PeerCN(*tlsState); cn != "" {
			meta["tls_peer_cn"] = cn
		}
	}
	ident.Apply(meta)
	sess := s.proxy.CreateSession(remote, meta)
	sessID = sess.ID

	s.logger.Info("msg", "Chain connection established",
		"component", "tcp_chain_source",
		"remote_addr", remote,
		"node", connNode,
		"auth_identity", ident.Name)

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

		entry, err := chain.DecodeEntry(line, connNode, trustEntryNode)
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
