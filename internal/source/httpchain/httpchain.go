package httpchain

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	if err := plugin.RegisterSource("http_chain", NewHTTPChainSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register http_chain source: %v", err))
	}
}

const (
	DefaultHTTPChainSourceBufferSize    = 1000
	DefaultHTTPChainSourceIngestPath    = "/ingest"
	DefaultHTTPChainSourceMaxBodyBytes  = 8 * 1024 * 1024
	DefaultHTTPChainSourceReadTimeoutMS = 30000
	HTTPChainReadHeaderTimeout          = 10 * time.Second
	HTTPChainServerShutdownTimeout      = 2 * time.Second
)

// HTTPChainSource accepts NDJSON batches from upstream http_chain sinks
type HTTPChainSource struct {
	id     string
	proxy  *session.Proxy
	config *config.HTTPChainSourceOptions

	subscribers []chan core.LogEntry
	server      *http.Server
	logger      *log.Logger

	// TLS
	tlsConfig *tls.Config

	// Authorization
	auth *authz.Policy

	// Session cache: one session per remote host + node + authenticated identity
	sessions   map[string]string // key -> sessionID
	sessionsMu sync.Mutex

	mu sync.RWMutex

	startTime        time.Time
	totalEntries     atomic.Uint64
	droppedEntries   atomic.Uint64
	parseErrors      atomic.Uint64
	totalRequests    atomic.Uint64
	rejectedRequests atomic.Uint64
	lastEntryTime    atomic.Value // time.Time
}

// NewHTTPChainSourcePlugin creates an http_chain source through plugin factory
func NewHTTPChainSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	opts := &config.HTTPChainSourceOptions{
		Host:      "0.0.0.0",
		TrustNode: true,
	}
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	if opts.IngestPath == "" {
		opts.IngestPath = DefaultHTTPChainSourceIngestPath
	} else if !strings.HasPrefix(opts.IngestPath, "/") {
		return nil, fmt.Errorf("ingest_path: must start with '/'")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultHTTPChainSourceBufferSize
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultHTTPChainSourceMaxBodyBytes
	}
	if opts.ReadTimeoutMS <= 0 {
		opts.ReadTimeoutMS = DefaultHTTPChainSourceReadTimeoutMS
	}
	tlsCfg, err := tlsx.Server(opts.TLS)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, opts.TLS, authz.RoleChainListener)
	if err != nil {
		return nil, err
	}

	s := &HTTPChainSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		sessions:    make(map[string]string),
		logger:      logger,
		tlsConfig:   tlsCfg,
		auth:        authPolicy,
	}
	s.lastEntryTime.Store(time.Time{})

	logger.Info("msg", "HTTP chain source initialized",
		"component", "http_chain_source",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port,
		"ingest_path", opts.IngestPath,
		"tls", tlsCfg != nil,
		"mtls", tlsCfg != nil && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert,
		"auth", authPolicy.Describe())
	if authPolicy.Unrestricted() {
		logger.Warn("msg", "Auth policy admits any identity the configured CA vouches for",
			"component", "http_chain_source",
			"instance_id", id,
			"hint", "set auth.allow or auth.allow_patterns to authorize named peers")
	}
	if authPolicy.BindsNode() {
		logger.Info("msg", "Node labels bound to peer identity; trust_node is ignored",
			"component", "http_chain_source",
			"instance_id", id,
			"node_binding", authPolicy.NodeBinding(),
			"trust_node", opts.TrustNode)
	}
	return s, nil
}

// Capabilities returns supported capabilities
func (s *HTTPChainSource) Capabilities() []core.Capability {
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
func (s *HTTPChainSource) Subscribe() <-chan core.LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan core.LogEntry, s.config.BufferSize)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

// Start binds the listener and serves the ingest endpoint
func (s *HTTPChainSource) Start() error {
	addr := net.JoinHostPort(s.config.Host, strconv.FormatInt(s.config.Port, 10))
	// IPv4-only, aligns with tcp/http sinks
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	// Method-scoped pattern: mux answers 405 with Allow header on non-POST
	mux.HandleFunc(http.MethodPost+" "+s.config.IngestPath, s.handleIngest)

	s.server = &http.Server{
		Handler:           mux,
		ReadTimeout:       time.Duration(s.config.ReadTimeoutMS) * time.Millisecond,
		ReadHeaderTimeout: HTTPChainReadHeaderTimeout,
		// TLS handshake bounded by min(ReadTimeout, ReadHeaderTimeout)
		ErrorLog: tlsx.HTTPErrorLog(s.logger, "http_chain_source"),
	}
	s.startTime = time.Now()

	serve := s.server.Serve
	if s.tlsConfig != nil {
		s.server.TLSConfig = s.tlsConfig
		serve = func(l net.Listener) error { return s.server.ServeTLS(l, "", "") }
	}

	go func() {
		if err := serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("msg", "HTTP chain server terminated",
				"component", "http_chain_source",
				"instance_id", s.id,
				"error", err)
		}
	}()

	s.logger.Info("msg", "HTTP chain source started",
		"component", "http_chain_source",
		"instance_id", s.id,
		"addr", addr)
	return nil
}

// Stop shuts down the server, sessions, and subscriber channels
func (s *HTTPChainSource) Stop() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), HTTPChainServerShutdownTimeout)
		defer cancel()
		s.server.Shutdown(ctx)
	}

	s.sessionsMu.Lock()
	for _, id := range s.sessions {
		s.proxy.RemoveSession(id)
	}
	s.sessions = make(map[string]string)
	s.sessionsMu.Unlock()

	s.mu.Lock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.mu.Unlock()

	s.logger.Info("msg", "HTTP chain source stopped",
		"component", "http_chain_source",
		"instance_id", s.id)
}

// GetStats returns the source's statistics
func (s *HTTPChainSource) GetStats() source.SourceStats {
	lastEntry, _ := s.lastEntryTime.Load().(time.Time)

	s.sessionsMu.Lock()
	cachedSessions := len(s.sessions)
	s.sessionsMu.Unlock()

	details := map[string]any{
		"host":              s.config.Host,
		"port":              s.config.Port,
		"ingest_path":       s.config.IngestPath,
		"tls":               s.tlsConfig != nil,
		"total_requests":    s.totalRequests.Load(),
		"rejected_requests": s.rejectedRequests.Load(),
		"parse_errors":      s.parseErrors.Load(),
		"cached_sessions":   cachedSessions,
		"trust_node":        s.config.TrustNode,
	}
	maps.Copy(details, s.auth.Stats())

	return source.SourceStats{
		ID:             s.id,
		Type:           "http_chain",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details:        details,
	}
}

// handleIngest validates protocol headers and ingests one NDJSON batch.
// Batch acceptance is atomic: entries publish only after a clean full read.
func (s *HTTPChainSource) handleIngest(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)

	// Authorize before the body is read: an unauthorized sender should not get
	// to stream max_body_bytes into the process. 403 is distinct from the 400
	// used for protocol errors, so a sender can tell "not allowed" from
	// "malformed batch".
	ident, err := s.auth.Authorize(r.TLS)
	if err != nil {
		s.rejectedRequests.Add(1)
		s.logger.Warn("msg", "Request rejected by auth policy",
			"component", "http_chain_source",
			"instance_id", s.id,
			"remote_addr", r.RemoteAddr,
			"error", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if r.Header.Get(chain.HeaderProtocol) != strconv.Itoa(chain.ProtocolVersion) {
		s.rejectedRequests.Add(1)
		http.Error(w, "unsupported protocol version", http.StatusBadRequest)
		return
	}

	remoteHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteHost = host
	}
	declaredNode := r.Header.Get(chain.HeaderNode)
	connNode, err := s.auth.ResolveNode(declaredNode, remoteHost, s.config.TrustNode, ident)
	if err != nil {
		s.rejectedRequests.Add(1)
		s.logger.Warn("msg", "Request rejected by node binding",
			"component", "http_chain_source",
			"instance_id", s.id,
			"remote_addr", r.RemoteAddr,
			"declared_node", declaredNode,
			"error", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// force relabels every entry, so a sender cannot smuggle a foreign origin
	// through the per-entry node field either
	trustEntryNode := s.auth.TrustsEntryNode(s.config.TrustNode)

	body := http.MaxBytesReader(w, r.Body, s.config.MaxBodyBytes)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), core.MaxLogEntryBytes)

	entries := make([]core.LogEntry, 0, 128)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		entry, err := chain.DecodeEntry(line, connNode, trustEntryNode)
		if err != nil {
			// Content error within a clean transfer: skip line, keep batch
			s.parseErrors.Add(1)
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		// Transfer error: reject batch without partial ingestion, sender retries
		s.rejectedRequests.Add(1)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.logger.Debug("msg", "Chain batch read failed",
			"component", "http_chain_source",
			"remote_addr", r.RemoteAddr,
			"error", err)
		http.Error(w, "malformed body", http.StatusBadRequest)
		return
	}

	for _, entry := range entries {
		s.publish(entry)
	}
	s.proxy.UpdateActivity(s.sessionFor(remoteHost, connNode, r.TLS, ident))

	w.Header().Set(chain.HeaderAccepted, strconv.Itoa(len(entries)))
	w.WriteHeader(http.StatusNoContent)
}

// sessionFor returns the cached session for a remote+node+identity,
// recreating after idle expiry. Identity is part of the key so two peers
// sharing a remote address never share a session.
func (s *HTTPChainSource) sessionFor(remoteHost, node string, cs *tls.ConnectionState, ident authz.Identity) string {
	key := remoteHost + "|" + node + "|" + ident.Name
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if id, ok := s.sessions[key]; ok {
		if _, exists := s.proxy.GetSession(id); exists {
			return id
		}
	}
	meta := map[string]any{
		"type": "http_chain",
		"node": node,
	}
	if cs != nil {
		meta["tls"] = true
		if cn := tlsx.PeerCN(*cs); cn != "" {
			meta["tls_peer_cn"] = cn
		}
	}
	ident.Apply(meta)
	sess := s.proxy.CreateSession(remoteHost, meta)
	s.sessions[key] = sess.ID
	return sess.ID
}

// publish sends a log entry to all subscribers
func (s *HTTPChainSource) publish(entry core.LogEntry) {
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
