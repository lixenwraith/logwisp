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
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/netacl"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/source"
	"github.com/lixenwraith/logwisp/internal/tlsx"

	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSource("http_chain", NewHTTPChainSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register http_chain source: %v", err))
	}
}

const (
	HTTPChainReadHeaderTimeout     = 10 * time.Second
	HTTPChainServerShutdownTimeout = 2 * time.Second
)

// HTTPChainSource accepts NDJSON batches from upstream http_chain sinks
type HTTPChainSource struct {
	id      string
	proxy   *session.Proxy
	config  *config.HTTPChainSourceOptions
	network string

	subscribers []chan core.LogEntry
	server      *http.Server
	logger      *log.Logger

	// TLS
	tlsConfig *tls.Config

	// Authorization
	auth *authz.Policy
	acl  *netacl.Policy

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
	opts, err := config.Decode[config.HTTPChainSourceOptions]("source", "http_chain", configMap)
	if err != nil {
		return nil, err
	}
	network, err := core.Network(opts.Host)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := tlsx.Server(opts.TLS, opts.Host)
	if err != nil {
		return nil, err
	}
	aclPolicy, err := netacl.New(opts.ACL, opts.Host, netacl.HTTP, logger, "http_chain_source", id)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, tlsCfg, aclPolicy, config.ChainListener, authz.HTTP)
	if err != nil {
		return nil, err
	}

	s := &HTTPChainSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		network:     network,
		subscribers: make([]chan core.LogEntry, 0),
		sessions:    make(map[string]string),
		logger:      logger,
		tlsConfig:   tlsCfg,
		auth:        authPolicy,
		acl:         aclPolicy,
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
		"auth", authPolicy.Describe(),
		"acl", aclPolicy.Describe())
	tlsx.LogWarnings(logger, "http_chain_source", id, opts.TLS, true)
	authPolicy.LogStartup(logger, "http_chain_source", id, opts.TrustNode)
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
	if err := s.auth.Start(); err != nil {
		return err
	}
	addr := net.JoinHostPort(s.config.Host, strconv.FormatInt(s.config.Port, 10))
	ln, err := core.Listen(context.Background(), &net.ListenConfig{}, s.network, addr)
	if err != nil {
		s.auth.Close()
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	ln = s.acl.Listener(ln)

	mux := http.NewServeMux()
	// Method-scoped pattern: mux answers 405 with Allow header on non-POST
	mux.Handle(http.MethodPost+" "+s.config.IngestPath, s.acl.Requests(http.HandlerFunc(s.handleIngest), nil))
	// Answers 404 unless the policy is scram, whose throttling limits it
	mux.HandleFunc(http.MethodPost+" "+chain.AuthPath, s.handleAuth)

	s.server = &http.Server{
		Handler:           mux,
		ReadTimeout:       time.Duration(s.config.ReadTimeoutMS) * time.Millisecond,
		ReadHeaderTimeout: HTTPChainReadHeaderTimeout,
		ConnContext:       netacl.ConnContext,
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
	s.auth.Close()

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
	maps.Copy(details, s.acl.Stats())

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
	// to stream max_body_bytes into the process. 401 (log in again) and 403
	// (not allowed) are distinct from the 400 used for protocol errors.
	ident, status, err := s.auth.AuthorizeRequest(r)
	if err != nil {
		s.rejectedRequests.Add(1)
		s.logger.Warn("msg", "Request rejected by auth policy",
			"component", "http_chain_source",
			"instance_id", s.id,
			"remote_addr", r.RemoteAddr,
			"error", err)
		authz.Refuse(w, status)
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
	s.proxy.UpdateActivity(s.sessionFor(remoteHost, connNode, netacl.ContextPeerAddr(r.Context()), r.TLS, ident))

	w.Header().Set(chain.HeaderAccepted, strconv.Itoa(len(entries)))
	w.WriteHeader(http.StatusNoContent)
}

// handleAuth runs one step of a SCRAM login and logs its outcome
func (s *HTTPChainSource) handleAuth(w http.ResponseWriter, r *http.Request) {
	ident, err := s.auth.ServeAuth(w, r)
	switch {
	case err != nil:
		s.logger.Warn("msg", "Login rejected",
			"component", "http_chain_source",
			"instance_id", s.id,
			"remote_addr", r.RemoteAddr,
			"error", err)
	case ident.Name != "":
		s.logger.Info("msg", "Login accepted",
			"component", "http_chain_source",
			"instance_id", s.id,
			"remote_addr", r.RemoteAddr,
			"auth_identity", ident.Name)
	}
}

// sessionFor returns the cached session for a remote+node+identity,
// recreating after idle expiry. Identity is part of the key so two peers
// sharing a remote address never share a session.
func (s *HTTPChainSource) sessionFor(remoteHost, node, peer string, cs *tls.ConnectionState, ident authz.Identity) string {
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
	if peer != "" {
		meta["peer_addr"] = peer
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
