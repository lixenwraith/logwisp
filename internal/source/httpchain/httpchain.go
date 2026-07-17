package httpchain

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
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

	// Session cache: one session per remote host + declared node
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

	s := &HTTPChainSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		sessions:    make(map[string]string),
		logger:      logger,
	}
	s.lastEntryTime.Store(time.Time{})

	logger.Info("msg", "HTTP chain source initialized",
		"component", "http_chain_source",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port,
		"ingest_path", opts.IngestPath)
	return s, nil
}

// Capabilities returns supported capabilities
func (s *HTTPChainSource) Capabilities() []core.Capability {
	// CapTLS/CapAuth added when transport security lands
	return []core.Capability{
		core.CapSessionAware,
		core.CapMultiSession,
	}
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
		// Future: TLSConfig for transport security
	}
	s.startTime = time.Now()

	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	return source.SourceStats{
		ID:             s.id,
		Type:           "http_chain",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"host":              s.config.Host,
			"port":              s.config.Port,
			"ingest_path":       s.config.IngestPath,
			"total_requests":    s.totalRequests.Load(),
			"rejected_requests": s.rejectedRequests.Load(),
			"parse_errors":      s.parseErrors.Load(),
			"cached_sessions":   cachedSessions,
			"trust_node":        s.config.TrustNode,
		},
	}
}

// handleIngest validates protocol headers and ingests one NDJSON batch.
// Batch acceptance is atomic: entries publish only after a clean full read.
func (s *HTTPChainSource) handleIngest(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)

	if r.Header.Get(chain.HeaderProtocol) != strconv.Itoa(chain.ProtocolVersion) {
		s.rejectedRequests.Add(1)
		http.Error(w, "unsupported protocol version", http.StatusBadRequest)
		return
	}

	remoteHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteHost = host
	}
	connNode := r.Header.Get(chain.HeaderNode)
	if connNode == "" || !s.config.TrustNode {
		connNode = remoteHost
	}

	body := http.MaxBytesReader(w, r.Body, s.config.MaxBodyBytes)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), core.MaxLogEntryBytes)

	entries := make([]core.LogEntry, 0, 128)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		entry, err := chain.DecodeEntry(line, connNode, s.config.TrustNode)
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
	s.proxy.UpdateActivity(s.sessionFor(remoteHost, connNode))

	w.Header().Set(chain.HeaderAccepted, strconv.Itoa(len(entries)))
	w.WriteHeader(http.StatusNoContent)
}

// sessionFor returns the cached session for a remote+node, recreating after idle expiry
func (s *HTTPChainSource) sessionFor(remoteHost, node string) string {
	key := remoteHost + "|" + node
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if id, ok := s.sessions[key]; ok {
		if _, exists := s.proxy.GetSession(id); exists {
			return id
		}
	}
	sess := s.proxy.CreateSession(remoteHost, map[string]any{
		"type": "http_chain",
		"node": node,
	})
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
