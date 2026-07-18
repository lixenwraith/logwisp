package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/sink"
	"logwisp/internal/tlsx"
	"logwisp/internal/version"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSink("http", NewHTTPSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register http sink: %v", err))
	}
}

const (
	DefaultHTTPHost             = "0.0.0.0"
	DefaultHTTPBufferSize       = 1000
	DefaultHTTPClientBufferSize = 256
	DefaultHTTPStreamPath       = "/stream"
	DefaultHTTPStatusPath       = "/status"
	HTTPReadHeaderTimeout       = 10 * time.Second
	HTTPShutdownTimeout         = 2 * time.Second
)

// HTTPSink streams log entries via Server-Sent Events
// Server.WriteTimeout is deliberately unset (it would terminate long-lived SSE streams)
// per-write deadlines are applied via http.ResponseController
type HTTPSink struct {
	// Plugin identity and session management
	id    string
	proxy *session.Proxy

	// Configuration
	config *config.HTTPSinkOptions
	addr   string

	// Network
	server *http.Server

	// Application
	input  chan core.TransportEvent
	logger *log.Logger

	// Client registry
	clients      map[uint64]*sseClient
	clientsMu    sync.Mutex
	nextClientID atomic.Uint64
	writeTimeout time.Duration

	// TLS
	tlsConfig *tls.Config

	// Runtime
	done      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	startTime time.Time

	// Statistics
	activeClients   atomic.Int64
	totalProcessed  atomic.Uint64
	droppedWrites   atomic.Uint64
	rejectedClients atomic.Uint64
	lastProcessed   atomic.Value // time.Time
}

// sseClient is a registered stream consumer with a bounded send queue
type sseClient struct {
	send      chan []byte
	sessionID string
}

// NewHTTPSinkPlugin creates a http sink through plugin factory
func NewHTTPSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.HTTPSinkOptions{
		Host:           DefaultHTTPHost,
		WriteTimeoutMS: 0, // SSE indefinite streaming
	}
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	if opts.StreamPath == "" {
		opts.StreamPath = DefaultHTTPStreamPath
	} else if !strings.HasPrefix(opts.StreamPath, "/") {
		return nil, fmt.Errorf("stream_path: must start with '/'")
	}
	if opts.StatusPath == "" {
		opts.StatusPath = DefaultHTTPStatusPath
	} else if !strings.HasPrefix(opts.StatusPath, "/") {
		return nil, fmt.Errorf("status_path: must start with '/'")
	}
	if opts.StreamPath == opts.StatusPath {
		return nil, fmt.Errorf("stream_path and status_path must differ")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultHTTPBufferSize
	}
	if opts.ClientBufferSize <= 0 {
		opts.ClientBufferSize = DefaultHTTPClientBufferSize
	}
	tlsCfg, err := tlsx.Server(opts.TLS)
	if err != nil {
		return nil, err
	}

	h := &HTTPSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		addr:         net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10)),
		input:        make(chan core.TransportEvent, opts.BufferSize),
		done:         make(chan struct{}),
		logger:       logger,
		clients:      make(map[uint64]*sseClient),
		writeTimeout: time.Duration(opts.WriteTimeoutMS) * time.Millisecond,
		tlsConfig:    tlsCfg,
	}
	h.lastProcessed.Store(time.Time{})

	logger.Info("msg", " HTTP sink initialized",
		"component", "http_sink",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port,
		"stream_path", opts.StreamPath,
		"status_path", opts.StatusPath,
		"tls", tlsCfg != nil,
		"mtls", tlsCfg != nil && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert)
	return h, nil
}

// Capabilities returns supported capabilities
func (h *HTTPSink) Capabilities() []core.Capability {
	caps := []core.Capability{core.CapSessionAware, core.CapMultiSession}
	if h.tlsConfig != nil {
		caps = append(caps, core.CapTLS)
		if h.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			caps = append(caps, core.CapAuth) // mTLS is authentication
		}
	}
	return caps
}

// Input returns the channel for sending transport events
func (h *HTTPSink) Input() chan<- core.TransportEvent {
	return h.input
}

// Start binds the listener and serves stream/status endpoints
func (h *HTTPSink) Start(ctx context.Context) error {
	// IPv4-only, parity with existing network sinks.
	// TLS is applied via server.TLSConfig + ServeTLS below, not by wrapping
	// ln; net/http then owns handshake, ALPN (h2), and per-conn errors.
	ln, err := net.Listen("tcp4", h.addr)
	if err != nil {
		return fmt.Errorf("http sink bind %s: %w", h.addr, err)
	}

	mux := http.NewServeMux()
	// Method-scoped patterns: mux answers 405 with Allow header on non-GET
	mux.HandleFunc(http.MethodGet+" "+h.config.StreamPath, h.handleStream)
	mux.HandleFunc(http.MethodGet+" "+h.config.StatusPath, h.handleStatus)

	// Auth extension point: wrap mux with auth middleware once credentials
	// land, e.g. handler = authMiddleware(cfg)(handler)
	var handler http.Handler = mux

	h.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: HTTPReadHeaderTimeout,
		// WriteTimeout unset by design: SSE responses are long-lived.
		// net/http bounds the TLS handshake by min(ReadHeaderTimeout,
		// ReadTimeout, WriteTimeout), so ReadHeaderTimeout covers it here.
		ErrorLog: tlsx.HTTPErrorLog(h.logger, "http_sink"),
	}
	h.startTime = time.Now()

	h.wg.Add(1)
	go h.brokerLoop(ctx)

	serve := h.server.Serve
	if h.tlsConfig != nil {
		h.server.TLSConfig = h.tlsConfig
		serve = func(l net.Listener) error { return h.server.ServeTLS(l, "", "") }
	}

	go func() {
		if err := serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Error("msg", "HTTP server terminated",
				"component", "http_sink",
				"instance_id", h.id,
				"error", err)
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			h.shutdown()
		case <-h.done:
		}
	}()

	h.logger.Info("msg", " HTTP server started",
		"component", "http_sink",
		"instance_id", h.id,
		"addr", h.addr)
	return nil
}

// Stop gracefully shuts down the sink
func (h *HTTPSink) Stop() {
	h.logger.Info("msg", "Stopping HTTP sink",
		"component", "http_sink",
		"instance_id", h.id)

	h.shutdown()
	h.wg.Wait()

	h.logger.Info("msg", " HTTP sink stopped",
		"component", "http_sink",
		"instance_id", h.id,
		"total_processed", h.totalProcessed.Load())
}

// shutdown funnels ctx-cancel and Stop() teardown through a single path.
// done is closed first so SSE handlers exit and Shutdown can complete;
// Server.Close force-closes any handler stalled in a deadline-free write.
func (h *HTTPSink) shutdown() {
	h.stopOnce.Do(func() {
		close(h.done)
		if h.server != nil {
			sctx, cancel := context.WithTimeout(context.Background(), HTTPShutdownTimeout)
			defer cancel()
			if err := h.server.Shutdown(sctx); err != nil {
				h.server.Close()
			}
		}
	})
}

// removeClient unregisters a client; the first caller closes the send
// channel and removes the session. Broker (stale-session eviction) and
// stream handler (disconnect) may race here safely.
func (h *HTTPSink) removeClient(id uint64) {
	h.clientsMu.Lock()
	c, ok := h.clients[id]
	if ok {
		delete(h.clients, id)
	}
	h.clientsMu.Unlock()
	if ok {
		close(c.send)
		h.proxy.RemoveSession(c.sessionID)
	}
}

// brokerLoop fans out transport events to all client queues, non-blocking,
// and evicts clients whose sessions were idle-expired by the session manager
func (h *HTTPSink) brokerLoop(ctx context.Context) {
	defer h.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.done:
			return
		case event, ok := <-h.input:
			if !ok {
				return
			}
			h.totalProcessed.Add(1)
			h.lastProcessed.Store(time.Now())

			var stale []uint64
			h.clientsMu.Lock()
			for id, c := range h.clients {
				if _, exists := h.proxy.GetSession(c.sessionID); !exists {
					stale = append(stale, id)
					continue
				}
				select {
				case c.send <- event.Payload:
					h.proxy.UpdateActivity(c.sessionID)
				default:
					h.droppedWrites.Add(1)
				}
			}
			h.clientsMu.Unlock()

			for _, id := range stale {
				h.removeClient(id)
			}
		}
	}
}

// handleStream serves one client's SSE stream
func (h *HTTPSink) handleStream(w http.ResponseWriter, r *http.Request) {
	if h.config.MaxConnections > 0 && h.activeClients.Load() >= h.config.MaxConnections {
		h.rejectedClients.Add(1)
		http.Error(w, "too many clients", http.StatusServiceUnavailable)
		return
	}

	rc := http.NewResponseController(w)
	remote := r.RemoteAddr

	meta := map[string]any{
		"type": "http_client",
	}
	if r.TLS != nil {
		meta["tls"] = true
		if cn := tlsx.PeerCN(*r.TLS); cn != "" {
			meta["tls_peer_cn"] = cn
		}
	}
	sess := h.proxy.CreateSession(remote, meta)

	c := &sseClient{
		send:      make(chan []byte, h.config.ClientBufferSize),
		sessionID: sess.ID,
	}
	id := h.nextClientID.Add(1)

	h.clientsMu.Lock()
	h.clients[id] = c
	h.clientsMu.Unlock()

	count := h.activeClients.Add(1)
	h.logger.Debug("msg", "HTTP client connected",
		"component", "http_sink",
		"remote_addr", remote,
		"session_id", sess.ID,
		"client_id", id,
		"active_clients", count)

	defer func() {
		h.removeClient(id)
		newCount := h.activeClients.Add(-1)
		h.logger.Debug("msg", "HTTP client disconnected",
			"component", "http_sink",
			"remote_addr", remote,
			"session_id", sess.ID,
			"client_id", id,
			"active_clients", newCount)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Connected event with metadata, parity with fasthttp sink
	info, _ := json.Marshal(map[string]any{
		"client_id":   strconv.FormatUint(id, 10),
		"session_id":  sess.ID,
		"instance_id": h.id,
		"stream_path": h.config.StreamPath,
		"status_path": h.config.StatusPath,
		"buffer_size": h.config.ClientBufferSize,
	})
	fmt.Fprintf(w, "event: connected\ndata: %s\n\n", info)
	if err := rc.Flush(); err != nil {
		return
	}

	clientGone := r.Context().Done()
	for {
		select {
		case payload, ok := <-c.send:
			if !ok {
				return // broker evicted (stale session)
			}
			if h.writeTimeout > 0 {
				_ = rc.SetWriteDeadline(time.Now().Add(h.writeTimeout))
			}
			if err := writeSSE(w, payload); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			h.proxy.UpdateActivity(sess.ID)
		case <-clientGone:
			return
		case <-h.done:
			fmt.Fprintf(w, "event: disconnect\ndata: {\"reason\":\"server_shutdown\"}\n\n")
			rc.Flush()
			return
		}
	}
}

// handleStatus provides a JSON status report
func (h *HTTPSink) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"service":     "LogWisp",
		"version":     version.Short(),
		"instance_id": h.id,
		"server": map[string]any{
			"type":           "http",
			"host":           h.config.Host,
			"port":           h.config.Port,
			"tls":            h.tlsConfig != nil,
			"active_clients": h.activeClients.Load(),
			"buffer_size":    h.config.BufferSize,
			"uptime_seconds": int(time.Since(h.startTime).Seconds()),
		},
		"endpoints": map[string]string{
			"stream": h.config.StreamPath,
			"status": h.config.StatusPath,
		},
		"statistics": map[string]any{
			"total_processed":  h.totalProcessed.Load(),
			"dropped_writes":   h.droppedWrites.Load(),
			"rejected_clients": h.rejectedClients.Load(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// GetStats returns sink statistics
func (h *HTTPSink) GetStats() sink.SinkStats {
	lastProc, _ := h.lastProcessed.Load().(time.Time)
	return sink.SinkStats{
		ID:                h.id,
		Type:              "http",
		TotalProcessed:    h.totalProcessed.Load(),
		ActiveConnections: h.activeClients.Load(),
		StartTime:         h.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"host":             h.config.Host,
			"port":             h.config.Port,
			"buffer_size":      h.config.BufferSize,
			"tls":              h.tlsConfig != nil,
			"dropped_writes":   h.droppedWrites.Load(),
			"rejected_clients": h.rejectedClients.Load(),
			"endpoints": map[string]string{
				"stream": h.config.StreamPath,
				"status": h.config.StatusPath,
			},
		},
	}
}

// writeSSE frames a payload per the W3C SSE spec (multi-line safe)
func writeSSE(w http.ResponseWriter, payload []byte) error {
	for _, line := range splitLines(payload) {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "\n")
	return err
}

// splitLines splits payload by newlines, trimming a single trailing newline
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	if len(lines) == 0 {
		return [][]byte{data}
	}
	return lines
}
