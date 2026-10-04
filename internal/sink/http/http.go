package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/tlsx"
	"github.com/lixenwraith/logwisp/internal/version"

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
)

// HTTPSink streams log entries via Server-Sent Events
// Server.WriteTimeout is deliberately unset (it would terminate long-lived SSE streams)
// per-write deadlines are applied via http.ResponseController
type HTTPSink struct {
	// Plugin identity and session management
	id    string
	proxy *session.Proxy

	// Configuration
	config  *config.HTTPSinkOptions
	addr    string
	network string

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
	keepalive    time.Duration

	// TLS
	tlsConfig *tls.Config

	// Authorization
	auth *authz.Policy
	web  map[string]http.Handler // GET paths of the browser files and the root

	// Runtime. Stop closes flush; the broker then moves what remains of its
	// input to tail and closes flushed; each stream writes its queue, tail
	// and the disconnect event on its own, until flushBy.
	done      chan struct{}
	flush     chan struct{}
	flushed   chan struct{}
	flushBy   time.Time
	tail      [][]byte // read only once flushed is closed
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
	if err := config.Scan(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	network, err := core.Network(opts.Host)
	if err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if opts.StreamPath == "" {
		opts.StreamPath = DefaultHTTPStreamPath
	}
	if opts.StatusPath == "" {
		opts.StatusPath = DefaultHTTPStatusPath
	}
	for _, o := range []struct{ name, p string }{{"stream_path", opts.StreamPath}, {"status_path", opts.StatusPath}} {
		if !routable(o.p) {
			return nil, fmt.Errorf("%s %q: must start with '/', hold no '//', '.' or '..' segment, and none of '{', '}', '%%', '?', '#'", o.name, o.p)
		}
		if p := o.p; p == chain.AuthPath || strings.HasPrefix(p, chain.AuthPath+"/") {
			return nil, fmt.Errorf("%s and the paths under it are reserved for authentication", chain.AuthPath)
		}
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
	tlsCfg, err := tlsx.Server(opts.TLS, opts.Host)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, tlsCfg, authz.RoleListener, authz.HTTP)
	if err != nil {
		return nil, err
	}
	switch {
	case (opts.LoginPage || opts.ViewerPage) && !authPolicy.BehindProxy():
		return nil, errors.New("login_page and viewer_page apply to scram behind auth.trusted_proxies, where browsers log in; without auth or under mtls the viewer is always served")
	case opts.ViewerPage && !opts.LoginPage:
		return nil, errors.New("viewer_page needs login_page, where it sends a signed-out viewer")
	}
	web, err := webHandlers(opts, authPolicy)
	if err != nil {
		return nil, err
	}

	h := &HTTPSink{
		id:           id,
		proxy:        proxy,
		config:       opts,
		addr:         net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10)),
		network:      network,
		input:        make(chan core.TransportEvent, opts.BufferSize),
		done:         make(chan struct{}),
		flush:        make(chan struct{}),
		flushed:      make(chan struct{}),
		logger:       logger,
		clients:      make(map[uint64]*sseClient),
		writeTimeout: time.Duration(opts.WriteTimeoutMS) * time.Millisecond,
		keepalive:    core.StreamKeepaliveInterval,
		tlsConfig:    tlsCfg,
		auth:         authPolicy,
		web:          web,
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
		"mtls", tlsCfg != nil && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert,
		"auth", authPolicy.Describe(),
		"login_page", opts.LoginPage,
		"viewer_page", web[chain.AuthPath+"/view"] != nil)
	tlsx.LogWarnings(logger, "http_sink", id, opts.TLS, true)
	authPolicy.LogStartup(logger, "http_sink", id, false)
	return h, nil
}

// Capabilities returns supported capabilities
func (h *HTTPSink) Capabilities() []core.Capability {
	caps := []core.Capability{core.CapSessionAware, core.CapMultiSession}
	if h.tlsConfig != nil {
		caps = append(caps, core.CapTLS)
	}
	if h.auth.BehindProxy() {
		caps = append(caps, core.CapProxyTLS)
	}
	if h.auth.Enabled() {
		caps = append(caps, core.CapAuth) // authorizes clients, not just the CA
	}
	return caps
}

// Input returns the channel for sending transport events
func (h *HTTPSink) Input() chan<- core.TransportEvent {
	return h.input
}

// Start binds the listener and serves stream/status endpoints
func (h *HTTPSink) Start(ctx context.Context) error {
	// TLS is applied via server.TLSConfig + ServeTLS below, not by wrapping
	// ln; net/http then owns handshake, ALPN (h2), and per-conn errors.
	ln, err := core.Listen(ctx, &net.ListenConfig{}, h.network, h.addr)
	if err != nil {
		return fmt.Errorf("http sink bind %s: %w", h.addr, err)
	}
	return h.serve(ctx, ln)
}

// serve owns an already-bound listener, allowing tests to reserve an ephemeral
// port and exercise the same routing and worker lifecycle as Start.
func (h *HTTPSink) serve(ctx context.Context, ln net.Listener) error {
	if err := h.auth.Start(); err != nil {
		ln.Close()
		return err
	}
	mux := http.NewServeMux()
	// Method-scoped patterns: mux answers 405 with Allow header on non-GET
	mux.HandleFunc(http.MethodGet+" "+exact(h.config.StreamPath), h.handleStream)
	mux.HandleFunc(http.MethodGet+" "+exact(h.config.StatusPath), h.handleStatus)
	// A GET pattern also serves HEAD, and a HEAD stream is a registered client
	// whose body writes are discarded: it never reads, so nothing but the peer
	// closing the connection ends it. The status path answers one either way.
	mux.HandleFunc(http.MethodHead+" "+exact(h.config.StreamPath), streamHeadNotAllowed)

	// One wrapper covers stream and status, and keeps the handlers themselves
	// unaware of authorization; a nil policy admits every request. Login, the
	// browser files and the root sit outside it; in proxy mode everything sits
	// behind the proxy gate.
	outer := http.NewServeMux()
	outer.HandleFunc(http.MethodPost+" "+chain.AuthPath, h.handleAuth)
	for p, file := range h.web {
		outer.Handle(http.MethodGet+" "+p, file)
	}
	outer.Handle("/", h.authMiddleware(mux))
	var handler http.Handler = outer
	if h.auth.BehindProxy() {
		handler = h.proxyGate(outer)
	}

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
	go h.brokerLoop()

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
	h.auth.Close()

	h.logger.Info("msg", " HTTP sink stopped",
		"component", "http_sink",
		"instance_id", h.id,
		"total_processed", h.totalProcessed.Load())
}

// shutdown funnels ctx-cancel and Stop() teardown through a single path.
// Server.Shutdown refuses new streams and waits for the open ones, which end
// once they wrote what is queued, within sink.FlushBound; Server.Close cuts a
// stream stalled past it.
func (h *HTTPSink) shutdown() {
	h.stopOnce.Do(func() {
		if h.server != nil {
			h.flushBy = time.Now().Add(sink.FlushBound(h.writeTimeout))
			ctx, cancel := context.WithDeadline(context.Background(), h.flushBy)
			defer cancel()
			close(h.flush)
			if err := h.server.Shutdown(ctx); err != nil {
				h.server.Close()
			}
		}
		close(h.done)
	})
}

// removeClient unregisters a client; the first caller closes the send channel.
// Broker (stale-session eviction) and stream handler (disconnect) may race here
// safely. The session is the handler's, released when it returns.
func (h *HTTPSink) removeClient(id uint64) {
	h.clientsMu.Lock()
	c, ok := h.clients[id]
	if ok {
		delete(h.clients, id)
	}
	h.clientsMu.Unlock()
	if ok {
		close(c.send)
	}
}

// brokerLoop fans out transport events to all client queues, non-blocking,
// and evicts clients whose sessions were idle-expired by the session manager,
// until flush, which shutdown closes on Stop and on context cancellation.
func (h *HTTPSink) brokerLoop() {
	defer h.wg.Done()
	for {
		select {
		case <-h.flush: // first: a select with both ready picks at random
			h.flushInput()
			return
		default:
		}
		select {
		case <-h.flush:
			h.flushInput()
			return
		case event := <-h.input:
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

// flushInput moves what remains of the input to tail for the streams
func (h *HTTPSink) flushInput() {
	h.tail = sink.Drain(h.input)
	h.totalProcessed.Add(uint64(len(h.tail)))
	close(h.flushed)
}

// handleStream serves one client's SSE stream
func (h *HTTPSink) handleStream(w http.ResponseWriter, r *http.Request) {
	if h.config.MaxConnections > 0 && h.activeClients.Load() >= h.config.MaxConnections {
		h.rejectedClients.Add(1)
		http.Error(w, "too many clients", http.StatusServiceUnavailable)
		return
	}

	rc := http.NewResponseController(w)
	remote := clientAddr(r)

	meta := map[string]any{
		"type": "http_client",
	}
	if r.TLS != nil {
		meta["tls"] = true
		if cn := tlsx.PeerCN(*r.TLS); cn != "" {
			meta["tls_peer_cn"] = cn
		}
	}
	// Set by authMiddleware; absent when auth is disabled
	ident, _ := r.Context().Value(identityKey{}).(authz.Identity)
	ident.Apply(meta)
	sess := h.proxy.CreateSession(remote, meta)

	c := &sseClient{
		send:      make(chan []byte, h.config.ClientBufferSize),
		sessionID: sess.ID,
	}
	id := h.nextClientID.Add(1)

	count := h.activeClients.Add(1)
	h.logger.Debug("msg", "HTTP client connected",
		"component", "http_sink",
		"remote_addr", remote,
		"session_id", sess.ID,
		"client_id", id,
		"auth_identity", ident.Name,
		"active_clients", count)

	defer func() {
		h.removeClient(id)
		h.proxy.RemoveSession(sess.ID)
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
	if !h.auth.Enabled() {
		// An authenticated stream is not offered to every web origin
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
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
	h.armWrite(rc)
	fmt.Fprintf(w, "event: connected\ndata: %s\n\n", info)
	if err := rc.Flush(); err != nil {
		return
	}

	// Registered only now: a client the broker can queue into before its reader
	// reaches the loop below loses a burst to a buffer nobody is draining.
	h.clientsMu.Lock()
	h.clients[id] = c
	h.clientsMu.Unlock()

	// A stream with nothing to carry still has to prove the peer is there. The
	// comment refreshes the session the broker evicts on, and fails on a peer
	// that stopped reading.
	idle := time.NewTicker(h.keepalive)
	defer idle.Stop()

	send := func(payload []byte) bool {
		if writeSSE(w, payload) != nil || rc.Flush() != nil {
			return false
		}
		h.proxy.UpdateActivity(sess.ID)
		return true
	}
	clientGone := r.Context().Done()
	for {
		select {
		case payload, ok := <-c.send:
			if !ok {
				return // broker evicted (stale session)
			}
			h.armWrite(rc)
			if !send(payload) {
				return
			}
		case <-idle.C:
			h.armWrite(rc)
			if _, err := fmt.Fprint(w, ":\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			h.proxy.UpdateActivity(sess.ID)
		case <-clientGone:
			return
		case <-h.flushed:
			// Nothing more will be queued: write the queue and the tail, then
			// say why the stream ends
			_ = rc.SetWriteDeadline(h.flushBy)
			for len(c.send) > 0 {
				if payload, ok := <-c.send; !ok || !send(payload) {
					return
				}
			}
			for _, payload := range h.tail {
				if !send(payload) {
					return
				}
			}
			fmt.Fprintf(w, "event: disconnect\ndata: {\"reason\":\"server_shutdown\"}\n\n")
			rc.Flush()
			return
		}
	}
}

// armWrite bounds the next response write. Without it an SSE write is unbounded
// and a peer that stops reading wedges its handler for as long as it stays open.
func (h *HTTPSink) armWrite(rc *http.ResponseController) {
	if h.writeTimeout > 0 {
		_ = rc.SetWriteDeadline(time.Now().Add(h.writeTimeout))
	}
}

// handleStatus provides a JSON status report
func (h *HTTPSink) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"service":     "LogWisp",
		"version":     version.Short(),
		"instance_id": h.id,
		"server": map[string]any{
			"type":               "http",
			"host":               h.config.Host,
			"port":               h.config.Port,
			"tls":                h.tlsConfig != nil,
			"auth":               h.auth.Describe(),
			"active_clients":     h.activeClients.Load(),
			"buffer_size":        h.config.BufferSize,
			"client_buffer_size": h.config.ClientBufferSize,
			"max_connections":    h.config.MaxConnections,
			"write_timeout_ms":   h.config.WriteTimeoutMS,
			"uptime_seconds":     int(time.Since(h.startTime).Seconds()),
		},
		"endpoints": map[string]string{
			"stream": h.config.StreamPath,
			"status": h.config.StatusPath,
		},
		"statistics": map[string]any{
			"total_processed":  h.totalProcessed.Load(),
			"dropped_writes":   h.droppedWrites.Load(),
			"rejected_clients": h.rejectedClients.Load(),
			"auth_rejected":    h.auth.Rejected(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// GetStats returns sink statistics
func (h *HTTPSink) GetStats() sink.SinkStats {
	lastProc, _ := h.lastProcessed.Load().(time.Time)
	details := map[string]any{
		"host":               h.config.Host,
		"port":               h.config.Port,
		"buffer_size":        h.config.BufferSize,
		"client_buffer_size": h.config.ClientBufferSize,
		"max_connections":    h.config.MaxConnections,
		"write_timeout_ms":   h.config.WriteTimeoutMS,
		"tls":                h.tlsConfig != nil,
		"dropped_writes":     h.droppedWrites.Load(),
		"rejected_clients":   h.rejectedClients.Load(),
		"endpoints": map[string]string{
			"stream": h.config.StreamPath,
			"status": h.config.StatusPath,
		},
	}
	maps.Copy(details, h.auth.Stats())

	return sink.SinkStats{
		ID:                h.id,
		Type:              "http",
		TotalProcessed:    h.totalProcessed.Load(),
		ActiveConnections: h.activeClients.Load(),
		StartTime:         h.startTime,
		LastProcessed:     lastProc,
		Details:           details,
	}
}

// identityKey carries the authorized identity from the middleware to the
// handlers; absent when auth is disabled
type identityKey struct{}

// authMiddleware gates every endpoint on the policy: a client certificate
// or a bearer token. The rejection carries no detail: the status endpoint
// already exposes host, port, and throughput counters, so a refusal should
// not add the shape of the policy on top of that.
func (h *HTTPSink) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident, status, err := h.auth.AuthorizeRequest(r)
		if err != nil {
			h.logger.Warn("msg", "Request rejected by auth policy",
				"component", "http_sink",
				"instance_id", h.id,
				"remote_addr", clientAddr(r),
				"path", r.URL.Path,
				"error", err)
			authz.Refuse(w, status)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, ident)))
	})
}

// handleAuth runs one step of a SCRAM login and logs its outcome
func (h *HTTPSink) handleAuth(w http.ResponseWriter, r *http.Request) {
	ident, err := h.auth.ServeAuth(w, r)
	switch {
	case err != nil:
		h.logger.Warn("msg", "Login rejected",
			"component", "http_sink",
			"instance_id", h.id,
			"remote_addr", clientAddr(r),
			"error", err)
	case ident.Name != "":
		h.logger.Info("msg", "Login accepted",
			"component", "http_sink",
			"instance_id", h.id,
			"remote_addr", clientAddr(r),
			"auth_identity", ident.Name)
	}
}

// routable reports a path ServeMux and a URL take literally: clean, a trailing
// '/' aside, without the braces of wildcards, an escape, a query or a fragment
func routable(p string) bool {
	c := path.Clean(p)
	return strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "{}%?#") && (c == p || c != "/" && c+"/" == p)
}

// exact keeps a path ending in '/' from matching every path beneath it
func exact(p string) string {
	if strings.HasSuffix(p, "/") {
		return p + "{$}"
	}
	return p
}

// streamHeadNotAllowed refuses a body-less read of a stream that is only a body
func streamHeadNotAllowed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// writeSSE frames a payload per the W3C SSE spec, one data: line per line
func writeSSE(w http.ResponseWriter, payload []byte) error {
	for _, line := range splitLines(payload) {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "\n")
	return err
}

// splitLines splits on every break SSE recognises (CRLF, LF and a lone CR),
// so no payload byte can end a data: line and start an event: or retry:
// field. One trailing break is dropped.
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	if bytes.HasSuffix(data, []byte("\r\n")) {
		data = data[:len(data)-2]
	} else if data[len(data)-1] == '\n' || data[len(data)-1] == '\r' {
		data = data[:len(data)-1]
	}
	var lines [][]byte
	for {
		i := bytes.IndexAny(data, "\r\n")
		if i < 0 {
			return append(lines, data)
		}
		lines = append(lines, data[:i])
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			i++
		}
		data = data[i+1:]
	}
}
