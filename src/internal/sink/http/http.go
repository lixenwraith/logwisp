package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/plugin"
	"logwisp/src/internal/session"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/version"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/valyala/fasthttp"
)

func init() {
	if err := plugin.RegisterSink("http", NewHTTPSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register http sink: %v", err))
	}
}

// HTTPSink streams log entries via Server-Sent Events (SSE)
type HTTPSink struct {
	// Plugin identity and session management
	id    string
	proxy *session.Proxy

	// Configuration
	config *config.HTTPSinkOptions

	// Network
	server *fasthttp.Server

	// Application
	input  chan core.TransportEvent
	logger *log.Logger

	// Runtime
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time

	// Broker
	clients      map[uint64]chan []byte
	clientsMu    sync.RWMutex
	unregister   chan uint64
	nextClientID atomic.Uint64

	// Client session tracking
	clientSessions map[uint64]string // clientID -> sessionID
	sessionsMu     sync.RWMutex

	// Statistics
	activeClients  atomic.Int64
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

const (
	// Server lifecycle
	HttpServerStartTimeout    = 100 * time.Millisecond
	HttpServerShutdownTimeout = 2 * time.Second

	// Defaults
	DefaultHTTPHost       = "0.0.0.0"
	DefaultHTTPBufferSize = 1000
	DefaultHTTPStreamPath = "/stream"
	DefaultHTTPStatusPath = "/status"
	HTTPMaxPort           = 65535
)

// NewHTTPSinkPlugin creates an HTTP sink through plugin factory
func NewHTTPSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.HTTPSinkOptions{
		Host:         DefaultHTTPHost,
		Port:         0,
		WriteTimeout: 0, // SSE indefinite streaming
	}

	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	if opts.Port <= 0 || opts.Port > HTTPMaxPort {
		return nil, fmt.Errorf("port must be between 1 and %d", HTTPMaxPort)
	}

	// Defaults
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultHTTPBufferSize
	}
	if opts.StreamPath == "" {
		opts.StreamPath = DefaultHTTPStreamPath
	}
	if opts.StatusPath == "" {
		opts.StatusPath = DefaultHTTPStatusPath
	}

	h := &HTTPSink{
		id:             id,
		proxy:          proxy,
		config:         opts,
		input:          make(chan core.TransportEvent, opts.BufferSize),
		done:           make(chan struct{}),
		logger:         logger,
		clients:        make(map[uint64]chan []byte),
		unregister:     make(chan uint64),
		clientSessions: make(map[uint64]string),
	}
	h.lastProcessed.Store(time.Time{})

	logger.Info("msg", "HTTP sink initialized",
		"component", "http_sink",
		"instance_id", id,
		"host", opts.Host,
		"port", opts.Port,
		"stream_path", opts.StreamPath,
		"status_path", opts.StatusPath)

	return h, nil
}

// Capabilities returns supported capabilities
func (h *HTTPSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
		core.CapMultiSession,
	}
}

// Input returns the channel for sending transport events
func (h *HTTPSink) Input() chan<- core.TransportEvent {
	return h.input
}

// Start initializes the HTTP server and begins the broker loop
func (h *HTTPSink) Start(ctx context.Context) error {
	h.startTime = time.Now()

	// Start central broker goroutine
	h.wg.Add(1)
	go h.brokerLoop(ctx)

	fasthttpLogger := compat.NewFastHTTPAdapter(h.logger)

	h.server = &fasthttp.Server{
		Name:              fmt.Sprintf("LogWisp/%s", version.Short()),
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		Logger:            fasthttpLogger,
		WriteTimeout:      time.Duration(h.config.WriteTimeout) * time.Millisecond,
	}

	addr := fmt.Sprintf("%s:%d", h.config.Host, h.config.Port)

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("http sink bind %s: %w", addr, err)
	}
	go func() {
		if err := h.server.Serve(ln); err != nil {
			h.logger.Error("msg", "HTTP server terminated",
				"component", "http_sink",
				"instance_id", h.id,
				"error", err)
		}
	}()

	// Monitor context for shutdown
	go func() {
		<-ctx.Done()
		if h.server != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), HttpServerShutdownTimeout)
			defer cancel()
			h.server.ShutdownWithContext(shutdownCtx)
		}
	}()

	h.logger.Info("msg", "HTTP server started",
		"component", "http_sink",
		"instance_id", h.id,
		"host", h.config.Host,
		"port", h.config.Port)
	return nil
}

// Stop gracefully shuts down the HTTP server and all client connections
func (h *HTTPSink) Stop() {
	h.logger.Info("msg", "Stopping HTTP sink",
		"component", "http_sink",
		"instance_id", h.id)

	close(h.done)

	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), HttpServerShutdownTimeout)
		defer cancel()
		h.server.ShutdownWithContext(ctx)
	}

	h.wg.Wait()

	close(h.unregister)

	h.clientsMu.Lock()
	for _, ch := range h.clients {
		close(ch)
	}
	h.clients = make(map[uint64]chan []byte)
	h.clientsMu.Unlock()

	h.logger.Info("msg", "HTTP sink stopped",
		"component", "http_sink",
		"instance_id", h.id,
		"total_processed", h.totalProcessed.Load())
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
			"host":        h.config.Host,
			"port":        h.config.Port,
			"buffer_size": h.config.BufferSize,
			"endpoints": map[string]string{
				"stream": h.config.StreamPath,
				"status": h.config.StatusPath,
			},
		},
	}
}

// brokerLoop manages client connections and broadcasts transport events
func (h *HTTPSink) brokerLoop(ctx context.Context) {
	defer h.wg.Done()

	for {
		select {
		case <-ctx.Done():
			h.logger.Debug("msg", "Broker loop stopping due to context cancellation",
				"component", "http_sink")
			return

		case <-h.done:
			h.logger.Debug("msg", "Broker loop stopping due to shutdown signal",
				"component", "http_sink")
			return

		case clientID := <-h.unregister:
			h.clientsMu.Lock()
			if clientChan, exists := h.clients[clientID]; exists {
				delete(h.clients, clientID)
				close(clientChan)
				h.logger.Debug("msg", "Unregistered client",
					"component", "http_sink",
					"client_id", clientID)
			}
			h.clientsMu.Unlock()

			h.sessionsMu.Lock()
			delete(h.clientSessions, clientID)
			h.sessionsMu.Unlock()

		case event, ok := <-h.input:
			if !ok {
				h.logger.Debug("msg", "Input channel closed, broker stopping",
					"component", "http_sink")
				return
			}

			h.totalProcessed.Add(1)
			h.lastProcessed.Store(time.Now())

			h.clientsMu.RLock()
			clientCount := len(h.clients)
			if clientCount > 0 {
				var staleClients []uint64

				for id, ch := range h.clients {
					h.sessionsMu.RLock()
					sessionID, hasSession := h.clientSessions[id]
					h.sessionsMu.RUnlock()

					if !hasSession {
						staleClients = append(staleClients, id)
						continue
					}

					// Check session still exists via proxy
					if _, exists := h.proxy.GetSession(sessionID); !exists {
						staleClients = append(staleClients, id)
						continue
					}

					select {
					case ch <- event.Payload:
						h.proxy.UpdateActivity(sessionID)
					default:
						h.logger.Debug("msg", "Dropped event for slow client",
							"component", "http_sink",
							"client_id", id)
					}
				}

				if len(staleClients) > 0 {
					go func() {
						for _, clientID := range staleClients {
							select {
							case h.unregister <- clientID:
							case <-h.done:
								return
							}
						}
					}()
				}
			}
			h.clientsMu.RUnlock()
		}
	}
}

// requestHandler is the main entry point for all incoming HTTP requests
func (h *HTTPSink) requestHandler(ctx *fasthttp.RequestCtx) {
	// IPv4-only enforcement - silent drop IPv6
	remoteAddr := ctx.RemoteAddr()
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		if tcpAddr.IP.To4() == nil {
			h.logger.Debug("msg", "IPv6 connection rejected",
				"component", "http_sink", "remote_addr", remoteAddr.String())
			ctx.SetConnectionClose()
			return
		}
	}

	path := string(ctx.Path())

	switch path {
	case h.config.StatusPath:
		h.handleStatus(ctx)
	case h.config.StreamPath:
		h.handleStream(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]any{
			"error": "Not Found",
		})
	}
}

// handleStream manages a client's Server-Sent Events (SSE) stream
func (h *HTTPSink) handleStream(ctx *fasthttp.RequestCtx) {
	remoteAddrStr := ctx.RemoteAddr().String()

	// Create session via proxy
	sess := h.proxy.CreateSession(remoteAddrStr, map[string]any{
		"type": "http_client",
	})

	// Set SSE headers
	ctx.Response.Header.Set("Content-Type", "text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")

	// Register client with broker
	clientID := h.nextClientID.Add(1)
	clientChan := make(chan []byte, h.config.BufferSize)

	h.clientsMu.Lock()
	h.clients[clientID] = clientChan
	h.clientsMu.Unlock()

	h.sessionsMu.Lock()
	h.clientSessions[clientID] = sess.ID
	h.sessionsMu.Unlock()

	streamFunc := func(w *bufio.Writer) {
		connectCount := h.activeClients.Add(1)
		h.logger.Debug("msg", "HTTP client connected",
			"component", "http_sink",
			"remote_addr", remoteAddrStr,
			"session_id", sess.ID,
			"client_id", clientID,
			"active_clients", connectCount)

		defer func() {
			disconnectCount := h.activeClients.Add(-1)
			h.logger.Debug("msg", "HTTP client disconnected",
				"component", "http_sink",
				"remote_addr", remoteAddrStr,
				"session_id", sess.ID,
				"client_id", clientID,
				"active_clients", disconnectCount)

			select {
			case h.unregister <- clientID:
			case <-h.done:
			}

			h.proxy.RemoveSession(sess.ID)
		}()

		// Send connected event with metadata
		connectionInfo := map[string]any{
			"client_id":   fmt.Sprintf("%d", clientID),
			"session_id":  sess.ID,
			"instance_id": h.id,
			"stream_path": h.config.StreamPath,
			"status_path": h.config.StatusPath,
			"buffer_size": h.config.BufferSize,
		}
		data, _ := json.Marshal(connectionInfo)
		fmt.Fprintf(w, "event: connected\ndata: %s\n\n", data)
		if err := w.Flush(); err != nil {
			return
		}

		for {
			select {
			case payload, ok := <-clientChan:
				if !ok {
					return
				}

				if err := h.writeSSE(w, payload); err != nil {
					return
				}

				if err := w.Flush(); err != nil {
					return
				}

				h.proxy.UpdateActivity(sess.ID)

			case <-h.done:
				fmt.Fprintf(w, "event: disconnect\ndata: {\"reason\":\"server_shutdown\"}\n\n")
				w.Flush()
				return
			}
		}
	}

	ctx.SetBodyStreamWriter(streamFunc)
}

// handleStatus provides a JSON status report
func (h *HTTPSink) handleStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	status := map[string]any{
		"service":     "LogWisp",
		"version":     version.Short(),
		"instance_id": h.id,
		"server": map[string]any{
			"type":           "http",
			"host":           h.config.Host,
			"port":           h.config.Port,
			"active_clients": h.activeClients.Load(),
			"buffer_size":    h.config.BufferSize,
			"uptime_seconds": int(time.Since(h.startTime).Seconds()),
		},
		"endpoints": map[string]string{
			"stream": h.config.StreamPath,
			"status": h.config.StatusPath,
		},
		"statistics": map[string]any{
			"total_processed": h.totalProcessed.Load(),
		},
	}

	data, _ := json.Marshal(status)
	ctx.SetBody(data)
}

// writeSSE formats payload into SSE data format
func (h *HTTPSink) writeSSE(w *bufio.Writer, payload []byte) error {
	// Handle multi-line payloads per W3C SSE spec
	lines := splitLines(payload)
	for _, line := range lines {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	// Empty line terminates event
	if _, err := w.WriteString("\n"); err != nil {
		return err
	}
	return nil
}

// splitLines splits payload by newlines, handling different line endings
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}

	// Trim trailing newline if present
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
