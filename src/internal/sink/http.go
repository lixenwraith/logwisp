// FILE: logwisp/src/internal/sink/http.go
package sink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	"logwisp/src/internal/network"
	"logwisp/src/internal/session"
	ltls "logwisp/src/internal/tls"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/valyala/fasthttp"
)

// HTTPSink streams log entries via Server-Sent Events (SSE).
type HTTPSink struct {
	// Configuration
	config *config.HTTPSinkOptions

	// Network
	server     *fasthttp.Server
	netLimiter *network.NetLimiter

	// Application
	input     chan core.LogEntry
	formatter format.Formatter
	logger    *log.Logger

	// Runtime
	mu        sync.RWMutex
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time

	// Broker
	clients      map[uint64]chan core.LogEntry
	clientsMu    sync.RWMutex
	unregister   chan uint64 // client unregistration channel
	nextClientID atomic.Uint64

	// Security & Session
	sessionManager *session.Manager
	clientSessions map[uint64]string // clientID -> sessionID
	sessionsMu     sync.RWMutex
	tlsManager     *ltls.ServerManager

	// Statistics
	activeClients  atomic.Int64
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewHTTPSink creates a new HTTP streaming sink.
func NewHTTPSink(opts *config.HTTPSinkOptions, logger *log.Logger, formatter format.Formatter) (*HTTPSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("HTTP sink options cannot be nil")
	}

	h := &HTTPSink{
		config:         opts,
		input:          make(chan core.LogEntry, opts.BufferSize),
		startTime:      time.Now(),
		done:           make(chan struct{}),
		logger:         logger,
		formatter:      formatter,
		clients:        make(map[uint64]chan core.LogEntry),
		unregister:     make(chan uint64),
		sessionManager: session.NewManager(30 * time.Minute),
		clientSessions: make(map[uint64]string),
	}

	h.lastProcessed.Store(time.Time{})

	// Initialize TLS manager if configured
	if opts.TLS != nil && opts.TLS.Enabled {
		tlsManager, err := ltls.NewServerManager(opts.TLS, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS manager: %w", err)
		}
		h.tlsManager = tlsManager
		logger.Info("msg", "TLS enabled",
			"component", "http_sink")
	}

	// Initialize net limiter if configured
	if opts.ACL != nil && (opts.ACL.Enabled ||
		len(opts.ACL.IPWhitelist) > 0 ||
		len(opts.ACL.IPBlacklist) > 0) {
		h.netLimiter = network.NewNetLimiter(opts.ACL, logger)
	}

	return h, nil
}

// Input returns the channel for sending log entries.
func (h *HTTPSink) Input() chan<- core.LogEntry {
	return h.input
}

// Start initializes the HTTP server and begins the broker loop.
func (h *HTTPSink) Start(ctx context.Context) error {
	// Register expiry callback
	h.sessionManager.RegisterExpiryCallback("http_sink", func(sessionID, remoteAddrStr string) {
		h.handleSessionExpiry(sessionID, remoteAddrStr)
	})

	// Start central broker goroutine
	h.wg.Add(1)
	go h.brokerLoop(ctx)

	// Create fasthttp adapter for logging
	fasthttpLogger := compat.NewFastHTTPAdapter(h.logger)

	h.server = &fasthttp.Server{
		Name:              fmt.Sprintf("LogWisp/%s", version.Short()),
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		Logger:            fasthttpLogger,
		//		ReadTimeout:       time.Duration(h.config.ReadTimeout) * time.Millisecond,
		WriteTimeout: time.Duration(h.config.WriteTimeout) * time.Millisecond,
		//		MaxRequestBodySize: int(h.config.MaxBodySize),
	}

	// Configure TLS if enabled
	if h.tlsManager != nil {
		h.server.TLSConfig = h.tlsManager.GetHTTPConfig()

		// Enforce mTLS configuration
		if h.config.TLS.ClientAuth {
			if h.config.TLS.VerifyClientCert {
				h.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			} else {
				h.server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
			}
		}

		h.logger.Info("msg", "TLS enabled for HTTP sink",
			"component", "http_sink",
			"port", h.config.Port)
	}

	// Use configured host and port
	addr := fmt.Sprintf("%s:%d", h.config.Host, h.config.Port)

	// Run server in separate goroutine to avoid blocking
	errChan := make(chan error, 1)
	go func() {
		h.logger.Info("msg", "HTTP server started",
			"component", "http_sink",
			"host", h.config.Host,
			"port", h.config.Port,
			"stream_path", h.config.StreamPath,
			"status_path", h.config.StatusPath,
			"tls_enabled", h.tlsManager != nil)

		var err error
		if h.tlsManager != nil {
			// HTTPS server
			err = h.server.ListenAndServeTLS(addr, h.config.TLS.CertFile, h.config.TLS.KeyFile)
		} else {
			// HTTP server
			err = h.server.ListenAndServe(addr)
		}

		if err != nil {
			errChan <- err
		}
	}()

	// Monitor context for shutdown signal
	go func() {
		<-ctx.Done()
		if h.server != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), core.HttpServerShutdownTimeout)
			defer cancel()
			_ = h.server.ShutdownWithContext(shutdownCtx)
		}
	}()

	// Check if server started successfully
	select {
	case err := <-errChan:
		return err
	case <-time.After(core.HttpServerStartTimeout):
		// Server started successfully
		return nil
	}
}

// Stop gracefully shuts down the HTTP server and all client connections.
func (h *HTTPSink) Stop() {
	h.logger.Info("msg", "Stopping HTTP sink")

	// Unregister callback
	h.sessionManager.UnregisterExpiryCallback("http_sink")

	// Signal all client handlers to stop
	close(h.done)

	// Shutdown HTTP server
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.server.ShutdownWithContext(ctx)
	}

	// Wait for all active client handlers to finish
	h.wg.Wait()

	// Close unregister channel after all clients have finished
	close(h.unregister)

	// Close all client channels
	h.clientsMu.Lock()
	for _, ch := range h.clients {
		close(ch)
	}
	h.clients = make(map[uint64]chan core.LogEntry)
	h.clientsMu.Unlock()

	// Stop session manager
	if h.sessionManager != nil {
		h.sessionManager.Stop()
	}

	h.logger.Info("msg", "HTTP sink stopped")
}

// GetStats returns the sink's statistics.
func (h *HTTPSink) GetStats() SinkStats {
	lastProc, _ := h.lastProcessed.Load().(time.Time)

	var netLimitStats map[string]any
	if h.netLimiter != nil {
		netLimitStats = h.netLimiter.GetStats()
	}

	var sessionStats map[string]any
	if h.sessionManager != nil {
		sessionStats = h.sessionManager.GetStats()
	}

	var tlsStats map[string]any
	if h.tlsManager != nil {
		tlsStats = h.tlsManager.GetStats()
	}

	return SinkStats{
		Type:              "http",
		TotalProcessed:    h.totalProcessed.Load(),
		ActiveConnections: h.activeClients.Load(),
		StartTime:         h.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"port":        h.config.Port,
			"buffer_size": h.config.BufferSize,
			"endpoints": map[string]string{
				"stream": h.config.StreamPath,
				"status": h.config.StatusPath,
			},
			"net_limit": netLimitStats,
			"sessions":  sessionStats,
			"tls":       tlsStats,
		},
	}
}

// GetActiveConnections returns the current number of active clients.
func (h *HTTPSink) GetActiveConnections() int64 {
	return h.activeClients.Load()
}

// GetStreamPath returns the configured transport endpoint path.
func (h *HTTPSink) GetStreamPath() string {
	return h.config.StreamPath
}

// GetStatusPath returns the configured status endpoint path.
func (h *HTTPSink) GetStatusPath() string {
	return h.config.StatusPath
}

// GetHost returns the configured host.
func (h *HTTPSink) GetHost() string {
	return h.config.Host
}

// brokerLoop manages client connections and broadcasts log entries.
func (h *HTTPSink) brokerLoop(ctx context.Context) {
	defer h.wg.Done()

	var ticker *time.Ticker
	var tickerChan <-chan time.Time

	if h.config.Heartbeat != nil && h.config.Heartbeat.Enabled {
		ticker = time.NewTicker(time.Duration(h.config.Heartbeat.IntervalMS) * time.Millisecond)
		tickerChan = ticker.C
		defer ticker.Stop()
	}

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
			// Broker owns channel cleanup
			h.clientsMu.Lock()
			if clientChan, exists := h.clients[clientID]; exists {
				delete(h.clients, clientID)
				close(clientChan)
				h.logger.Debug("msg", "Unregistered client",
					"component", "http_sink",
					"client_id", clientID)
			}
			h.clientsMu.Unlock()

			// Clean up session tracking
			h.sessionsMu.Lock()
			delete(h.clientSessions, clientID)
			h.sessionsMu.Unlock()

		case entry, ok := <-h.input:
			if !ok {
				h.logger.Debug("msg", "Input channel closed, broker stopping",
					"component", "http_sink")
				return
			}

			h.totalProcessed.Add(1)
			h.lastProcessed.Store(time.Now())

			// Broadcast to all active clients
			h.clientsMu.RLock()
			clientCount := len(h.clients)
			if clientCount > 0 {
				slowClients := 0
				var staleClients []uint64

				for id, ch := range h.clients {
					h.sessionsMu.RLock()
					sessionID, hasSession := h.clientSessions[id]
					h.sessionsMu.RUnlock()

					if hasSession {
						if !h.sessionManager.IsSessionActive(sessionID) {
							staleClients = append(staleClients, id)
							continue
						}
						select {
						case ch <- entry:
							h.sessionManager.UpdateActivity(sessionID)
						default:
							slowClients++
							if slowClients == 1 {
								h.logger.Debug("msg", "Dropped entry for slow client(s)",
									"component", "http_sink",
									"client_id", id,
									"slow_clients", slowClients,
									"total_clients", clientCount)
							}
						}
					} else {
						delete(h.clients, id)
					}
				}

				// Clean up stale clients after broadcast
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

			// If no clients connected, entry is discarded (no buffering)
			h.clientsMu.RUnlock()

		case <-tickerChan:
			// Send global heartbeat to all clients
			if h.config.Heartbeat != nil && h.config.Heartbeat.Enabled {
				heartbeatEntry := h.createHeartbeatEntry()

				h.clientsMu.RLock()
				for id, ch := range h.clients {
					h.sessionsMu.RLock()
					sessionID, hasSession := h.clientSessions[id]
					h.sessionsMu.RUnlock()

					if hasSession {
						select {
						case ch <- heartbeatEntry:
							// Update session activity on heartbeat
							h.sessionManager.UpdateActivity(sessionID)
						default:
							// Client buffer full, skip heartbeat
							h.logger.Debug("msg", "Skipped heartbeat for slow client",
								"component", "http_sink",
								"client_id", id)
						}
					}
				}
			}
		}
	}
}

// requestHandler is the main entry point for all incoming HTTP requests.
func (h *HTTPSink) requestHandler(ctx *fasthttp.RequestCtx) {
	remoteAddrStr := ctx.RemoteAddr().String()

	// Check net limit
	if h.netLimiter != nil {
		if allowed, statusCode, message := h.netLimiter.CheckHTTP(remoteAddrStr); !allowed {
			ctx.SetStatusCode(int(statusCode))
			ctx.SetContentType("application/json")
			h.logger.Warn("msg", "Net limited",
				"component", "http_sink",
				"remote_addr", remoteAddrStr,
				"status_code", statusCode,
				"error", message)
			json.NewEncoder(ctx).Encode(map[string]any{
				"error": "Too many requests",
			})
			return
		}
	}

	path := string(ctx.Path())

	// Status endpoint doesn't require auth
	if path == h.config.StatusPath {
		h.handleStatus(ctx)
		return
	}

	// Create anonymous session for all connections
	sess := h.sessionManager.CreateSession(remoteAddrStr, "http_sink", map[string]any{
		"tls": ctx.IsTLS() || h.tlsManager != nil,
	})

	switch path {
	case h.config.StreamPath:
		h.handleStream(ctx, sess)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]any{
			"error": "Not Found",
		})
	}

}

// handleStream manages a client's Server-Sent Events (SSE) stream.
func (h *HTTPSink) handleStream(ctx *fasthttp.RequestCtx, sess *session.Session) {
	remoteAddrStr := ctx.RemoteAddr().String()
	// Track connection for net limiting
	if h.netLimiter != nil {
		h.netLimiter.RegisterConnection(remoteAddrStr)
		defer h.netLimiter.ReleaseConnection(remoteAddrStr)
	}

	// Set SSE headers
	ctx.Response.Header.Set("Content-Type", "text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")

	// Register new client with broker
	clientID := h.nextClientID.Add(1)
	clientChan := make(chan core.LogEntry, h.config.BufferSize)

	h.clientsMu.Lock()
	h.clients[clientID] = clientChan
	h.clientsMu.Unlock()

	// Register session mapping
	h.sessionsMu.Lock()
	h.clientSessions[clientID] = sess.ID
	h.sessionsMu.Unlock()

	// Define the stream writer function
	streamFunc := func(w *bufio.Writer) {
		connectCount := h.activeClients.Add(1)
		h.logger.Debug("msg", "HTTP client connected",
			"component", "http_sink",
			"remote_addr", remoteAddrStr,
			"session_id", sess.ID,
			"client_id", clientID,
			"active_clients", connectCount)

		// Track goroutine lifecycle with waitgroup
		h.wg.Add(1)

		// Cleanup signals unregister
		defer func() {
			disconnectCount := h.activeClients.Add(-1)
			h.logger.Debug("msg", "HTTP client disconnected",
				"component", "http_sink",
				"remote_addr", remoteAddrStr,
				"session_id", sess.ID,
				"client_id", clientID,
				"active_clients", disconnectCount)

			// Signal broker to cleanup this client's channel
			select {
			case h.unregister <- clientID:
			case <-h.done:
				// Shutting down, don't block
			}

			// Remove session
			h.sessionManager.RemoveSession(sess.ID)

			h.wg.Done()
		}()

		// Send initial connected event with metadata
		connectionInfo := map[string]any{
			"client_id":   fmt.Sprintf("%d", clientID),
			"session_id":  sess.ID,
			"stream_path": h.config.StreamPath,
			"status_path": h.config.StatusPath,
			"buffer_size": h.config.BufferSize,
			"tls":         h.tlsManager != nil,
		}
		data, _ := json.Marshal(connectionInfo)
		fmt.Fprintf(w, "event: connected\ndata: %s\n\n", data)
		if err := w.Flush(); err != nil {
			return
		}

		// Setup heartbeat ticker if enabled
		var ticker *time.Ticker
		var tickerChan <-chan time.Time

		if h.config.Heartbeat != nil && h.config.Heartbeat.Enabled {
			ticker = time.NewTicker(time.Duration(h.config.Heartbeat.IntervalMS) * time.Millisecond)
			tickerChan = ticker.C
			defer ticker.Stop()
		}

		// Main streaming loop
		for {
			select {
			case entry, ok := <-clientChan:
				if !ok {
					// Channel closed, client being removed
					return
				}

				if err := h.formatEntryForSSE(w, entry); err != nil {
					h.logger.Error("msg", "Failed to format log entry",
						"component", "http_sink",
						"client_id", clientID,
						"error", err,
						"entry_source", entry.Source)
					continue
				}

				if err := w.Flush(); err != nil {
					// Client disconnected
					return
				}

				// Update session activity
				h.sessionManager.UpdateActivity(sess.ID)

			case <-tickerChan:
				// Client-specific heartbeat
				sessionHB := map[string]any{
					"type":       "heartbeat",
					"client_id":  fmt.Sprintf("%d", clientID),
					"session_id": sess.ID,
				}
				hbData, _ := json.Marshal(sessionHB)
				fmt.Fprintf(w, "event: heartbeat\ndata: %s\n\n", hbData)

				if err := w.Flush(); err != nil {
					return
				}

			case <-h.done:
				// Send final disconnect event
				fmt.Fprintf(w, "event: disconnect\ndata: {\"reason\":\"server_shutdown\"}\n\n")
				w.Flush()
				return
			}
		}
	}

	ctx.SetBodyStreamWriter(streamFunc)
}

// handleStatus provides a JSON status report of the sink.
func (h *HTTPSink) handleStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	var netLimitStats any
	if h.netLimiter != nil {
		netLimitStats = h.netLimiter.GetStats()
	} else {
		netLimitStats = map[string]any{
			"enabled": false,
		}
	}

	var tlsStats any
	if h.tlsManager != nil {
		tlsStats = h.tlsManager.GetStats()
	} else {
		tlsStats = map[string]any{
			"enabled": false,
		}
	}

	var sessionStats any
	if h.sessionManager != nil {
		sessionStats = h.sessionManager.GetStats()
	}

	status := map[string]any{
		"service": "LogWisp",
		"version": version.Short(),
		"server": map[string]any{
			"type":           "http",
			"port":           h.config.Port,
			"active_clients": h.activeClients.Load(),
			"buffer_size":    h.config.BufferSize,
			"uptime_seconds": int(time.Since(h.startTime).Seconds()),
		},
		"endpoints": map[string]string{
			"transport": h.config.StreamPath,
			"status":    h.config.StatusPath,
		},
		"features": map[string]any{
			"heartbeat": map[string]any{
				"enabled":     h.config.Heartbeat.Enabled,
				"interval_ms": h.config.Heartbeat.IntervalMS,
				"format":      h.config.Heartbeat.Format,
			},
			"tls":       tlsStats,
			"sessions":  sessionStats,
			"net_limit": netLimitStats,
		},
		"statistics": map[string]any{
			"total_processed": h.totalProcessed.Load(),
		},
	}

	data, _ := json.Marshal(status)
	ctx.SetBody(data)
}

// handleSessionExpiry is the callback for cleaning up expired sessions.
func (h *HTTPSink) handleSessionExpiry(sessionID, remoteAddrStr string) {
	h.sessionsMu.RLock()
	defer h.sessionsMu.RUnlock()

	// Find client by session ID
	for clientID, sessID := range h.clientSessions {
		if sessID == sessionID {
			h.logger.Info("msg", "Closing expired session client",
				"component", "http_sink",
				"session_id", sessionID,
				"client_id", clientID,
				"remote_addr", remoteAddrStr)

			// Signal broker to unregister
			select {
			case h.unregister <- clientID:
			case <-h.done:
			}
			return
		}
	}
}

// createHeartbeatEntry generates a new heartbeat log entry.
func (h *HTTPSink) createHeartbeatEntry() core.LogEntry {
	message := "heartbeat"

	// Build fields for heartbeat metadata
	fields := make(map[string]any)
	fields["type"] = "heartbeat"

	if h.config.Heartbeat.Enabled {
		fields["active_clients"] = h.activeClients.Load()
		fields["uptime_seconds"] = int(time.Since(h.startTime).Seconds())
	}

	fieldsJSON, _ := json.Marshal(fields)

	return core.LogEntry{
		Time:    time.Now(),
		Source:  "logwisp-http",
		Level:   "INFO",
		Message: message,
		Fields:  fieldsJSON,
	}
}

// formatEntryForSSE formats a log entry into the SSE 'data:' format.
func (h *HTTPSink) formatEntryForSSE(w *bufio.Writer, entry core.LogEntry) error {
	formatted, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}

	// Multi-line content handler
	lines := bytes.Split(formatted, []byte{'\n'})
	for _, line := range lines {
		// SSE needs "data: " prefix for each line based on W3C spec
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprintf(w, "\n") // Empty line to terminate event

	return nil
}