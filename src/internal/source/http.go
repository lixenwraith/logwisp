// FILE: logwisp/src/internal/source/http.go
package source

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/limit"
	"logwisp/src/internal/session"
	ltls "logwisp/src/internal/tls"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// HTTPSource receives log entries via HTTP POST requests.
type HTTPSource struct {
	config *config.HTTPSourceOptions

	// Application
	server      *fasthttp.Server
	subscribers []chan core.LogEntry
	netLimiter  *limit.NetLimiter
	logger      *log.Logger

	// Runtime
	mu   sync.RWMutex
	done chan struct{}
	wg   sync.WaitGroup

	// Security
	httpSessions   sync.Map
	sessionManager *session.Manager
	tlsManager     *ltls.ServerManager
	tlsStates      sync.Map // remoteAddr -> *tls.ConnectionState

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// NewHTTPSource creates a new HTTP server source.
func NewHTTPSource(opts *config.HTTPSourceOptions, logger *log.Logger) (*HTTPSource, error) {
	// Validation done in config package
	if opts == nil {
		return nil, fmt.Errorf("HTTP source options cannot be nil")
	}

	h := &HTTPSource{
		config:         opts,
		done:           make(chan struct{}),
		startTime:      time.Now(),
		logger:         logger,
		sessionManager: session.NewManager(core.MaxSessionTime),
	}
	h.lastEntryTime.Store(time.Time{})

	// Initialize net limiter if configured
	if opts.NetLimit != nil && (opts.NetLimit.Enabled ||
		len(opts.NetLimit.IPWhitelist) > 0 ||
		len(opts.NetLimit.IPBlacklist) > 0) {
		h.netLimiter = limit.NewNetLimiter(opts.NetLimit, logger)
	}

	// Initialize TLS manager if configured
	if opts.TLS != nil && opts.TLS.Enabled {
		tlsManager, err := ltls.NewServerManager(opts.TLS, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS manager: %w", err)
		}
		h.tlsManager = tlsManager
	}

	return h, nil
}

// Subscribe returns a channel for receiving log entries.
func (h *HTTPSource) Subscribe() <-chan core.LogEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan core.LogEntry, h.config.BufferSize)
	h.subscribers = append(h.subscribers, ch)
	return ch
}

// Start initializes and starts the HTTP server.
func (h *HTTPSource) Start() error {
	// Register expiry callback
	h.sessionManager.RegisterExpiryCallback("http_source", func(sessionID, remoteAddr string) {
		h.handleSessionExpiry(sessionID, remoteAddr)
	})

	h.server = &fasthttp.Server{
		Handler:            h.requestHandler,
		DisableKeepalive:   false,
		StreamRequestBody:  true,
		CloseOnShutdown:    true,
		ReadTimeout:        time.Duration(h.config.ReadTimeout) * time.Millisecond,
		WriteTimeout:       time.Duration(h.config.WriteTimeout) * time.Millisecond,
		MaxRequestBodySize: int(h.config.MaxRequestBodySize),
	}

	// TLS and mTLS configuration
	if h.tlsManager != nil {
		h.server.TLSConfig = h.tlsManager.GetHTTPConfig()

		// Enforce mTLS configuration from the TLSServerConfig struct.
		if h.config.TLS.ClientAuth {
			if h.config.TLS.VerifyClientCert {
				h.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			} else {
				h.server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
			}
		}
	}

	// Use configured host and port
	addr := fmt.Sprintf("%s:%d", h.config.Host, h.config.Port)

	// Start server in background
	h.wg.Add(1)
	errChan := make(chan error, 1)
	go func() {
		defer h.wg.Done()
		h.logger.Info("msg", "HTTP source server starting",
			"component", "http_source",
			"port", h.config.Port,
			"ingest_path", h.config.IngestPath,
			"tls_enabled", h.tlsManager != nil,
			"mtls_enabled", h.config.TLS != nil && h.config.TLS.ClientAuth,
		)

		var err error
		if h.tlsManager != nil {
			h.server.TLSConfig = h.tlsManager.GetHTTPConfig()

			// Add certificate verification callback
			if h.config.TLS.ClientAuth {
				h.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
				if h.config.TLS.ClientCAFile != "" {
					// ClientCAs already set by tls.Manager
				}
			}

			// HTTPS server
			err = h.server.ListenAndServeTLS(addr, h.config.TLS.CertFile, h.config.TLS.KeyFile)
		} else {
			// HTTP server
			err = h.server.ListenAndServe(addr)
		}

		if err != nil {
			h.logger.Error("msg", "HTTP source server failed",
				"component", "http_source",
				"port", h.config.Port,
				"error", err)
			errChan <- err
		}
	}()

	// Wait briefly for server startup
	select {
	case err := <-errChan:
		return fmt.Errorf("HTTP server failed to start: %w", err)
	case <-time.After(250 * time.Millisecond):
		return nil
	}
}

// Stop gracefully shuts down the HTTP server.
func (h *HTTPSource) Stop() {
	h.logger.Info("msg", "Stopping HTTP source")

	// Unregister callback
	h.sessionManager.UnregisterExpiryCallback("http_source")

	close(h.done)

	if h.server != nil {
		if err := h.server.Shutdown(); err != nil {
			h.logger.Error("msg", "Error shutting down HTTP source server",
				"component", "http_source",
				"error", err)
		}
	}

	// Shutdown net limiter
	if h.netLimiter != nil {
		h.netLimiter.Shutdown()
	}

	h.wg.Wait()

	// Close subscriber channels
	h.mu.Lock()
	for _, ch := range h.subscribers {
		close(ch)
	}
	h.mu.Unlock()

	// Stop session manager
	if h.sessionManager != nil {
		h.sessionManager.Stop()
	}

	h.logger.Info("msg", "HTTP source stopped")
}

// GetStats returns the source's statistics.
func (h *HTTPSource) GetStats() SourceStats {
	lastEntry, _ := h.lastEntryTime.Load().(time.Time)

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

	return SourceStats{
		Type:           "http",
		TotalEntries:   h.totalEntries.Load(),
		DroppedEntries: h.droppedEntries.Load(),
		StartTime:      h.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"host":            h.config.Host,
			"port":            h.config.Port,
			"path":            h.config.IngestPath,
			"invalid_entries": h.invalidEntries.Load(),
			"net_limit":       netLimitStats,
			"sessions":        sessionStats,
			"tls":             tlsStats,
		},
	}
}

// requestHandler is the main entry point for all incoming HTTP requests.
func (h *HTTPSource) requestHandler(ctx *fasthttp.RequestCtx) {
	remoteAddr := ctx.RemoteAddr().String()

	// 1. IPv6 check (early reject)
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() == nil {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetContentType("application/json")
			json.NewEncoder(ctx).Encode(map[string]string{
				"error": "IPv4-only (IPv6 not supported)",
			})
			return
		}
	}

	// 2. Net limit check (early reject)
	if h.netLimiter != nil {
		if allowed, statusCode, message := h.netLimiter.CheckHTTP(remoteAddr); !allowed {
			ctx.SetStatusCode(int(statusCode))
			ctx.SetContentType("application/json")
			json.NewEncoder(ctx).Encode(map[string]any{
				"error":       message,
				"retry_after": "60",
			})
			return
		}
	}

	// 3. Create session for connections
	var sess *session.Session
	if savedID, exists := h.httpSessions.Load(remoteAddr); exists {
		if s, found := h.sessionManager.GetSession(savedID.(string)); found {
			sess = s
			h.sessionManager.UpdateActivity(savedID.(string))
		}
	}

	if sess == nil {
		// New connection
		sess = h.sessionManager.CreateSession(remoteAddr, "http_source", map[string]any{
			"tls":          ctx.IsTLS() || h.tlsManager != nil,
			"mtls_enabled": h.config.TLS != nil && h.config.TLS.ClientAuth,
		})
		h.httpSessions.Store(remoteAddr, sess.ID)

		// Setup connection close handler
		ctx.SetConnectionClose()
		go h.cleanupHTTPSession(remoteAddr, sess.ID)
	}

	// 4. Path check
	path := string(ctx.Path())
	if path != h.config.IngestPath {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Not Found",
			"hint":  fmt.Sprintf("POST logs to %s", h.config.IngestPath),
		})
		return
	}

	// 5. Method check (only accepts POST)
	if string(ctx.Method()) != "POST" {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.SetContentType("application/json")
		ctx.Response.Header.Set("Allow", "POST")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Method not allowed",
			"hint":  "Use POST to submit logs",
		})
		return
	}

	// 6. Process log entry
	body := ctx.PostBody()
	if len(body) == 0 {
		h.invalidEntries.Add(1)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Empty request body",
		})
		return
	}

	var entry core.LogEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		h.invalidEntries.Add(1)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": fmt.Sprintf("Invalid JSON: %v", err),
		})
		return
	}

	// Set defaults
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	if entry.Source == "" {
		entry.Source = "http"
	}
	entry.RawSize = int64(len(body))

	// Publish to subscribers
	h.publish(entry)

	// Update session activity after successful processing
	h.sessionManager.UpdateActivity(sess.ID)

	// Success response
	ctx.SetStatusCode(fasthttp.StatusAccepted)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{
		"status":     "accepted",
		"session_id": sess.ID,
	})
}

// publish sends a log entry to all subscribers.
func (h *HTTPSource) publish(entry core.LogEntry) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	h.totalEntries.Add(1)
	h.lastEntryTime.Store(entry.Time)

	for _, ch := range h.subscribers {
		select {
		case ch <- entry:
		default:
			h.droppedEntries.Add(1)
			h.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
				"component", "http_source")
		}
	}
}

// handleSessionExpiry is the callback for cleaning up expired sessions.
func (h *HTTPSource) handleSessionExpiry(sessionID, remoteAddr string) {
	h.logger.Info("msg", "Removing expired HTTP session",
		"component", "http_source",
		"session_id", sessionID,
		"remote_addr", remoteAddr)

	// Remove from mapping
	h.httpSessions.Delete(remoteAddr)
}

// cleanupHTTPSession removes a session when a client connection is closed.
func (h *HTTPSource) cleanupHTTPSession(addr, sessionID string) {
	// Wait for connection to actually close
	time.Sleep(100 * time.Millisecond)

	h.httpSessions.CompareAndDelete(addr, sessionID)
	h.sessionManager.RemoveSession(sessionID)
}

// parseEntries attempts to parse a request body as a single JSON object, a JSON array, or newline-delimited JSON.
func (h *HTTPSource) parseEntries(body []byte) ([]core.LogEntry, error) {
	var entries []core.LogEntry

	// Try to parse as single JSON object first
	var single core.LogEntry
	if err := json.Unmarshal(body, &single); err == nil {
		// Validate required fields
		if single.Message == "" {
			return nil, fmt.Errorf("missing required field: message")
		}
		if single.Time.IsZero() {
			single.Time = time.Now()
		}
		if single.Source == "" {
			single.Source = "http"
		}
		single.RawSize = int64(len(body))
		entries = append(entries, single)
		return entries, nil
	}

	// Try to parse as JSON array
	var array []core.LogEntry
	if err := json.Unmarshal(body, &array); err == nil {
		// For array, divide total size by entry count as approximation
		// Accurate calculation adds too much complexity and processing
		approxSizePerEntry := int64(len(body) / len(array))
		for i, entry := range array {
			if entry.Message == "" {
				return nil, fmt.Errorf("entry %d missing required field: message", i)
			}
			if entry.Time.IsZero() {
				array[i].Time = time.Now()
			}
			if entry.Source == "" {
				array[i].Source = "http"
			}
			array[i].RawSize = approxSizePerEntry
		}
		return array, nil
	}

	// Try to parse as newline-delimited JSON
	lines := splitLines(body)
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}

		var entry core.LogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}

		if entry.Message == "" {
			return nil, fmt.Errorf("line %d missing required field: message", i+1)
		}
		if entry.Time.IsZero() {
			entry.Time = time.Now()
		}
		if entry.Source == "" {
			entry.Source = "http"
		}
		entry.RawSize = int64(len(line))

		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no valid log entries found")
	}

	return entries, nil
}

// splitLines splits a byte slice into lines, handling both \n and \r\n.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0

	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			end := i
			if i > 0 && data[i-1] == '\r' {
				end = i - 1
			}
			if end > start {
				lines = append(lines, data[start:end])
			}
			start = i + 1
		}
	}

	if start < len(data) {
		lines = append(lines, data[start:])
	}

	return lines
}