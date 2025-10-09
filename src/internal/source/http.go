// FILE: logwisp/src/internal/source/http.go
package source

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/limit"
	"logwisp/src/internal/tls"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// Receives log entries via HTTP POST requests
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
	authenticator *auth.Authenticator
	authFailures  atomic.Uint64
	authSuccesses atomic.Uint64
	tlsManager    *tls.Manager

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// Creates a new HTTP server source
func NewHTTPSource(opts *config.HTTPSourceOptions, logger *log.Logger) (*HTTPSource, error) {
	// Validation done in config package
	if opts == nil {
		return nil, fmt.Errorf("HTTP source options cannot be nil")
	}

	h := &HTTPSource{
		config:    opts,
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
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
		tlsManager, err := tls.NewManager(opts.TLS, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS manager: %w", err)
		}
		h.tlsManager = tlsManager
	}

	// Initialize authenticator if configured
	if opts.Auth != nil && opts.Auth.Type != "none" && opts.Auth.Type != "" {
		// Verify TLS is enabled for auth (validation should have caught this)
		if h.tlsManager == nil {
			return nil, fmt.Errorf("authentication requires TLS to be enabled")
		}

		authenticator, err := auth.NewAuthenticator(opts.Auth, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create authenticator: %w", err)
		}
		h.authenticator = authenticator

		logger.Info("msg", "Authentication configured for HTTP source",
			"component", "http_source",
			"auth_type", opts.Auth.Type)
	}

	return h, nil
}

func (h *HTTPSource) Subscribe() <-chan core.LogEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan core.LogEntry, h.config.BufferSize)
	h.subscribers = append(h.subscribers, ch)
	return ch
}

func (h *HTTPSource) Start() error {
	h.server = &fasthttp.Server{
		Handler:            h.requestHandler,
		DisableKeepalive:   false,
		StreamRequestBody:  true,
		CloseOnShutdown:    true,
		ReadTimeout:        time.Duration(h.config.ReadTimeout) * time.Millisecond,
		WriteTimeout:       time.Duration(h.config.WriteTimeout) * time.Millisecond,
		MaxRequestBodySize: int(h.config.MaxRequestBodySize),
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
			"auth_enabled", h.authenticator != nil)

		var err error
		if h.tlsManager != nil {
			// HTTPS server
			h.server.TLSConfig = h.tlsManager.GetHTTPConfig()
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

func (h *HTTPSource) Stop() {
	h.logger.Info("msg", "Stopping HTTP source")
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

	h.logger.Info("msg", "HTTP source stopped")
}

func (h *HTTPSource) GetStats() SourceStats {
	lastEntry, _ := h.lastEntryTime.Load().(time.Time)

	var netLimitStats map[string]any
	if h.netLimiter != nil {
		netLimitStats = h.netLimiter.GetStats()
	}

	var authStats map[string]any
	if h.authenticator != nil {
		authStats = map[string]any{
			"enabled":   true,
			"type":      h.config.Auth.Type,
			"failures":  h.authFailures.Load(),
			"successes": h.authSuccesses.Load(),
		}
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
			"auth":            authStats,
			"tls":             tlsStats,
		},
	}
}

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

	// 3. Check TLS requirement for auth
	if h.authenticator != nil {
		isTLS := ctx.IsTLS() || h.tlsManager != nil
		if !isTLS {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetContentType("application/json")
			json.NewEncoder(ctx).Encode(map[string]string{
				"error": "TLS required for authentication",
				"hint":  "Use HTTPS to submit authenticated requests",
			})
			return
		}

		// Authenticate request
		authHeader := string(ctx.Request.Header.Peek("Authorization"))
		session, err := h.authenticator.AuthenticateHTTP(authHeader, remoteAddr)
		if err != nil {
			h.authFailures.Add(1)
			h.logger.Warn("msg", "Authentication failed",
				"component", "http_source",
				"remote_addr", remoteAddr,
				"error", err)

			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			if h.config.Auth.Type == "basic" && h.config.Auth.Basic != nil && h.config.Auth.Basic.Realm != "" {
				ctx.Response.Header.Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, h.config.Auth.Basic.Realm))
			}
			ctx.SetContentType("application/json")
			json.NewEncoder(ctx).Encode(map[string]string{
				"error": "Authentication failed",
			})
			return
		}

		h.authSuccesses.Add(1)
		_ = session // Session can be used for audit logging
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

	// Success response
	ctx.SetStatusCode(fasthttp.StatusAccepted)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{
		"status": "accepted",
	})
}

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

// Splits bytes into lines, handling both \n and \r\n
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