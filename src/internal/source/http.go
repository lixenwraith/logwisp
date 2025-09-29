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
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// Receives log entries via HTTP POST requests
type HTTPSource struct {
	// Config
	host               string
	port               int64
	path               string
	bufferSize         int64
	maxRequestBodySize int64

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
	authConfig    *config.AuthConfig
	authFailures  atomic.Uint64
	authSuccesses atomic.Uint64
	tlsManager    *tls.Manager
	tlsConfig     *config.TLSConfig

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// Creates a new HTTP server source
func NewHTTPSource(options map[string]any, logger *log.Logger) (*HTTPSource, error) {
	host := "0.0.0.0"
	if h, ok := options["host"].(string); ok && h != "" {
		host = h
	}

	port, ok := options["port"].(int64)
	if !ok || port < 1 || port > 65535 {
		return nil, fmt.Errorf("http source requires valid 'port' option")
	}

	ingestPath := "/ingest"
	if path, ok := options["path"].(string); ok && path != "" {
		ingestPath = path
	}

	bufferSize := int64(1000)
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	maxRequestBodySize := int64(10 * 1024 * 1024) // fasthttp default 10MB
	if maxBodySize, ok := options["max_body_size"].(int64); ok && maxBodySize > 0 && maxBodySize < maxRequestBodySize {
		maxRequestBodySize = maxBodySize
	}

	h := &HTTPSource{
		host:               host,
		port:               port,
		path:               ingestPath,
		bufferSize:         bufferSize,
		maxRequestBodySize: maxRequestBodySize,
		done:               make(chan struct{}),
		startTime:          time.Now(),
		logger:             logger,
	}
	h.lastEntryTime.Store(time.Time{})

	// Initialize net limiter if configured
	if nl, ok := options["net_limit"].(map[string]any); ok {
		if enabled, _ := nl["enabled"].(bool); enabled {
			cfg := config.NetLimitConfig{
				Enabled: true,
			}

			if rps, ok := nl["requests_per_second"].(float64); ok {
				cfg.RequestsPerSecond = rps
			}
			if burst, ok := nl["burst_size"].(int64); ok {
				cfg.BurstSize = burst
			}
			if respCode, ok := nl["response_code"].(int64); ok {
				cfg.ResponseCode = respCode
			}
			if msg, ok := nl["response_message"].(string); ok {
				cfg.ResponseMessage = msg
			}
			if maxPerIP, ok := nl["max_connections_per_ip"].(int64); ok {
				cfg.MaxConnectionsPerIP = maxPerIP
			}
			if maxPerUser, ok := nl["max_connections_per_user"].(int64); ok {
				cfg.MaxConnectionsPerUser = maxPerUser
			}
			if maxPerToken, ok := nl["max_connections_per_token"].(int64); ok {
				cfg.MaxConnectionsPerToken = maxPerToken
			}
			if maxTotal, ok := nl["max_connections_total"].(int64); ok {
				cfg.MaxConnectionsTotal = maxTotal
			}

			h.netLimiter = limit.NewNetLimiter(cfg, logger)
		}
	}

	// Extract TLS config after existing options
	if tc, ok := options["tls"].(map[string]any); ok {
		h.tlsConfig = &config.TLSConfig{}
		h.tlsConfig.Enabled, _ = tc["enabled"].(bool)
		if certFile, ok := tc["cert_file"].(string); ok {
			h.tlsConfig.CertFile = certFile
		}
		if keyFile, ok := tc["key_file"].(string); ok {
			h.tlsConfig.KeyFile = keyFile
		}
		h.tlsConfig.ClientAuth, _ = tc["client_auth"].(bool)
		if caFile, ok := tc["client_ca_file"].(string); ok {
			h.tlsConfig.ClientCAFile = caFile
		}
		h.tlsConfig.VerifyClientCert, _ = tc["verify_client_cert"].(bool)
		h.tlsConfig.InsecureSkipVerify, _ = tc["insecure_skip_verify"].(bool)
		if minVer, ok := tc["min_version"].(string); ok {
			h.tlsConfig.MinVersion = minVer
		}
		if maxVer, ok := tc["max_version"].(string); ok {
			h.tlsConfig.MaxVersion = maxVer
		}
		if ciphers, ok := tc["cipher_suites"].(string); ok {
			h.tlsConfig.CipherSuites = ciphers
		}

		// Create TLS manager
		if h.tlsConfig.Enabled {
			tlsManager, err := tls.NewManager(h.tlsConfig, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS manager: %w", err)
			}
			h.tlsManager = tlsManager
		}
	}

	return h, nil
}

func (h *HTTPSource) Subscribe() <-chan core.LogEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan core.LogEntry, h.bufferSize)
	h.subscribers = append(h.subscribers, ch)
	return ch
}

func (h *HTTPSource) Start() error {
	h.server = &fasthttp.Server{
		Name:               fmt.Sprintf("LogWisp/%s", version.Short()),
		Handler:            h.requestHandler,
		DisableKeepalive:   false,
		StreamRequestBody:  true,
		CloseOnShutdown:    true,
		MaxRequestBodySize: int(h.maxRequestBodySize),
	}

	// Use configured host and port
	addr := fmt.Sprintf("%s:%d", h.host, h.port)

	// Start server in background
	h.wg.Add(1)
	errChan := make(chan error, 1)
	go func() {
		defer h.wg.Done()
		h.logger.Info("msg", "HTTP source server starting",
			"component", "http_source",
			"port", h.port,
			"path", h.path,
			"tls_enabled", h.tlsManager != nil)

		var err error
		// Check for TLS manager and start the appropriate server type
		if h.tlsManager != nil {
			h.server.TLSConfig = h.tlsManager.GetHTTPConfig()
			err = h.server.ListenAndServeTLS(addr, h.tlsConfig.CertFile, h.tlsConfig.KeyFile)
		} else {
			err = h.server.ListenAndServe(addr)
		}

		if err != nil {
			h.logger.Error("msg", "HTTP source server failed",
				"component", "http_source",
				"port", h.port,
				"error", err)
			errChan <- err
		}
	}()

	// Robust server startup check with timeout
	select {
	case err := <-errChan:
		// Server failed to start
		return fmt.Errorf("HTTP server failed to start: %w", err)
	case <-time.After(250 * time.Millisecond):
		// Server started successfully (no immediate error)
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

	return SourceStats{
		Type:           "http",
		TotalEntries:   h.totalEntries.Load(),
		DroppedEntries: h.droppedEntries.Load(),
		StartTime:      h.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"port":            h.port,
			"path":            h.path,
			"invalid_entries": h.invalidEntries.Load(),
			"net_limit":       netLimitStats,
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

	// 3. Path check (only process ingest path)
	path := string(ctx.Path())
	if path != h.path {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Not Found",
			"hint":  fmt.Sprintf("POST logs to %s", h.path),
		})
		return
	}

	// 4. Method check (only accept POST)
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

	// 5. Authentication check (if configured)
	if h.authenticator != nil {
		authHeader := string(ctx.Request.Header.Peek("Authorization"))
		session, err := h.authenticator.AuthenticateHTTP(authHeader, remoteAddr)
		if err != nil {
			h.authFailures.Add(1)
			h.logger.Warn("msg", "Authentication failed",
				"component", "http_source",
				"remote_addr", remoteAddr,
				"error", err)

			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			if h.authConfig.Type == "basic" && h.authConfig.BasicAuth != nil {
				realm := h.authConfig.BasicAuth.Realm
				if realm == "" {
					realm = "Restricted"
				}
				ctx.Response.Header.Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			} else if h.authConfig.Type == "bearer" {
				ctx.Response.Header.Set("WWW-Authenticate", "Bearer")
			}
			ctx.SetContentType("application/json")
			json.NewEncoder(ctx).Encode(map[string]string{
				"error": "Unauthorized",
			})
			return
		}
		h.authSuccesses.Add(1)
		h.logger.Debug("msg", "Request authenticated",
			"component", "http_source",
			"remote_addr", remoteAddr,
			"username", session.Username)
	}

	// 6. Process request body
	body := ctx.PostBody()
	if len(body) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Empty request body",
		})
		return
	}

	// 7. Parse log entries
	entries, err := h.parseEntries(body)
	if err != nil {
		h.invalidEntries.Add(1)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": fmt.Sprintf("Invalid log format: %v", err),
		})
		return
	}

	// 8. Publish entries to subscribers
	accepted := 0
	for _, entry := range entries {
		if h.publish(entry) {
			accepted++
		}
	}

	// 9. Return success response
	ctx.SetStatusCode(fasthttp.StatusAccepted)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]any{
		"accepted": accepted,
		"total":    len(entries),
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

func (h *HTTPSource) publish(entry core.LogEntry) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	h.totalEntries.Add(1)
	h.lastEntryTime.Store(entry.Time)

	dropped := false
	for _, ch := range h.subscribers {
		select {
		case ch <- entry:
		default:
			dropped = true
			h.droppedEntries.Add(1)
		}
	}

	if dropped {
		h.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
			"component", "http_source")
	}

	return true
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

// Configure HTTP source auth
func (h *HTTPSource) SetAuth(authCfg *config.AuthConfig) {
	if authCfg == nil || authCfg.Type == "none" {
		return
	}

	h.authConfig = authCfg
	authenticator, err := auth.New(authCfg, h.logger)
	if err != nil {
		h.logger.Error("msg", "Failed to initialize authenticator for HTTP source",
			"component", "http_source",
			"error", err)
		return
	}
	h.authenticator = authenticator

	h.logger.Info("msg", "Authentication configured for HTTP source",
		"component", "http_source",
		"auth_type", authCfg.Type)
}