// FILE: logwisp/src/internal/sink/http.go
package sink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	"logwisp/src/internal/limit"
	"logwisp/src/internal/tls"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/valyala/fasthttp"
)

// HTTPSink streams log entries via Server-Sent Events
type HTTPSink struct {
	input         chan core.LogEntry
	config        HTTPConfig
	server        *fasthttp.Server
	activeClients atomic.Int64
	mu            sync.RWMutex
	startTime     time.Time
	done          chan struct{}
	wg            sync.WaitGroup
	logger        *log.Logger
	formatter     format.Formatter

	// Security components
	authenticator *auth.Authenticator
	tlsManager    *tls.Manager
	authConfig    *config.AuthConfig

	// Path configuration
	streamPath string
	statusPath string

	// Net limiting
	netLimiter *limit.NetLimiter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
	authFailures   atomic.Uint64
	authSuccesses  atomic.Uint64
}

// HTTPConfig holds HTTP sink configuration
type HTTPConfig struct {
	Port       int64
	BufferSize int64
	StreamPath string
	StatusPath string
	Heartbeat  *config.HeartbeatConfig
	SSL        *config.SSLConfig
	NetLimit   *config.NetLimitConfig
}

// NewHTTPSink creates a new HTTP streaming sink
func NewHTTPSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*HTTPSink, error) {
	cfg := HTTPConfig{
		Port:       8080,
		BufferSize: 1000,
		StreamPath: "/transport",
		StatusPath: "/status",
	}

	// Extract configuration from options
	if port, ok := options["port"].(int64); ok {
		cfg.Port = port
	}
	if bufSize, ok := options["buffer_size"].(int64); ok {
		cfg.BufferSize = bufSize
	}
	if path, ok := options["stream_path"].(string); ok {
		cfg.StreamPath = path
	}
	if path, ok := options["status_path"].(string); ok {
		cfg.StatusPath = path
	}

	// Extract heartbeat config
	if hb, ok := options["heartbeat"].(map[string]any); ok {
		cfg.Heartbeat = &config.HeartbeatConfig{}
		cfg.Heartbeat.Enabled, _ = hb["enabled"].(bool)
		if interval, ok := hb["interval_seconds"].(int64); ok {
			cfg.Heartbeat.IntervalSeconds = interval
		}
		cfg.Heartbeat.IncludeTimestamp, _ = hb["include_timestamp"].(bool)
		cfg.Heartbeat.IncludeStats, _ = hb["include_stats"].(bool)
		if hbFormat, ok := hb["format"].(string); ok {
			cfg.Heartbeat.Format = hbFormat
		}
	}

	// Extract SSL config
	if ssl, ok := options["ssl"].(map[string]any); ok {
		cfg.SSL = &config.SSLConfig{}
		cfg.SSL.Enabled, _ = ssl["enabled"].(bool)
		if certFile, ok := ssl["cert_file"].(string); ok {
			cfg.SSL.CertFile = certFile
		}
		if keyFile, ok := ssl["key_file"].(string); ok {
			cfg.SSL.KeyFile = keyFile
		}
		cfg.SSL.ClientAuth, _ = ssl["client_auth"].(bool)
		if caFile, ok := ssl["client_ca_file"].(string); ok {
			cfg.SSL.ClientCAFile = caFile
		}
		cfg.SSL.VerifyClientCert, _ = ssl["verify_client_cert"].(bool)
		if minVer, ok := ssl["min_version"].(string); ok {
			cfg.SSL.MinVersion = minVer
		}
		if maxVer, ok := ssl["max_version"].(string); ok {
			cfg.SSL.MaxVersion = maxVer
		}
		if ciphers, ok := ssl["cipher_suites"].(string); ok {
			cfg.SSL.CipherSuites = ciphers
		}
	}

	// Extract net limit config
	if rl, ok := options["net_limit"].(map[string]any); ok {
		cfg.NetLimit = &config.NetLimitConfig{}
		cfg.NetLimit.Enabled, _ = rl["enabled"].(bool)
		if rps, ok := rl["requests_per_second"].(float64); ok {
			cfg.NetLimit.RequestsPerSecond = rps
		}
		if burst, ok := rl["burst_size"].(int64); ok {
			cfg.NetLimit.BurstSize = burst
		}
		if limitBy, ok := rl["limit_by"].(string); ok {
			cfg.NetLimit.LimitBy = limitBy
		}
		if respCode, ok := rl["response_code"].(int64); ok {
			cfg.NetLimit.ResponseCode = respCode
		}
		if msg, ok := rl["response_message"].(string); ok {
			cfg.NetLimit.ResponseMessage = msg
		}
		if maxPerIP, ok := rl["max_connections_per_ip"].(int64); ok {
			cfg.NetLimit.MaxConnectionsPerIP = maxPerIP
		}
		if maxTotal, ok := rl["max_total_connections"].(int64); ok {
			cfg.NetLimit.MaxTotalConnections = maxTotal
		}
		if ipWhitelist, ok := rl["ip_whitelist"].([]any); ok {
			cfg.NetLimit.IPWhitelist = make([]string, 0, len(ipWhitelist))
			for _, entry := range ipWhitelist {
				if str, ok := entry.(string); ok {
					cfg.NetLimit.IPWhitelist = append(cfg.NetLimit.IPWhitelist, str)
				}
			}
		}
		if ipBlacklist, ok := rl["ip_blacklist"].([]any); ok {
			cfg.NetLimit.IPBlacklist = make([]string, 0, len(ipBlacklist))
			for _, entry := range ipBlacklist {
				if str, ok := entry.(string); ok {
					cfg.NetLimit.IPBlacklist = append(cfg.NetLimit.IPBlacklist, str)
				}
			}
		}
	}

	h := &HTTPSink{
		input:      make(chan core.LogEntry, cfg.BufferSize),
		config:     cfg,
		startTime:  time.Now(),
		done:       make(chan struct{}),
		streamPath: cfg.StreamPath,
		statusPath: cfg.StatusPath,
		logger:     logger,
		formatter:  formatter,
	}
	h.lastProcessed.Store(time.Time{})

	// Initialize net limiter if configured
	if cfg.NetLimit != nil && cfg.NetLimit.Enabled {
		h.netLimiter = limit.NewNetLimiter(*cfg.NetLimit, logger)
	}

	return h, nil
}

func (h *HTTPSink) Input() chan<- core.LogEntry {
	return h.input
}

func (h *HTTPSink) Start(ctx context.Context) error {
	// Create fasthttp adapter for logging
	fasthttpLogger := compat.NewFastHTTPAdapter(h.logger)

	h.server = &fasthttp.Server{
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		Logger:            fasthttpLogger,
	}

	// Configure TLS if enabled
	if h.tlsManager != nil {
		h.server.TLSConfig = h.tlsManager.GetHTTPConfig()
		h.logger.Info("msg", "TLS enabled for HTTP sink",
			"component", "http_sink",
			"port", h.config.Port)
	}

	addr := fmt.Sprintf(":%d", h.config.Port)

	// Run server in separate goroutine to avoid blocking
	errChan := make(chan error, 1)
	go func() {
		h.logger.Info("msg", "HTTP server started",
			"component", "http_sink",
			"port", h.config.Port,
			"stream_path", h.streamPath,
			"status_path", h.statusPath,
			"tls_enabled", h.tlsManager != nil)

		var err error
		if h.tlsManager != nil {
			// HTTPS server
			err = h.server.ListenAndServeTLS(addr, h.config.SSL.CertFile, h.config.SSL.KeyFile)
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
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			h.server.ShutdownWithContext(shutdownCtx)
		}
	}()

	// Check if server started successfully
	select {
	case err := <-errChan:
		return err
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
		return nil
	}
}

func (h *HTTPSink) Stop() {
	h.logger.Info("msg", "Stopping HTTP sink")

	// Signal all client handlers to stop
	close(h.done)

	// Shutdown HTTP server
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		h.server.ShutdownWithContext(ctx)
	}

	// Wait for all active client handlers to finish
	h.wg.Wait()

	h.logger.Info("msg", "HTTP sink stopped")
}

func (h *HTTPSink) GetStats() SinkStats {
	lastProc, _ := h.lastProcessed.Load().(time.Time)

	var netLimitStats map[string]any
	if h.netLimiter != nil {
		netLimitStats = h.netLimiter.GetStats()
	}

	var authStats map[string]any
	if h.authenticator != nil {
		authStats = h.authenticator.GetStats()
		authStats["failures"] = h.authFailures.Load()
		authStats["successes"] = h.authSuccesses.Load()
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
				"stream": h.streamPath,
				"status": h.statusPath,
			},
			"net_limit": netLimitStats,
			"auth":      authStats,
			"tls":       tlsStats,
		},
	}
}

func (h *HTTPSink) requestHandler(ctx *fasthttp.RequestCtx) {
	remoteAddr := ctx.RemoteAddr().String()

	// Check net limit
	if h.netLimiter != nil {
		if allowed, statusCode, message := h.netLimiter.CheckHTTP(remoteAddr); !allowed {
			ctx.SetStatusCode(int(statusCode))
			ctx.SetContentType("application/json")
			h.logger.Warn("msg", "Net limited",
				"component", "http_sink",
				"remote_addr", remoteAddr,
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
	if path == h.statusPath {
		h.handleStatus(ctx)
		return
	}

	// Authenticate request
	var session *auth.Session
	if h.authenticator != nil {
		authHeader := string(ctx.Request.Header.Peek("Authorization"))
		var err error
		session, err = h.authenticator.AuthenticateHTTP(authHeader, remoteAddr)
		if err != nil {
			h.authFailures.Add(1)
			h.logger.Warn("msg", "Authentication failed",
				"component", "http_sink",
				"remote_addr", remoteAddr,
				"error", err)

			// Return 401 with WWW-Authenticate header
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			if h.authConfig.Type == "basic" && h.authConfig.BasicAuth != nil {
				realm := h.authConfig.BasicAuth.Realm
				if realm == "" {
					realm = "Restricted"
				}
				ctx.Response.Header.Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
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
	}

	switch path {
	case h.streamPath:
		h.handleStream(ctx, session)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]any{
			"error": "Not Found",
		})
	}
}

func (h *HTTPSink) handleStream(ctx *fasthttp.RequestCtx, session *auth.Session) {
	// Track connection for net limiting
	remoteAddr := ctx.RemoteAddr().String()
	if h.netLimiter != nil {
		h.netLimiter.AddConnection(remoteAddr)
		defer h.netLimiter.RemoveConnection(remoteAddr)
	}

	// Set SSE headers
	ctx.Response.Header.Set("Content-Type", "text/event-transport")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")

	// Create subscription for this client
	clientChan := make(chan core.LogEntry, h.config.BufferSize)
	clientDone := make(chan struct{})

	// Subscribe to input channel
	go func() {
		defer close(clientChan)
		for {
			select {
			case entry, ok := <-h.input:
				if !ok {
					return
				}
				h.totalProcessed.Add(1)
				h.lastProcessed.Store(time.Now())

				select {
				case clientChan <- entry:
				case <-clientDone:
					return
				case <-h.done:
					return
				default:
					// Drop if client buffer full
					h.logger.Debug("msg", "Dropped entry for slow client",
						"component", "http_sink",
						"remote_addr", remoteAddr)
				}
			case <-clientDone:
				return
			case <-h.done:
				return
			}
		}
	}()

	// Define the transport writer function
	streamFunc := func(w *bufio.Writer) {
		newCount := h.activeClients.Add(1)
		h.logger.Debug("msg", "HTTP client connected",
			"remote_addr", remoteAddr,
			"username", session.Username,
			"auth_method", session.Method,
			"active_clients", newCount)

		h.wg.Add(1)
		defer func() {
			close(clientDone)
			newCount := h.activeClients.Add(-1)
			h.logger.Debug("msg", "HTTP client disconnected",
				"remote_addr", remoteAddr,
				"username", session.Username,
				"active_clients", newCount)
			h.wg.Done()
		}()

		// Send initial connected event
		clientID := fmt.Sprintf("%d", time.Now().UnixNano())
		connectionInfo := map[string]any{
			"client_id":   clientID,
			"username":    session.Username,
			"auth_method": session.Method,
			"stream_path": h.streamPath,
			"status_path": h.statusPath,
			"buffer_size": h.config.BufferSize,
			"tls":         h.tlsManager != nil,
		}
		data, _ := json.Marshal(connectionInfo)
		fmt.Fprintf(w, "event: connected\ndata: %s\n\n", data)
		w.Flush()

		var ticker *time.Ticker
		var tickerChan <-chan time.Time

		if h.config.Heartbeat.Enabled {
			ticker = time.NewTicker(time.Duration(h.config.Heartbeat.IntervalSeconds) * time.Second)
			tickerChan = ticker.C
			defer ticker.Stop()
		}

		for {
			select {
			case entry, ok := <-clientChan:
				if !ok {
					return
				}

				if err := h.formatEntryForSSE(w, entry); err != nil {
					h.logger.Error("msg", "Failed to format log entry",
						"component", "http_sink",
						"error", err,
						"entry_source", entry.Source)
					continue
				}

				if err := w.Flush(); err != nil {
					// Client disconnected
					return
				}

			case <-tickerChan:
				// Validate session is still active
				if h.authenticator != nil && !h.authenticator.ValidateSession(session.ID) {
					fmt.Fprintf(w, "event: disconnect\ndata: {\"reason\":\"session_expired\"}\n\n")
					w.Flush()
					return
				}

				heartbeatEntry := h.createHeartbeatEntry()
				if err := h.formatEntryForSSE(w, heartbeatEntry); err != nil {
					h.logger.Error("msg", "Failed to format heartbeat",
						"component", "http_sink",
						"error", err)
				}
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

func (h *HTTPSink) formatEntryForSSE(w *bufio.Writer, entry core.LogEntry) error {
	formatted, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}

	// Remove trailing newline if present (SSE adds its own)
	formatted = bytes.TrimSuffix(formatted, []byte{'\n'})

	// Multi-line content handler
	lines := bytes.Split(formatted, []byte{'\n'})
	for _, line := range lines {
		// SSE needs "data: " prefix for each line based on W3C spec
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprintf(w, "\n") // Empty line to terminate event

	return nil
}

func (h *HTTPSink) createHeartbeatEntry() core.LogEntry {
	message := "heartbeat"

	// Build fields for heartbeat metadata
	fields := make(map[string]any)
	fields["type"] = "heartbeat"

	if h.config.Heartbeat.IncludeStats {
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

	var authStats any
	if h.authenticator != nil {
		authStats = h.authenticator.GetStats()
		authStats.(map[string]any)["failures"] = h.authFailures.Load()
		authStats.(map[string]any)["successes"] = h.authSuccesses.Load()
	} else {
		authStats = map[string]any{
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
			"transport": h.streamPath,
			"status":    h.statusPath,
		},
		"features": map[string]any{
			"heartbeat": map[string]any{
				"enabled":  h.config.Heartbeat.Enabled,
				"interval": h.config.Heartbeat.IntervalSeconds,
				"format":   h.config.Heartbeat.Format,
			},
			"tls":       tlsStats,
			"auth":      authStats,
			"net_limit": netLimitStats,
		},
		"statistics": map[string]any{
			"total_processed": h.totalProcessed.Load(),
			"auth_failures":   h.authFailures.Load(),
			"auth_successes":  h.authSuccesses.Load(),
		},
	}

	data, _ := json.Marshal(status)
	ctx.SetBody(data)
}

// GetActiveConnections returns the current number of active clients
func (h *HTTPSink) GetActiveConnections() int64 {
	return h.activeClients.Load()
}

// GetStreamPath returns the configured transport endpoint path
func (h *HTTPSink) GetStreamPath() string {
	return h.streamPath
}

// GetStatusPath returns the configured status endpoint path
func (h *HTTPSink) GetStatusPath() string {
	return h.statusPath
}

// SetAuthConfig configures http sink authentication
func (h *HTTPSink) SetAuthConfig(authCfg *config.AuthConfig) {
	if authCfg == nil || authCfg.Type == "none" {
		return
	}

	h.authConfig = authCfg
	authenticator, err := auth.New(authCfg, h.logger)
	if err != nil {
		h.logger.Error("msg", "Failed to initialize authenticator for HTTP sink",
			"component", "http_sink",
			"error", err)
		// Continue without auth
		return
	}
	h.authenticator = authenticator

	h.logger.Info("msg", "Authentication configured for HTTP sink",
		"component", "http_sink",
		"auth_type", authCfg.Type)
}