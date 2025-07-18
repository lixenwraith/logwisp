// FILE: src/internal/sink/http.go
package sink

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/ratelimit"
	"logwisp/src/internal/source"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/compat"
	"github.com/valyala/fasthttp"
)

// HTTPSink streams log entries via Server-Sent Events
type HTTPSink struct {
	input         chan source.LogEntry
	config        HTTPConfig
	server        *fasthttp.Server
	activeClients atomic.Int32
	mu            sync.RWMutex
	startTime     time.Time
	done          chan struct{}
	wg            sync.WaitGroup
	logger        *log.Logger

	// Path configuration
	streamPath string
	statusPath string

	// For router integration
	standalone bool

	// Rate limiting
	rateLimiter *ratelimit.Limiter

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// HTTPConfig holds HTTP sink configuration
type HTTPConfig struct {
	Port       int
	BufferSize int
	StreamPath string
	StatusPath string
	Heartbeat  config.HeartbeatConfig
	SSL        *config.SSLConfig
	RateLimit  *config.RateLimitConfig
}

// NewHTTPSink creates a new HTTP streaming sink
func NewHTTPSink(options map[string]any, logger *log.Logger) (*HTTPSink, error) {
	cfg := HTTPConfig{
		Port:       8080,
		BufferSize: 1000,
		StreamPath: "/transport",
		StatusPath: "/status",
	}

	// Extract configuration from options
	if port, ok := toInt(options["port"]); ok {
		cfg.Port = port
	}
	if bufSize, ok := toInt(options["buffer_size"]); ok {
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
		cfg.Heartbeat.Enabled, _ = hb["enabled"].(bool)
		if interval, ok := toInt(hb["interval_seconds"]); ok {
			cfg.Heartbeat.IntervalSeconds = interval
		}
		cfg.Heartbeat.IncludeTimestamp, _ = hb["include_timestamp"].(bool)
		cfg.Heartbeat.IncludeStats, _ = hb["include_stats"].(bool)
		if format, ok := hb["format"].(string); ok {
			cfg.Heartbeat.Format = format
		}
	}

	// Extract rate limit config
	if rl, ok := options["rate_limit"].(map[string]any); ok {
		cfg.RateLimit = &config.RateLimitConfig{}
		cfg.RateLimit.Enabled, _ = rl["enabled"].(bool)
		if rps, ok := toFloat(rl["requests_per_second"]); ok {
			cfg.RateLimit.RequestsPerSecond = rps
		}
		if burst, ok := toInt(rl["burst_size"]); ok {
			cfg.RateLimit.BurstSize = burst
		}
		if limitBy, ok := rl["limit_by"].(string); ok {
			cfg.RateLimit.LimitBy = limitBy
		}
		if respCode, ok := toInt(rl["response_code"]); ok {
			cfg.RateLimit.ResponseCode = respCode
		}
		if msg, ok := rl["response_message"].(string); ok {
			cfg.RateLimit.ResponseMessage = msg
		}
		if maxPerIP, ok := toInt(rl["max_connections_per_ip"]); ok {
			cfg.RateLimit.MaxConnectionsPerIP = maxPerIP
		}
		if maxTotal, ok := toInt(rl["max_total_connections"]); ok {
			cfg.RateLimit.MaxTotalConnections = maxTotal
		}
	}

	h := &HTTPSink{
		input:      make(chan source.LogEntry, cfg.BufferSize),
		config:     cfg,
		startTime:  time.Now(),
		done:       make(chan struct{}),
		streamPath: cfg.StreamPath,
		statusPath: cfg.StatusPath,
		standalone: true,
		logger:     logger,
	}
	h.lastProcessed.Store(time.Time{})

	// Initialize rate limiter if configured
	if cfg.RateLimit != nil && cfg.RateLimit.Enabled {
		h.rateLimiter = ratelimit.New(*cfg.RateLimit, logger)
	}

	return h, nil
}

func (h *HTTPSink) Input() chan<- source.LogEntry {
	return h.input
}

func (h *HTTPSink) Start(ctx context.Context) error {
	if !h.standalone {
		// In router mode, don't start our own server
		h.logger.Debug("msg", "HTTP sink in router mode, skipping server start",
			"component", "http_sink")
		return nil
	}

	// Create fasthttp adapter for logging
	fasthttpLogger := compat.NewFastHTTPAdapter(h.logger)

	h.server = &fasthttp.Server{
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		Logger:            fasthttpLogger,
	}

	addr := fmt.Sprintf(":%d", h.config.Port)

	// Run server in separate goroutine to avoid blocking
	errChan := make(chan error, 1)
	go func() {
		h.logger.Info("msg", "HTTP server started",
			"component", "http_sink",
			"port", h.config.Port,
			"stream_path", h.streamPath,
			"status_path", h.statusPath)
		err := h.server.ListenAndServe(addr)
		if err != nil {
			errChan <- err
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

	// Shutdown HTTP server if in standalone mode
	if h.standalone && h.server != nil {
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

	var rateLimitStats map[string]any
	if h.rateLimiter != nil {
		rateLimitStats = h.rateLimiter.GetStats()
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
			"rate_limit": rateLimitStats,
		},
	}
}

// SetRouterMode configures the sink for use with a router
func (h *HTTPSink) SetRouterMode() {
	h.standalone = false
	h.logger.Debug("msg", "HTTP sink set to router mode",
		"component", "http_sink")
}

// RouteRequest handles a request from the router
func (h *HTTPSink) RouteRequest(ctx *fasthttp.RequestCtx) {
	h.requestHandler(ctx)
}

func (h *HTTPSink) requestHandler(ctx *fasthttp.RequestCtx) {
	// Check rate limit first
	remoteAddr := ctx.RemoteAddr().String()
	if allowed, statusCode, message := h.rateLimiter.CheckHTTP(remoteAddr); !allowed {
		ctx.SetStatusCode(statusCode)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]any{
			"error":       message,
			"retry_after": "60", // seconds
		})
		return
	}

	path := string(ctx.Path())

	switch path {
	case h.streamPath:
		h.handleStream(ctx)
	case h.statusPath:
		h.handleStatus(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]any{
			"error": "Not Found",
			"message": fmt.Sprintf("Available endpoints: %s (SSE transport), %s (status)",
				h.streamPath, h.statusPath),
		})
	}
}

func (h *HTTPSink) handleStream(ctx *fasthttp.RequestCtx) {
	// Track connection for rate limiting
	remoteAddr := ctx.RemoteAddr().String()
	if h.rateLimiter != nil {
		h.rateLimiter.AddConnection(remoteAddr)
		defer h.rateLimiter.RemoveConnection(remoteAddr)
	}

	// Set SSE headers
	ctx.Response.Header.Set("Content-Type", "text/event-transport")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")

	// Create subscription for this client
	clientChan := make(chan source.LogEntry, h.config.BufferSize)
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
					// Drop if client buffer full, may flood logging for slow client
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
			"active_clients", newCount)

		h.wg.Add(1)
		defer func() {
			close(clientDone)
			newCount := h.activeClients.Add(-1)
			h.logger.Debug("msg", "HTTP client disconnected",
				"remote_addr", remoteAddr,
				"active_clients", newCount)
			h.wg.Done()
		}()

		// Send initial connected event
		clientID := fmt.Sprintf("%d", time.Now().UnixNano())
		connectionInfo := map[string]any{
			"client_id":   clientID,
			"stream_path": h.streamPath,
			"status_path": h.statusPath,
			"buffer_size": h.config.BufferSize,
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

				data, err := json.Marshal(entry)
				if err != nil {
					h.logger.Error("msg", "Failed to marshal log entry",
						"component", "http_sink",
						"error", err,
						"entry_source", entry.Source)
					continue
				}

				fmt.Fprintf(w, "data: %s\n\n", data)
				if err := w.Flush(); err != nil {
					// Client disconnected, fasthttp handles cleanup
					return
				}

			case <-tickerChan:
				if heartbeat := h.formatHeartbeat(); heartbeat != "" {
					fmt.Fprint(w, heartbeat)
					if err := w.Flush(); err != nil {
						return
					}
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

func (h *HTTPSink) formatHeartbeat() string {
	if !h.config.Heartbeat.Enabled {
		return ""
	}

	if h.config.Heartbeat.Format == "json" {
		data := make(map[string]any)
		data["type"] = "heartbeat"

		if h.config.Heartbeat.IncludeTimestamp {
			data["timestamp"] = time.Now().UTC().Format(time.RFC3339)
		}

		if h.config.Heartbeat.IncludeStats {
			data["active_clients"] = h.activeClients.Load()
			data["uptime_seconds"] = int(time.Since(h.startTime).Seconds())
		}

		jsonData, _ := json.Marshal(data)
		return fmt.Sprintf("data: %s\n\n", jsonData)
	}

	// Default comment format
	var parts []string
	parts = append(parts, "heartbeat")

	if h.config.Heartbeat.IncludeTimestamp {
		parts = append(parts, time.Now().UTC().Format(time.RFC3339))
	}

	if h.config.Heartbeat.IncludeStats {
		parts = append(parts, fmt.Sprintf("clients=%d", h.activeClients.Load()))
		parts = append(parts, fmt.Sprintf("uptime=%ds", int(time.Since(h.startTime).Seconds())))
	}

	return fmt.Sprintf(": %s\n\n", strings.Join(parts, " "))
}

func (h *HTTPSink) handleStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	var rateLimitStats any
	if h.rateLimiter != nil {
		rateLimitStats = h.rateLimiter.GetStats()
	} else {
		rateLimitStats = map[string]any{
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
			"mode":           map[string]bool{"standalone": h.standalone, "router": !h.standalone},
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
			"ssl": map[string]bool{
				"enabled": h.config.SSL != nil && h.config.SSL.Enabled,
			},
			"rate_limit": rateLimitStats,
		},
	}

	data, _ := json.Marshal(status)
	ctx.SetBody(data)
}

// GetActiveConnections returns the current number of active clients
func (h *HTTPSink) GetActiveConnections() int32 {
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