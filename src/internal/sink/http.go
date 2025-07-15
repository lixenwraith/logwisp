// FILE: src/internal/sink/http.go
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

	"logwisp/src/internal/config"
	"logwisp/src/internal/format"
	"logwisp/src/internal/netlimit"
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
	formatter     format.Formatter

	// Path configuration
	streamPath string
	statusPath string

	// For router integration
	standalone bool

	// Net limiting
	netLimiter *netlimit.Limiter

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
		cfg.Heartbeat = &config.HeartbeatConfig{}
		cfg.Heartbeat.Enabled, _ = hb["enabled"].(bool)
		if interval, ok := toInt(hb["interval_seconds"]); ok {
			cfg.Heartbeat.IntervalSeconds = interval
		}
		cfg.Heartbeat.IncludeTimestamp, _ = hb["include_timestamp"].(bool)
		cfg.Heartbeat.IncludeStats, _ = hb["include_stats"].(bool)
		if hbFormat, ok := hb["format"].(string); ok {
			cfg.Heartbeat.Format = hbFormat
		}
	}

	// Extract net limit config
	if rl, ok := options["net_limit"].(map[string]any); ok {
		cfg.NetLimit = &config.NetLimitConfig{}
		cfg.NetLimit.Enabled, _ = rl["enabled"].(bool)
		if rps, ok := toFloat(rl["requests_per_second"]); ok {
			cfg.NetLimit.RequestsPerSecond = rps
		}
		if burst, ok := toInt(rl["burst_size"]); ok {
			cfg.NetLimit.BurstSize = burst
		}
		if limitBy, ok := rl["limit_by"].(string); ok {
			cfg.NetLimit.LimitBy = limitBy
		}
		if respCode, ok := toInt(rl["response_code"]); ok {
			cfg.NetLimit.ResponseCode = respCode
		}
		if msg, ok := rl["response_message"].(string); ok {
			cfg.NetLimit.ResponseMessage = msg
		}
		if maxPerIP, ok := toInt(rl["max_connections_per_ip"]); ok {
			cfg.NetLimit.MaxConnectionsPerIP = maxPerIP
		}
		if maxTotal, ok := toInt(rl["max_total_connections"]); ok {
			cfg.NetLimit.MaxTotalConnections = maxTotal
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
		formatter:  formatter,
	}
	h.lastProcessed.Store(time.Time{})

	// Initialize net limiter if configured
	if cfg.NetLimit != nil && cfg.NetLimit.Enabled {
		h.netLimiter = netlimit.New(*cfg.NetLimit, logger)
	}

	return h, nil
}

func (h *HTTPSink) Input() chan<- source.LogEntry {
	return h.input
}

func (h *HTTPSink) Start(ctx context.Context) error {
	// TODO: use or remove unused ctx
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

	var netLimitStats map[string]any
	if h.netLimiter != nil {
		netLimitStats = h.netLimiter.GetStats()
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
	// Check net limit first
	remoteAddr := ctx.RemoteAddr().String()
	if allowed, statusCode, message := h.netLimiter.CheckHTTP(remoteAddr); !allowed {
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
		fmt.Fprintf(w, "event: connected\ndata: %s\n", data)
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

func (h *HTTPSink) formatEntryForSSE(w *bufio.Writer, entry source.LogEntry) error {
	formatted, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}

	// Remove trailing newline if present (SSE adds its own)
	formatted = bytes.TrimSuffix(formatted, []byte{'\n'})

	// Multi-line content handler
	lines := bytes.Split(formatted, []byte{'\n'})
	for _, line := range lines {
		// SSE needs "data: " prefix for each line
		fmt.Fprintf(w, "data: %s\n", line)
	}

	return nil
}

func (h *HTTPSink) createHeartbeatEntry() source.LogEntry {
	message := "heartbeat"

	// Build fields for heartbeat metadata
	fields := make(map[string]any)
	fields["type"] = "heartbeat"

	if h.config.Heartbeat.IncludeStats {
		fields["active_clients"] = h.activeClients.Load()
		fields["uptime_seconds"] = int(time.Since(h.startTime).Seconds())
	}

	fieldsJSON, _ := json.Marshal(fields)

	return source.LogEntry{
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
			"net_limit": netLimitStats,
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