// FILE: src/internal/source/http.go
package source

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/netlimit"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// HTTPSource receives log entries via HTTP POST requests
type HTTPSource struct {
	port        int
	ingestPath  string
	bufferSize  int
	server      *fasthttp.Server
	subscribers []chan LogEntry
	mu          sync.RWMutex
	done        chan struct{}
	wg          sync.WaitGroup
	netLimiter  *netlimit.Limiter
	logger      *log.Logger

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	invalidEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// NewHTTPSource creates a new HTTP server source
func NewHTTPSource(options map[string]any, logger *log.Logger) (*HTTPSource, error) {
	port, ok := toInt(options["port"])
	if !ok || port < 1 || port > 65535 {
		return nil, fmt.Errorf("http source requires valid 'port' option")
	}

	ingestPath := "/ingest"
	if path, ok := options["ingest_path"].(string); ok && path != "" {
		ingestPath = path
	}

	bufferSize := 1000
	if bufSize, ok := toInt(options["buffer_size"]); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	h := &HTTPSource{
		port:       port,
		ingestPath: ingestPath,
		bufferSize: bufferSize,
		done:       make(chan struct{}),
		startTime:  time.Now(),
		logger:     logger,
	}
	h.lastEntryTime.Store(time.Time{})

	// Initialize net limiter if configured
	if rl, ok := options["net_limit"].(map[string]any); ok {
		if enabled, _ := rl["enabled"].(bool); enabled {
			cfg := config.NetLimitConfig{
				Enabled: true,
			}

			if rps, ok := toFloat(rl["requests_per_second"]); ok {
				cfg.RequestsPerSecond = rps
			}
			if burst, ok := toInt(rl["burst_size"]); ok {
				cfg.BurstSize = burst
			}
			if limitBy, ok := rl["limit_by"].(string); ok {
				cfg.LimitBy = limitBy
			}
			if respCode, ok := toInt(rl["response_code"]); ok {
				cfg.ResponseCode = respCode
			}
			if msg, ok := rl["response_message"].(string); ok {
				cfg.ResponseMessage = msg
			}
			if maxPerIP, ok := toInt(rl["max_connections_per_ip"]); ok {
				cfg.MaxConnectionsPerIP = maxPerIP
			}

			h.netLimiter = netlimit.New(cfg, logger)
		}
	}

	return h, nil
}

func (h *HTTPSource) Subscribe() <-chan LogEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan LogEntry, h.bufferSize)
	h.subscribers = append(h.subscribers, ch)
	return ch
}

func (h *HTTPSource) Start() error {
	h.server = &fasthttp.Server{
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		CloseOnShutdown:   true,
	}

	addr := fmt.Sprintf(":%d", h.port)

	// Start server in background
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.logger.Info("msg", "HTTP source server starting",
			"component", "http_source",
			"port", h.port,
			"ingest_path", h.ingestPath)

		if err := h.server.ListenAndServe(addr); err != nil {
			h.logger.Error("msg", "HTTP source server failed",
				"component", "http_source",
				"port", h.port,
				"error", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	return nil
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
			"ingest_path":     h.ingestPath,
			"invalid_entries": h.invalidEntries.Load(),
			"net_limit":       netLimitStats,
		},
	}
}

func (h *HTTPSource) requestHandler(ctx *fasthttp.RequestCtx) {
	// Only handle POST to the configured ingest path
	if string(ctx.Method()) != "POST" || string(ctx.Path()) != h.ingestPath {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Not Found",
			"hint":  fmt.Sprintf("POST logs to %s", h.ingestPath),
		})
		return
	}

	// Check net limit
	remoteAddr := ctx.RemoteAddr().String()
	if h.netLimiter != nil {
		if allowed, statusCode, message := h.netLimiter.CheckHTTP(remoteAddr); !allowed {
			ctx.SetStatusCode(statusCode)
			ctx.SetContentType("application/json")
			json.NewEncoder(ctx).Encode(map[string]any{
				"error":       message,
				"retry_after": "60",
			})
			return
		}
	}

	// Process the request body
	body := ctx.PostBody()
	if len(body) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Empty request body",
		})
		return
	}

	// Parse the log entries
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

	// Publish entries
	accepted := 0
	for _, entry := range entries {
		if h.publish(entry) {
			accepted++
		}
	}

	// Return success response
	ctx.SetStatusCode(fasthttp.StatusAccepted)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]any{
		"accepted": accepted,
		"total":    len(entries),
	})
}

func (h *HTTPSource) parseEntries(body []byte) ([]LogEntry, error) {
	var entries []LogEntry

	// Try to parse as single JSON object first
	var single LogEntry
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
		entries = append(entries, single)
		return entries, nil
	}

	// Try to parse as JSON array
	var array []LogEntry
	if err := json.Unmarshal(body, &array); err == nil {
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
		}
		return array, nil
	}

	// Try to parse as newline-delimited JSON
	lines := splitLines(body)
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}

		var entry LogEntry
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

		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no valid log entries found")
	}

	return entries, nil
}

func (h *HTTPSource) publish(entry LogEntry) bool {
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

// splitLines splits bytes into lines, handling both \n and \r\n
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

// Helper function for type conversion
func toFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	default:
		return 0, false
	}
}