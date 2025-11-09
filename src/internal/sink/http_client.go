// FILE: logwisp/src/internal/sink/http_client.go
package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	"logwisp/src/internal/session"
	ltls "logwisp/src/internal/tls"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// TODO: add heartbeat
// HTTPClientSink forwards log entries to a remote HTTP endpoint.
type HTTPClientSink struct {
	// Configuration
	config *config.HTTPClientSinkOptions

	// Network
	client     *fasthttp.Client
	tlsManager *ltls.ClientManager

	// Application
	input     chan core.LogEntry
	formatter format.Formatter
	logger    *log.Logger

	// Runtime
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time

	// Batching
	batch   []core.LogEntry
	batchMu sync.Mutex

	// Security & Session
	sessionID      string
	sessionManager *session.Manager

	// Statistics
	totalProcessed    atomic.Uint64
	totalBatches      atomic.Uint64
	failedBatches     atomic.Uint64
	lastProcessed     atomic.Value // time.Time
	lastBatchSent     atomic.Value // time.Time
	activeConnections atomic.Int64
}

// NewHTTPClientSink creates a new HTTP client sink.
func NewHTTPClientSink(opts *config.HTTPClientSinkOptions, logger *log.Logger, formatter format.Formatter) (*HTTPClientSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("HTTP client sink options cannot be nil")
	}

	h := &HTTPClientSink{
		config:         opts,
		input:          make(chan core.LogEntry, opts.BufferSize),
		batch:          make([]core.LogEntry, 0, opts.BatchSize),
		done:           make(chan struct{}),
		startTime:      time.Now(),
		logger:         logger,
		formatter:      formatter,
		sessionManager: session.NewManager(30 * time.Minute),
	}
	h.lastProcessed.Store(time.Time{})
	h.lastBatchSent.Store(time.Time{})

	// Create fasthttp client
	h.client = &fasthttp.Client{
		MaxConnsPerHost:               10,
		MaxIdleConnDuration:           10 * time.Second,
		ReadTimeout:                   time.Duration(opts.Timeout) * time.Second,
		WriteTimeout:                  time.Duration(opts.Timeout) * time.Second,
		DisableHeaderNamesNormalizing: true,
	}

	// Configure TLS for HTTPS
	if strings.HasPrefix(opts.URL, "https://") {
		if opts.TLS != nil && opts.TLS.Enabled {
			// Use the new ClientManager with the clear client-specific config
			tlsManager, err := ltls.NewClientManager(opts.TLS, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS client manager: %w", err)
			}
			h.tlsManager = tlsManager
			// Get the generated config
			h.client.TLSConfig = tlsManager.GetConfig()

			logger.Info("msg", "Client TLS configured",
				"component", "http_client_sink",
				"has_client_cert", opts.TLS.ClientCertFile != "", // Clearer check
				"has_server_ca", opts.TLS.ServerCAFile != "", // Clearer check
				"min_version", opts.TLS.MinVersion)
		} else if opts.InsecureSkipVerify { // Use the new clear field
			// TODO: document this behavior
			h.client.TLSConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
	}

	return h, nil
}

// Input returns the channel for sending log entries.
func (h *HTTPClientSink) Input() chan<- core.LogEntry {
	return h.input
}

// Start begins the processing and batching loops.
func (h *HTTPClientSink) Start(ctx context.Context) error {
	// Create session for HTTP client sink lifetime
	sess := h.sessionManager.CreateSession(h.config.URL, "http_client_sink", map[string]any{
		"batch_size": h.config.BatchSize,
		"timeout":    h.config.Timeout,
	})
	h.sessionID = sess.ID

	h.wg.Add(2)
	go h.processLoop(ctx)
	go h.batchTimer(ctx)

	h.logger.Info("msg", "HTTP client sink started",
		"component", "http_client_sink",
		"url", h.config.URL,
		"batch_size", h.config.BatchSize,
		"batch_delay_ms", h.config.BatchDelayMS,
		"session_id", h.sessionID)
	return nil
}

// Stop gracefully shuts down the sink, sending any remaining batched entries.
func (h *HTTPClientSink) Stop() {
	h.logger.Info("msg", "Stopping HTTP client sink")
	close(h.done)
	h.wg.Wait()

	// Send any remaining batched entries
	h.batchMu.Lock()
	if len(h.batch) > 0 {
		batch := h.batch
		h.batch = make([]core.LogEntry, 0, h.config.BatchSize)
		h.batchMu.Unlock()
		h.sendBatch(batch)
	} else {
		h.batchMu.Unlock()
	}

	// Remove session and stop manager
	if h.sessionID != "" {
		h.sessionManager.RemoveSession(h.sessionID)
	}
	if h.sessionManager != nil {
		h.sessionManager.Stop()
	}

	h.logger.Info("msg", "HTTP client sink stopped",
		"total_processed", h.totalProcessed.Load(),
		"total_batches", h.totalBatches.Load(),
		"failed_batches", h.failedBatches.Load())
}

// GetStats returns the sink's statistics.
func (h *HTTPClientSink) GetStats() SinkStats {
	lastProc, _ := h.lastProcessed.Load().(time.Time)
	lastBatch, _ := h.lastBatchSent.Load().(time.Time)

	h.batchMu.Lock()
	pendingEntries := len(h.batch)
	h.batchMu.Unlock()

	// Get session information
	var sessionInfo map[string]any
	if h.sessionID != "" {
		if sess, exists := h.sessionManager.GetSession(h.sessionID); exists {
			sessionInfo = map[string]any{
				"session_id":    sess.ID,
				"created_at":    sess.CreatedAt,
				"last_activity": sess.LastActivity,
			}
		}
	}

	var tlsStats map[string]any
	if h.tlsManager != nil {
		tlsStats = h.tlsManager.GetStats()
	}

	return SinkStats{
		Type:              "http_client",
		TotalProcessed:    h.totalProcessed.Load(),
		ActiveConnections: h.activeConnections.Load(),
		StartTime:         h.startTime,
		LastProcessed:     lastProc,
		Details: map[string]any{
			"url":             h.config.URL,
			"batch_size":      h.config.BatchSize,
			"pending_entries": pendingEntries,
			"total_batches":   h.totalBatches.Load(),
			"failed_batches":  h.failedBatches.Load(),
			"last_batch_sent": lastBatch,
			"session":         sessionInfo,
			"tls":             tlsStats,
		},
	}
}

// processLoop collects incoming log entries into a batch.
func (h *HTTPClientSink) processLoop(ctx context.Context) {
	defer h.wg.Done()

	for {
		select {
		case entry, ok := <-h.input:
			if !ok {
				return
			}

			h.totalProcessed.Add(1)
			h.lastProcessed.Store(time.Now())

			// Add to batch
			h.batchMu.Lock()
			h.batch = append(h.batch, entry)

			// Check if batch is full
			if int64(len(h.batch)) >= h.config.BatchSize {
				batch := h.batch
				h.batch = make([]core.LogEntry, 0, h.config.BatchSize)
				h.batchMu.Unlock()

				// Send batch in background
				go h.sendBatch(batch)
			} else {
				h.batchMu.Unlock()
			}

		case <-ctx.Done():
			return
		case <-h.done:
			return
		}
	}
}

// batchTimer periodically triggers sending of the current batch.
func (h *HTTPClientSink) batchTimer(ctx context.Context) {
	defer h.wg.Done()

	ticker := time.NewTicker(time.Duration(h.config.BatchDelayMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.batchMu.Lock()
			if len(h.batch) > 0 {
				batch := h.batch
				h.batch = make([]core.LogEntry, 0, h.config.BatchSize)
				h.batchMu.Unlock()

				// Send batch in background
				go h.sendBatch(batch)
			} else {
				h.batchMu.Unlock()
			}

		case <-ctx.Done():
			return
		case <-h.done:
			return
		}
	}
}

// sendBatch sends a batch of log entries to the remote endpoint with retry logic.
func (h *HTTPClientSink) sendBatch(batch []core.LogEntry) {
	h.activeConnections.Add(1)
	defer h.activeConnections.Add(-1)

	h.totalBatches.Add(1)
	h.lastBatchSent.Store(time.Now())

	// Special handling for JSON formatter with batching
	var body []byte
	var err error

	if jsonFormatter, ok := h.formatter.(*format.JSONFormatter); ok {
		// Use the batch formatting method
		body, err = jsonFormatter.FormatBatch(batch)
	} else {
		// For non-JSON formatters, format each entry and combine
		var formatted [][]byte
		for _, entry := range batch {
			entryBytes, err := h.formatter.Format(entry)
			if err != nil {
				h.logger.Error("msg", "Failed to format entry in batch",
					"component", "http_client_sink",
					"error", err)
				continue
			}
			formatted = append(formatted, entryBytes)
		}

		// For raw/text formats, join with newlines
		body = bytes.Join(formatted, nil)
	}

	if err != nil {
		h.logger.Error("msg", "Failed to format batch",
			"component", "http_client_sink",
			"error", err,
			"batch_size", len(batch))
		h.failedBatches.Add(1)
		return
	}

	// Retry logic
	var lastErr error
	retryDelay := time.Duration(h.config.RetryDelayMS) * time.Millisecond

	for attempt := int64(0); attempt <= h.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			time.Sleep(retryDelay)

			// Calculate new delay with overflow protection
			newDelay := time.Duration(float64(retryDelay) * h.config.RetryBackoff)

			// Cap at maximum to prevent integer overflow
			timeout := time.Duration(h.config.Timeout) * time.Second
			if newDelay > timeout || newDelay < retryDelay {
				// Either exceeded max or overflowed (negative/wrapped)
				retryDelay = timeout
			} else {
				retryDelay = newDelay
			}
		}

		// Acquire resources inside loop, release immediately after use
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(h.config.URL)
		req.Header.SetMethod("POST")
		req.Header.SetContentType("application/json")
		req.SetBody(body)

		req.Header.Set("User-Agent", fmt.Sprintf("LogWisp/%s", version.Short()))

		// Send request
		err := h.client.DoTimeout(req, resp, time.Duration(h.config.Timeout)*time.Second)

		// Capture response before releasing
		statusCode := resp.StatusCode()
		var responseBody []byte
		if len(resp.Body()) > 0 {
			responseBody = make([]byte, len(resp.Body()))
			copy(responseBody, resp.Body())
		}

		// Release immediately, not deferred
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		// Handle errors
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			h.logger.Warn("msg", "HTTP request failed",
				"component", "http_client_sink",
				"attempt", attempt+1,
				"max_retries", h.config.MaxRetries,
				"error", err)
			continue
		}

		// Check response status
		if statusCode >= 200 && statusCode < 300 {
			// Success

			// Update session activity on successful batch send
			if h.sessionID != "" {
				h.sessionManager.UpdateActivity(h.sessionID)
			}

			h.logger.Debug("msg", "Batch sent successfully",
				"component", "http_client_sink",
				"batch_size", len(batch),
				"status_code", statusCode,
				"attempt", attempt+1)
			return
		}

		// Non-2xx status
		lastErr = fmt.Errorf("server returned status %d: %s", statusCode, responseBody)

		// Don't retry on 4xx errors (client errors)
		if statusCode >= 400 && statusCode < 500 {
			h.logger.Error("msg", "Batch rejected by server",
				"component", "http_client_sink",
				"status_code", statusCode,
				"response", string(responseBody),
				"batch_size", len(batch))
			h.failedBatches.Add(1)
			return
		}

		h.logger.Warn("msg", "Server returned error status",
			"component", "http_client_sink",
			"attempt", attempt+1,
			"status_code", statusCode,
			"response", string(responseBody))
	}

	// All retries exhausted
	h.logger.Error("msg", "Failed to send batch after all retries",
		"component", "http_client_sink",
		"batch_size", len(batch),
		"retries", h.config.MaxRetries,
		"last_error", lastErr)
	h.failedBatches.Add(1)
}