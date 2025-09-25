// FILE: logwisp/src/internal/sink/http_client.go
package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/core"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// HTTPClientSink forwards log entries to a remote HTTP endpoint
type HTTPClientSink struct {
	input     chan core.LogEntry
	config    HTTPClientConfig
	client    *fasthttp.Client
	batch     []core.LogEntry
	batchMu   sync.Mutex
	done      chan struct{}
	wg        sync.WaitGroup
	startTime time.Time
	logger    *log.Logger
	formatter format.Formatter

	// Statistics
	totalProcessed    atomic.Uint64
	totalBatches      atomic.Uint64
	failedBatches     atomic.Uint64
	lastProcessed     atomic.Value // time.Time
	lastBatchSent     atomic.Value // time.Time
	activeConnections atomic.Int64
}

// HTTPClientConfig holds HTTP client sink configuration
type HTTPClientConfig struct {
	URL        string
	BufferSize int64
	BatchSize  int64
	BatchDelay time.Duration
	Timeout    time.Duration
	Headers    map[string]string

	// Retry configuration
	MaxRetries   int64
	RetryDelay   time.Duration
	RetryBackoff float64 // Multiplier for exponential backoff

	// TLS configuration
	InsecureSkipVerify bool
	CAFile             string
	CertFile           string
	KeyFile            string
}

// NewHTTPClientSink creates a new HTTP client sink
func NewHTTPClientSink(options map[string]any, logger *log.Logger, formatter format.Formatter) (*HTTPClientSink, error) {
	cfg := HTTPClientConfig{
		BufferSize:   int64(1000),
		BatchSize:    int64(100),
		BatchDelay:   time.Second,
		Timeout:      30 * time.Second,
		MaxRetries:   int64(3),
		RetryDelay:   time.Second,
		RetryBackoff: float64(2.0),
		Headers:      make(map[string]string),
	}

	// Extract URL
	urlStr, ok := options["url"].(string)
	if !ok || urlStr == "" {
		return nil, fmt.Errorf("http_client sink requires 'url' option")
	}

	// Validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}
	cfg.URL = urlStr

	// Extract other options
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		cfg.BufferSize = bufSize
	}
	if batchSize, ok := options["batch_size"].(int64); ok && batchSize > 0 {
		cfg.BatchSize = batchSize
	}
	if delayMs, ok := options["batch_delay_ms"].(int64); ok && delayMs > 0 {
		cfg.BatchDelay = time.Duration(delayMs) * time.Millisecond
	}
	if timeoutSec, ok := options["timeout_seconds"].(int64); ok && timeoutSec > 0 {
		cfg.Timeout = time.Duration(timeoutSec) * time.Second
	}
	if maxRetries, ok := options["max_retries"].(int64); ok && maxRetries >= 0 {
		cfg.MaxRetries = maxRetries
	}
	if retryDelayMs, ok := options["retry_delay_ms"].(int64); ok && retryDelayMs > 0 {
		cfg.RetryDelay = time.Duration(retryDelayMs) * time.Millisecond
	}
	if backoff, ok := options["retry_backoff"].(float64); ok && backoff >= 1.0 {
		cfg.RetryBackoff = backoff
	}
	if insecure, ok := options["insecure_skip_verify"].(bool); ok {
		cfg.InsecureSkipVerify = insecure
	}

	// Extract headers
	if headers, ok := options["headers"].(map[string]any); ok {
		for k, v := range headers {
			if strVal, ok := v.(string); ok {
				cfg.Headers[k] = strVal
			}
		}
	}

	// Set default Content-Type if not specified
	if _, exists := cfg.Headers["Content-Type"]; !exists {
		cfg.Headers["Content-Type"] = "application/json"
	}

	// Extract TLS options
	if caFile, ok := options["ca_file"].(string); ok && caFile != "" {
		cfg.CAFile = caFile
	}

	// Extract client certificate options from TLS config
	if tc, ok := options["tls"].(map[string]any); ok {
		if enabled, _ := tc["enabled"].(bool); enabled {
			// Extract client certificate files for mTLS
			if certFile, ok := tc["cert_file"].(string); ok && certFile != "" {
				if keyFile, ok := tc["key_file"].(string); ok && keyFile != "" {
					// These will be used below when configuring TLS
					cfg.CertFile = certFile // Need to add these fields to HTTPClientConfig
					cfg.KeyFile = keyFile
				}
			}
			// Extract CA file from TLS config if not already set
			if cfg.CAFile == "" {
				if caFile, ok := tc["ca_file"].(string); ok {
					cfg.CAFile = caFile
				}
			}
			// Extract insecure skip verify from TLS config
			if insecure, ok := tc["insecure_skip_verify"].(bool); ok {
				cfg.InsecureSkipVerify = insecure
			}
		}
	}

	h := &HTTPClientSink{
		input:     make(chan core.LogEntry, cfg.BufferSize),
		config:    cfg,
		batch:     make([]core.LogEntry, 0, cfg.BatchSize),
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
		formatter: formatter,
	}
	h.lastProcessed.Store(time.Time{})
	h.lastBatchSent.Store(time.Time{})

	// Create fasthttp client
	h.client = &fasthttp.Client{
		MaxConnsPerHost:               10,
		MaxIdleConnDuration:           10 * time.Second,
		ReadTimeout:                   cfg.Timeout,
		WriteTimeout:                  cfg.Timeout,
		DisableHeaderNamesNormalizing: true,
	}

	// Configure TLS if using HTTPS
	if strings.HasPrefix(cfg.URL, "https://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}

		// Load custom CA for server verification if provided
		if cfg.CAFile != "" {
			caCert, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file '%s': %w", cfg.CAFile, err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate from '%s'", cfg.CAFile)
			}
			tlsConfig.RootCAs = caCertPool
			logger.Debug("msg", "Custom CA loaded for server verification",
				"component", "http_client_sink",
				"ca_file", cfg.CAFile)
		}

		// Load client certificate for mTLS if provided
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
			logger.Info("msg", "Client certificate loaded for mTLS",
				"component", "http_client_sink",
				"cert_file", cfg.CertFile)
		}

		// Set TLS config directly on the client
		h.client.TLSConfig = tlsConfig
	}

	return h, nil
}

func (h *HTTPClientSink) Input() chan<- core.LogEntry {
	return h.input
}

func (h *HTTPClientSink) Start(ctx context.Context) error {
	h.wg.Add(2)
	go h.processLoop(ctx)
	go h.batchTimer(ctx)

	h.logger.Info("msg", "HTTP client sink started",
		"component", "http_client_sink",
		"url", h.config.URL,
		"batch_size", h.config.BatchSize,
		"batch_delay", h.config.BatchDelay)
	return nil
}

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

	h.logger.Info("msg", "HTTP client sink stopped",
		"total_processed", h.totalProcessed.Load(),
		"total_batches", h.totalBatches.Load(),
		"failed_batches", h.failedBatches.Load())
}

func (h *HTTPClientSink) GetStats() SinkStats {
	lastProc, _ := h.lastProcessed.Load().(time.Time)
	lastBatch, _ := h.lastBatchSent.Load().(time.Time)

	h.batchMu.Lock()
	pendingEntries := len(h.batch)
	h.batchMu.Unlock()

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
		},
	}
}

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

func (h *HTTPClientSink) batchTimer(ctx context.Context) {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.BatchDelay)
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
	retryDelay := h.config.RetryDelay

	for attempt := int64(0); attempt <= h.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			time.Sleep(retryDelay)

			// Calculate new delay with overflow protection
			newDelay := time.Duration(float64(retryDelay) * h.config.RetryBackoff)

			// Cap at maximum to prevent integer overflow
			if newDelay > h.config.Timeout || newDelay < retryDelay {
				// Either exceeded max or overflowed (negative/wrapped)
				retryDelay = h.config.Timeout
			} else {
				retryDelay = newDelay
			}
		}

		// Acquire resources inside loop, release immediately after use
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(h.config.URL)
		req.Header.SetMethod("POST")
		req.SetBody(body)

		// Set headers
		for k, v := range h.config.Headers {
			req.Header.Set(k, v)
		}

		// Send request
		err := h.client.DoTimeout(req, resp, h.config.Timeout)

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