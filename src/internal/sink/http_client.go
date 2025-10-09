// FILE: logwisp/src/internal/sink/http_client.go
package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/format"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// Forwards log entries to a remote HTTP endpoint
type HTTPClientSink struct {
	input         chan core.LogEntry
	config        *config.HTTPClientSinkOptions
	client        *fasthttp.Client
	batch         []core.LogEntry
	batchMu       sync.Mutex
	done          chan struct{}
	wg            sync.WaitGroup
	startTime     time.Time
	logger        *log.Logger
	formatter     format.Formatter
	authenticator *auth.Authenticator

	// Statistics
	totalProcessed    atomic.Uint64
	totalBatches      atomic.Uint64
	failedBatches     atomic.Uint64
	lastProcessed     atomic.Value // time.Time
	lastBatchSent     atomic.Value // time.Time
	activeConnections atomic.Int64
}

// Creates a new HTTP client sink
func NewHTTPClientSink(opts *config.HTTPClientSinkOptions, logger *log.Logger, formatter format.Formatter) (*HTTPClientSink, error) {
	if opts == nil {
		return nil, fmt.Errorf("HTTP client sink options cannot be nil")
	}

	h := &HTTPClientSink{
		config:    opts,
		input:     make(chan core.LogEntry, opts.BufferSize),
		batch:     make([]core.LogEntry, 0, opts.BatchSize),
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
		ReadTimeout:                   time.Duration(opts.Timeout) * time.Second,
		WriteTimeout:                  time.Duration(opts.Timeout) * time.Second,
		DisableHeaderNamesNormalizing: true,
	}

	// Configure TLS if using HTTPS
	if strings.HasPrefix(opts.URL, "https://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
		}

		// Use TLS config if provided
		if opts.TLS != nil {
			// Load custom CA for server verification
			if opts.TLS.CAFile != "" {
				caCert, err := os.ReadFile(opts.TLS.CAFile)
				if err != nil {
					return nil, fmt.Errorf("failed to read CA file '%s': %w", opts.TLS.CAFile, err)
				}
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					return nil, fmt.Errorf("failed to parse CA certificate from '%s'", opts.TLS.CAFile)
				}
				tlsConfig.RootCAs = caCertPool
				logger.Debug("msg", "Custom CA loaded for server verification",
					"component", "http_client_sink",
					"ca_file", opts.TLS.CAFile)
			}

			// Load client certificate for mTLS if provided
			if opts.TLS.CertFile != "" && opts.TLS.KeyFile != "" {
				cert, err := tls.LoadX509KeyPair(opts.TLS.CertFile, opts.TLS.KeyFile)
				if err != nil {
					return nil, fmt.Errorf("failed to load client certificate: %w", err)
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
				logger.Info("msg", "Client certificate loaded for mTLS",
					"component", "http_client_sink",
					"cert_file", opts.TLS.CertFile)
			}
		}

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
		"batch_delay_ms", h.config.BatchDelayMS)
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

	// TODO: verify retry loop placement is correct or should it be after acquiring resources (req :=....)
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

		// Add authentication based on auth type
		switch h.config.Auth.Type {
		case "basic":
			creds := h.config.Auth.Username + ":" + h.config.Auth.Password
			encodedCreds := base64.StdEncoding.EncodeToString([]byte(creds))
			req.Header.Set("Authorization", "Basic "+encodedCreds)

		case "token":
			req.Header.Set("Authorization", "Token "+h.config.Auth.Token)

		case "mtls":
			// mTLS auth is handled at TLS layer via client certificates
			// No Authorization header needed

		case "none":
			// No authentication
		}

		// Set headers
		for k, v := range h.config.Headers {
			req.Header.Set(k, v)
		}

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