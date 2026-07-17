package httpchain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/sink"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSink("http_chain", NewHTTPChainSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register http_chain sink: %v", err))
	}
}

const (
	DefaultHTTPChainSinkBufferSize       = 1000
	DefaultHTTPChainSinkIngestPath       = "/ingest"
	DefaultHTTPChainSinkMaxBatchCount    = 100
	DefaultHTTPChainSinkMaxBatchBytes    = 1024 * 1024
	DefaultHTTPChainSinkFlushIntervalMS  = 1000
	DefaultHTTPChainSinkRequestTimeoutMS = 10000
	DefaultHTTPChainSinkBackoffMinMS     = 500
	DefaultHTTPChainSinkBackoffMaxMS     = 30000
)

// HTTPChainSink batches structured entries and posts NDJSON to a downstream
// http_chain source. Delivery is at-least-once per batch.
type HTTPChainSink struct {
	id      string
	proxy   *session.Proxy
	session *session.Session
	config  *config.HTTPChainSinkOptions

	node string
	url  string

	client *http.Client
	input  chan core.TransportEvent
	logger *log.Logger

	// Batch state owned exclusively by run loop goroutine
	batch      bytes.Buffer
	batchCount int64

	reqTimeout time.Duration
	done       chan struct{}
	wg         sync.WaitGroup
	startTime  time.Time

	totalProcessed atomic.Uint64
	batchesSent    atomic.Uint64
	requestErrors  atomic.Uint64
	droppedBatches atomic.Uint64
	synthesized    atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

// NewHTTPChainSinkPlugin creates an http_chain sink through plugin factory
func NewHTTPChainSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.HTTPChainSinkOptions{}
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := lconfig.NonEmpty(opts.Host); err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if err := lconfig.Port(opts.Port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	if opts.IngestPath == "" {
		opts.IngestPath = DefaultHTTPChainSinkIngestPath
	} else if !strings.HasPrefix(opts.IngestPath, "/") {
		return nil, fmt.Errorf("ingest_path: must start with '/'")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultHTTPChainSinkBufferSize
	}
	if opts.MaxBatchCount <= 0 {
		opts.MaxBatchCount = DefaultHTTPChainSinkMaxBatchCount
	}
	if opts.MaxBatchBytes <= 0 {
		opts.MaxBatchBytes = DefaultHTTPChainSinkMaxBatchBytes
	}
	if opts.FlushIntervalMS <= 0 {
		opts.FlushIntervalMS = DefaultHTTPChainSinkFlushIntervalMS
	}
	if opts.RequestTimeoutMS <= 0 {
		opts.RequestTimeoutMS = DefaultHTTPChainSinkRequestTimeoutMS
	}
	if opts.BackoffMinMS <= 0 {
		opts.BackoffMinMS = DefaultHTTPChainSinkBackoffMinMS
	}
	if opts.BackoffMaxMS < opts.BackoffMinMS {
		opts.BackoffMaxMS = DefaultHTTPChainSinkBackoffMaxMS
	}

	node := opts.Node
	if node == "" {
		if hn, err := os.Hostname(); err == nil {
			node = hn
		} else {
			node = "unknown"
		}
	}

	addr := net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10))

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// IPv4-only, aligns with tcp/http sinks
			d := net.Dialer{}
			return d.DialContext(ctx, "tcp4", address)
		},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		// Future: TLSClientConfig; HTTP/2 via ALPN once TLS lands
	}

	t := &HTTPChainSink{
		id:     id,
		proxy:  proxy,
		config: opts,
		node:   node,
		// Future: "https" scheme with TLS
		url:        "http://" + addr + opts.IngestPath,
		client:     &http.Client{Transport: transport},
		input:      make(chan core.TransportEvent, opts.BufferSize),
		done:       make(chan struct{}),
		logger:     logger,
		reqTimeout: time.Duration(opts.RequestTimeoutMS) * time.Millisecond,
	}
	t.lastProcessed.Store(time.Time{})

	t.session = proxy.CreateSession(
		"http_chain://"+addr,
		map[string]any{
			"instance_id": id,
			"type":        "http_chain",
			"target":      t.url,
			"node":        node,
		},
	)

	logger.Info("msg", "HTTP chain sink initialized",
		"component", "http_chain_sink",
		"instance_id", id,
		"target", t.url,
		"node", node)
	return t, nil
}

// Capabilities returns supported capabilities
func (t *HTTPChainSink) Capabilities() []core.Capability {
	// CapTLS/CapAuth added when transport security lands
	return []core.Capability{
		core.CapSessionAware,
	}
}

// Input returns the channel for sending transport events
func (t *HTTPChainSink) Input() chan<- core.TransportEvent {
	return t.input
}

// Start launches the batching loop; downstream availability is not required
func (t *HTTPChainSink) Start(ctx context.Context) error {
	t.startTime = time.Now()
	t.wg.Add(1)
	go t.runLoop(ctx)

	t.logger.Info("msg", "HTTP chain sink started",
		"component", "http_chain_sink",
		"instance_id", t.id,
		"target", t.url)
	return nil
}

// Stop terminates the loop. Worst case: one in-flight request timeout plus
// one final-flush request timeout.
func (t *HTTPChainSink) Stop() {
	t.logger.Info("msg", "Stopping HTTP chain sink",
		"component", "http_chain_sink",
		"instance_id", t.id)

	close(t.done)
	t.wg.Wait()
	t.client.CloseIdleConnections()

	if t.session != nil {
		t.proxy.RemoveSession(t.session.ID)
	}

	t.logger.Info("msg", "HTTP chain sink stopped",
		"component", "http_chain_sink",
		"instance_id", t.id,
		"total_processed", t.totalProcessed.Load())
}

// GetStats returns sink statistics
func (t *HTTPChainSink) GetStats() sink.SinkStats {
	lastProc, _ := t.lastProcessed.Load().(time.Time)
	return sink.SinkStats{
		ID:             t.id,
		Type:           "http_chain",
		TotalProcessed: t.totalProcessed.Load(),
		StartTime:      t.startTime,
		LastProcessed:  lastProc,
		Details: map[string]any{
			"target":          t.url,
			"node":            t.node,
			"batches_sent":    t.batchesSent.Load(),
			"request_errors":  t.requestErrors.Load(),
			"dropped_batches": t.droppedBatches.Load(),
			"synthesized":     t.synthesized.Load(),
		},
	}
}

// runLoop batches events and flushes on size or interval
func (t *HTTPChainSink) runLoop(ctx context.Context) {
	defer t.wg.Done()

	// Fold done channel into a context for request/backoff interruption
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-t.done:
			cancel()
		case <-runCtx.Done():
		}
	}()

	ticker := time.NewTicker(time.Duration(t.config.FlushIntervalMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			t.finalFlush()
			return
		case <-ticker.C:
			if t.batchCount > 0 && !t.flush(runCtx) {
				t.finalFlush()
				return
			}
		case event, ok := <-t.input:
			if !ok {
				t.finalFlush()
				return
			}
			t.append(event)
			if t.batchCount >= t.config.MaxBatchCount ||
				int64(t.batch.Len()) >= t.config.MaxBatchBytes {
				if !t.flush(runCtx) {
					t.finalFlush()
					return
				}
			}
		}
	}
}

// append serializes one event into the pending batch
func (t *HTTPChainSink) append(event core.TransportEvent) {
	entry, synthesized := chain.EntryFromEvent(event, t.node, t.id)
	if synthesized {
		t.synthesized.Add(1)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		// Non-transient: drop entry
		t.logger.Error("msg", "Failed to marshal chain entry",
			"component", "http_chain_sink",
			"error", err)
		return
	}
	t.batch.Write(line)
	t.batch.WriteByte('\n')
	t.batchCount++
}

// flush delivers the pending batch, retrying transient failures with backoff.
// Returns false when shutdown interrupts delivery; undelivered batch is dropped
// by finalFlush semantics (batch already consumed here).
func (t *HTTPChainSink) flush(ctx context.Context) bool {
	body := bytes.Clone(t.batch.Bytes())
	count := t.batchCount
	t.batch.Reset()
	t.batchCount = 0

	failures := 0
	for {
		if failures > 0 && !t.waitBackoff(ctx, failures) {
			t.droppedBatches.Add(1)
			return false
		}
		transient, err := t.post(ctx, body)
		if err == nil {
			t.batchesSent.Add(1)
			t.totalProcessed.Add(uint64(count))
			t.lastProcessed.Store(time.Now())
			t.proxy.UpdateActivity(t.session.ID)
			return true
		}
		t.requestErrors.Add(1)
		if !transient {
			t.droppedBatches.Add(1)
			t.logger.Error("msg", "Chain batch rejected, dropping",
				"component", "http_chain_sink",
				"target", t.url,
				"entries", count,
				"error", err)
			return true
		}
		if ctx.Err() != nil {
			t.droppedBatches.Add(1)
			return false
		}
		failures++
		t.logger.Warn("msg", "Chain batch delivery failed",
			"component", "http_chain_sink",
			"target", t.url,
			"attempt", failures,
			"error", err)
	}
}

// finalFlush best-effort delivers the pending batch during shutdown (single attempt)
func (t *HTTPChainSink) finalFlush() {
	if t.batchCount == 0 {
		return
	}
	fctx, cancel := context.WithTimeout(context.Background(), t.reqTimeout)
	defer cancel()

	count := t.batchCount
	if _, err := t.post(fctx, t.batch.Bytes()); err != nil {
		t.droppedBatches.Add(1)
		t.logger.Warn("msg", "Final chain batch dropped on shutdown",
			"component", "http_chain_sink",
			"entries", count,
			"error", err)
		return
	}
	t.batchesSent.Add(1)
	t.totalProcessed.Add(uint64(count))
}

// post sends one NDJSON batch; transient=true marks retryable failures
func (t *HTTPChainSink) post(ctx context.Context, body []byte) (transient bool, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, t.reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", chain.ContentTypeNDJSON)
	req.Header.Set(chain.HeaderProtocol, strconv.Itoa(chain.ProtocolVersion))
	req.Header.Set(chain.HeaderNode, t.node)
	// Future: Authorization header for auth

	resp, err := t.client.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	// Drain for connection reuse
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusRequestTimeout,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return true, fmt.Errorf("status %s", resp.Status)
	default:
		return false, fmt.Errorf("status %s", resp.Status)
	}
}

// waitBackoff sleeps for the computed delay, interruptible by shutdown
func (t *HTTPChainSink) waitBackoff(ctx context.Context, failures int) bool {
	minD := time.Duration(t.config.BackoffMinMS) * time.Millisecond
	maxD := time.Duration(t.config.BackoffMaxMS) * time.Millisecond
	timer := time.NewTimer(chain.BackoffDelay(minD, maxD, failures))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
