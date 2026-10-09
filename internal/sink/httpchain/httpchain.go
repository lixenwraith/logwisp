package httpchain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/tlsx"

	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSink("http_chain", NewHTTPChainSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register http_chain sink: %v", err))
	}
}

const (
	maxResponseDrain = 64 * 1024
)

// HTTPChainSink batches structured entries and posts NDJSON to a downstream
// http_chain source. Delivery is at-least-once per batch.
type HTTPChainSink struct {
	id      string
	proxy   *session.Proxy
	session *session.Session
	config  *config.HTTPChainSinkOptions

	node    string
	baseURL string // scheme://host:port, where /auth lives
	url     string

	tlsEnabled bool
	mtls       bool

	// Authorization: pins the downstream server's identity
	auth *authz.Policy

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
	opts, err := config.Decode[config.HTTPChainSinkOptions]("sink", "http_chain", configMap)
	if err != nil {
		return nil, err
	}
	network, err := core.Network(opts.Host)
	if err != nil {
		return nil, err
	}

	node := opts.Node
	if node == "" {
		if hn, err := os.Hostname(); err == nil {
			node = hn
		} else {
			node = "unknown"
		}
	}

	tlsCfg, err := tlsx.Client(opts.TLS, opts.Host)
	if err != nil {
		return nil, err
	}
	authPolicy, err := authz.New(opts.Auth, tlsCfg, nil, config.Dialer, authz.HTTP)
	if err != nil {
		return nil, err
	}
	if authPolicy.Enabled() {
		// Runs after the standard chain and hostname checks, so a server the
		// policy rejects fails the handshake instead of the first request
		tlsCfg.VerifyConnection = authPolicy.VerifyConnection
	}

	addr := net.JoinHostPort(opts.Host, strconv.FormatInt(opts.Port, 10))

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, address)
		},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     tlsCfg, // nil = plaintext
		TLSHandshakeTimeout: tlsx.HandshakeTimeout,
		// h2 stays off: custom DialContext disables auto-ALPN and batched
		// NDJSON POSTs gain nothing from it
	}

	base := url.URL{Scheme: "http", Host: addr} // escapes an IPv6 zone
	if tlsCfg != nil {
		base.Scheme = "https"
	}

	t := &HTTPChainSink{
		id:         id,
		proxy:      proxy,
		config:     opts,
		node:       node,
		tlsEnabled: tlsCfg != nil,
		mtls:       tlsCfg != nil && len(tlsCfg.Certificates) > 0,
		auth:       authPolicy,
		baseURL:    base.String(),
		url:        base.String() + opts.IngestPath,
		// A redirect would resend the batch, even from https to plaintext http
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
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
		"node", node,
		"tls", t.tlsEnabled,
		"mtls", t.mtls,
		"auth", authPolicy.Describe())
	tlsx.LogWarnings(logger, "http_chain_sink", id, opts.TLS, false)
	authPolicy.LogStartup(logger, "http_chain_sink", id, false)
	return t, nil
}

// Capabilities returns supported capabilities
func (t *HTTPChainSink) Capabilities() []core.Capability {
	caps := []core.Capability{core.CapSessionAware}
	if t.tlsEnabled {
		caps = append(caps, core.CapTLS)
	}
	if t.auth.Enabled() {
		caps = append(caps, core.CapAuth) // pins the server identity
	}
	return caps
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

// Stop delivers what is queued and batched within sink.FlushBound, then ends
// the loop
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
	details := map[string]any{
		"target":          t.url,
		"node":            t.node,
		"tls":             t.tlsEnabled,
		"batches_sent":    t.batchesSent.Load(),
		"request_errors":  t.requestErrors.Load(),
		"dropped_batches": t.droppedBatches.Load(),
		"synthesized":     t.synthesized.Load(),
	}
	maps.Copy(details, t.auth.Stats())

	return sink.SinkStats{
		ID:             t.id,
		Type:           "http_chain",
		TotalProcessed: t.totalProcessed.Load(),
		StartTime:      t.startTime,
		LastProcessed:  lastProc,
		Details:        details,
	}
}

// runLoop batches events and flushes on size or interval
func (t *HTTPChainSink) runLoop(ctx context.Context) {
	defer t.wg.Done()

	// Stop leaves sink.FlushBound to deliver the queue and the batch, so a
	// finite input arrives whole; a request or backoff in flight then ends,
	// and every later flush drops its batch at once
	ctx, cancel := sink.FlushContext(ctx, t.done, t.reqTimeout)
	defer cancel()

	ticker := time.NewTicker(time.Duration(t.config.FlushIntervalMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if t.batchCount > 0 {
				t.flush(ctx)
			}
		case event := <-t.input:
			if t.append(event) {
				t.flush(ctx)
			}
		case <-t.done:
			for len(t.input) > 0 {
				if t.append(<-t.input) {
					t.flush(ctx)
				}
			}
			if t.batchCount > 0 {
				t.flush(ctx)
			}
			return
		}
	}
}

// append serializes one event into the pending batch; true once it is full
func (t *HTTPChainSink) append(event core.TransportEvent) bool {
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
		return false
	}
	t.batch.Write(line)
	t.batch.WriteByte('\n')
	t.batchCount++
	return t.batchCount >= t.config.MaxBatchCount || int64(t.batch.Len()) >= t.config.MaxBatchBytes
}

// flush delivers the pending batch, retrying transient failures with backoff
// until shutdown drops it
func (t *HTTPChainSink) flush(ctx context.Context) {
	body := bytes.Clone(t.batch.Bytes())
	count := t.batchCount
	t.batch.Reset()
	t.batchCount = 0

	failures := 0
	for {
		if failures > 0 && !t.waitBackoff(ctx, failures) {
			break
		}
		transient, err := t.post(ctx, body)
		if err == nil {
			t.batchesSent.Add(1)
			t.totalProcessed.Add(uint64(count))
			t.lastProcessed.Store(time.Now())
			t.proxy.UpdateActivity(t.session.ID)
			return
		}
		t.requestErrors.Add(1)
		if !transient {
			t.droppedBatches.Add(1)
			t.logger.Error("msg", "Chain batch rejected, dropping",
				"component", "http_chain_sink",
				"target", t.url,
				"entries", count,
				"error", err)
			return
		}
		if ctx.Err() != nil {
			break
		}
		failures++
		t.logger.Warn("msg", "Chain batch delivery failed",
			"component", "http_chain_sink",
			"target", t.url,
			"attempt", failures,
			"error", err)
	}
	t.droppedBatches.Add(1)
	t.logger.Warn("msg", "Chain batch dropped on shutdown",
		"component", "http_chain_sink",
		"target", t.url,
		"entries", count)
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
	// Under scram: log in when no token is held; every failure is transient,
	// so the batch waits under backoff rather than being dropped
	if err := t.auth.Prepare(reqCtx, t.client, t.baseURL, req); err != nil {
		return true, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		t.auth.Invalidate(0, err) // another server certificate: log in anew
		return true, err
	}
	defer resp.Body.Close()
	// Drain for connection reuse, bounded so a hostile peer cannot stream forever
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseDrain))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case t.auth.Invalidate(resp.StatusCode, nil):
		// Token expired or the source reloaded; the retry logs in again
		return true, fmt.Errorf("status %s", resp.Status)
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
