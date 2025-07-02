// FILE: src/internal/stream/http.go
package stream

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
	"logwisp/src/internal/config"
	"logwisp/src/internal/monitor"
)

type HTTPStreamer struct {
	logChan       chan monitor.LogEntry
	config        config.HTTPConfig
	server        *fasthttp.Server
	activeClients atomic.Int32
	mu            sync.RWMutex
	startTime     time.Time
	done          chan struct{}
	wg            sync.WaitGroup
}

func NewHTTPStreamer(logChan chan monitor.LogEntry, cfg config.HTTPConfig) *HTTPStreamer {
	return &HTTPStreamer{
		logChan:   logChan,
		config:    cfg,
		startTime: time.Now(),
		done:      make(chan struct{}),
	}
}

func (h *HTTPStreamer) Start() error {
	h.server = &fasthttp.Server{
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		Logger:            nil, // Suppress fasthttp logs
	}

	addr := fmt.Sprintf(":%d", h.config.Port)

	// Run server in separate goroutine to avoid blocking
	errChan := make(chan error, 1)
	go func() {
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

func (h *HTTPStreamer) Stop() {
	// Signal all client handlers to stop
	close(h.done)

	// Shutdown HTTP server
	if h.server != nil {
		// Create context with timeout for server shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Use ShutdownWithContext for graceful shutdown
		h.server.ShutdownWithContext(ctx)
	}

	// Wait for all active client handlers to finish
	h.wg.Wait()
}

func (h *HTTPStreamer) requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	switch path {
	case "/stream":
		h.handleStream(ctx)
	case "/status":
		h.handleStatus(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
	}
}

func (h *HTTPStreamer) handleStream(ctx *fasthttp.RequestCtx) {
	// Set SSE headers
	ctx.Response.Header.Set("Content-Type", "text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")

	h.activeClients.Add(1)
	h.wg.Add(1) // Track this client handler
	defer func() {
		h.activeClients.Add(-1)
		h.wg.Done() // Mark handler as done
	}()

	// Create subscription for this client
	clientChan := make(chan monitor.LogEntry, h.config.BufferSize)
	clientDone := make(chan struct{})

	// Subscribe to monitor's broadcast
	go func() {
		defer close(clientChan)
		for {
			select {
			case entry, ok := <-h.logChan:
				if !ok {
					return
				}
				select {
				case clientChan <- entry:
				case <-clientDone:
					return
				case <-h.done: // Check for server shutdown
					return
				default:
					// Drop if client buffer full
				}
			case <-clientDone:
				return
			case <-h.done: // Check for server shutdown
				return
			}
		}
	}()

	// Define the stream writer function
	streamFunc := func(w *bufio.Writer) {
		defer close(clientDone)

		// Send initial connected event
		clientID := fmt.Sprintf("%d", time.Now().UnixNano())
		fmt.Fprintf(w, "event: connected\ndata: {\"client_id\":\"%s\"}\n\n", clientID)
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
					continue
				}

				fmt.Fprintf(w, "data: %s\n\n", data)
				if err := w.Flush(); err != nil {
					return
				}

			case <-tickerChan:
				if heartbeat := h.formatHeartbeat(); heartbeat != "" {
					fmt.Fprint(w, heartbeat)
					if err := w.Flush(); err != nil {
						return
					}
				}

			case <-h.done: // ADDED: Check for server shutdown
				// Send final disconnect event
				fmt.Fprintf(w, "event: disconnect\ndata: {\"reason\":\"server_shutdown\"}\n\n")
				w.Flush()
				return
			}
		}
	}

	ctx.SetBodyStreamWriter(streamFunc)
}

func (h *HTTPStreamer) formatHeartbeat() string {
	if !h.config.Heartbeat.Enabled {
		return ""
	}

	if h.config.Heartbeat.Format == "json" {
		data := make(map[string]interface{})
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

func (h *HTTPStreamer) handleStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	status := map[string]interface{}{
		"service": "LogWisp",
		"version": "3.0.0",
		"http_server": map[string]interface{}{
			"port":           h.config.Port,
			"active_clients": h.activeClients.Load(),
			"buffer_size":    h.config.BufferSize,
		},
	}

	data, _ := json.Marshal(status)
	ctx.SetBody(data)
}