// FILE: src/internal/stream/httpstreamer.go
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

	// Path configuration
	streamPath string
	statusPath string

	// For router integration
	standalone bool
}

func NewHTTPStreamer(logChan chan monitor.LogEntry, cfg config.HTTPConfig) *HTTPStreamer {
	// Set default paths if not configured
	streamPath := cfg.StreamPath
	if streamPath == "" {
		streamPath = "/stream"
	}
	statusPath := cfg.StatusPath
	if statusPath == "" {
		statusPath = "/status"
	}

	return &HTTPStreamer{
		logChan:    logChan,
		config:     cfg,
		startTime:  time.Now(),
		done:       make(chan struct{}),
		streamPath: streamPath,
		statusPath: statusPath,
		standalone: true, // Default to standalone mode
	}
}

// SetRouterMode configures the streamer for use with a router
func (h *HTTPStreamer) SetRouterMode() {
	h.standalone = false
}

func (h *HTTPStreamer) Start() error {
	if !h.standalone {
		// In router mode, don't start our own server
		return nil
	}

	h.server = &fasthttp.Server{
		Handler:           h.requestHandler,
		DisableKeepalive:  false,
		StreamRequestBody: true,
		Logger:            nil,
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

	// Shutdown HTTP server if in standalone mode
	if h.standalone && h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		h.server.ShutdownWithContext(ctx)
	}

	// Wait for all active client handlers to finish
	h.wg.Wait()
}

func (h *HTTPStreamer) RouteRequest(ctx *fasthttp.RequestCtx) {
	h.requestHandler(ctx)
}

func (h *HTTPStreamer) requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	switch path {
	case h.streamPath:
		h.handleStream(ctx)
	case h.statusPath:
		h.handleStatus(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]interface{}{
			"error": "Not Found",
			"message": fmt.Sprintf("Available endpoints: %s (SSE stream), %s (status)",
				h.streamPath, h.statusPath),
		})
	}
}

func (h *HTTPStreamer) handleStream(ctx *fasthttp.RequestCtx) {
	// Set SSE headers
	ctx.Response.Header.Set("Content-Type", "text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("X-Accel-Buffering", "no")

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
				case <-h.done:
					return
				default:
					// Drop if client buffer full
				}
			case <-clientDone:
				return
			case <-h.done:
				return
			}
		}
	}()

	// Define the stream writer function
	streamFunc := func(w *bufio.Writer) {
		newCount := h.activeClients.Add(1)
		fmt.Printf("[HTTP DEBUG] Client connected on port %d. Count now: %d\n",
			h.config.Port, newCount)

		h.wg.Add(1)
		defer func() {
			newCount := h.activeClients.Add(-1)
			fmt.Printf("[HTTP DEBUG] Client disconnected on port %d. Count now: %d\n",
				h.config.Port, newCount)
			h.wg.Done()
		}()

		// Send initial connected event
		clientID := fmt.Sprintf("%d", time.Now().UnixNano())
		connectionInfo := map[string]interface{}{
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
		"server": map[string]interface{}{
			"type":           "http",
			"port":           h.config.Port,
			"active_clients": h.activeClients.Load(),
			"buffer_size":    h.config.BufferSize,
			"uptime_seconds": int(time.Since(h.startTime).Seconds()),
			"mode":           map[string]bool{"standalone": h.standalone, "router": !h.standalone},
		},
		"endpoints": map[string]string{
			"stream": h.streamPath,
			"status": h.statusPath,
		},
		"features": map[string]interface{}{
			"heartbeat": map[string]interface{}{
				"enabled":  h.config.Heartbeat.Enabled,
				"interval": h.config.Heartbeat.IntervalSeconds,
				"format":   h.config.Heartbeat.Format,
			},
			"ssl": map[string]bool{
				"enabled": h.config.SSL != nil && h.config.SSL.Enabled,
			},
			"rate_limit": map[string]bool{
				"enabled": h.config.RateLimit != nil && h.config.RateLimit.Enabled,
			},
		},
	}

	data, _ := json.Marshal(status)
	ctx.SetBody(data)
}

// GetActiveConnections returns the current number of active clients
func (h *HTTPStreamer) GetActiveConnections() int32 {
	return h.activeClients.Load()
}

// GetStreamPath returns the configured stream endpoint path
func (h *HTTPStreamer) GetStreamPath() string {
	return h.streamPath
}

// GetStatusPath returns the configured status endpoint path
func (h *HTTPStreamer) GetStatusPath() string {
	return h.statusPath
}