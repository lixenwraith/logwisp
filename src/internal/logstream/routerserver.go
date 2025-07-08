// FILE: src/internal/config/routerserver.go
package logstream

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
	"logwisp/src/internal/version"
)

type routerServer struct {
	port      int
	server    *fasthttp.Server
	routes    map[string]*LogStream // path prefix -> stream
	routeMu   sync.RWMutex
	router    *HTTPRouter
	startTime time.Time
	requests  atomic.Uint64
}

func (rs *routerServer) requestHandler(ctx *fasthttp.RequestCtx) {
	rs.requests.Add(1)
	rs.router.totalRequests.Add(1)

	path := string(ctx.Path())

	// Log request for debugging
	fmt.Printf("[ROUTER] Request: %s %s from %s\n", ctx.Method(), path, ctx.RemoteAddr())

	// Special case: global status at /status
	if path == "/status" {
		rs.handleGlobalStatus(ctx)
		return
	}

	// Find matching stream
	rs.routeMu.RLock()
	var matchedStream *LogStream
	var matchedPrefix string
	var remainingPath string

	for prefix, stream := range rs.routes {
		if strings.HasPrefix(path, prefix) {
			// Use longest prefix match
			if len(prefix) > len(matchedPrefix) {
				matchedPrefix = prefix
				matchedStream = stream
				remainingPath = strings.TrimPrefix(path, prefix)
				// Ensure remaining path starts with / or is empty
				if remainingPath != "" && !strings.HasPrefix(remainingPath, "/") {
					remainingPath = "/" + remainingPath
				}
			}
		}
	}
	rs.routeMu.RUnlock()

	if matchedStream == nil {
		rs.router.failedRequests.Add(1)
		rs.handleNotFound(ctx)
		return
	}

	rs.router.routedRequests.Add(1)

	// Route to stream's handler
	if matchedStream.HTTPServer != nil {
		// Save original path
		originalPath := string(ctx.URI().Path())

		// Rewrite path to remove stream prefix
		if remainingPath == "" {
			// Default to stream path if no remaining path
			remainingPath = matchedStream.Config.HTTPServer.StreamPath
		}

		fmt.Printf("[ROUTER] Routing to stream '%s': %s -> %s\n",
			matchedStream.Name, originalPath, remainingPath)

		ctx.URI().SetPath(remainingPath)
		matchedStream.HTTPServer.RouteRequest(ctx)

		// Restore original path
		ctx.URI().SetPath(originalPath)
	} else {
		ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error":  "Stream HTTP server not available",
			"stream": matchedStream.Name,
		})
	}
}

func (rs *routerServer) handleGlobalStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	rs.routeMu.RLock()
	streams := make(map[string]interface{})
	for prefix, stream := range rs.routes {
		streamStats := stream.GetStats()

		// Add routing information
		streamStats["routing"] = map[string]interface{}{
			"path_prefix": prefix,
			"endpoints": map[string]string{
				"stream": prefix + stream.Config.HTTPServer.StreamPath,
				"status": prefix + stream.Config.HTTPServer.StatusPath,
			},
		}

		streams[stream.Name] = streamStats
	}
	rs.routeMu.RUnlock()

	// Get router stats
	routerStats := rs.router.GetStats()

	status := map[string]interface{}{
		"service":       "LogWisp Router",
		"version":       version.String(),
		"port":          rs.port,
		"streams":       streams,
		"total_streams": len(streams),
		"router":        routerStats,
		"endpoints": map[string]string{
			"global_status": "/status",
		},
	}

	data, _ := json.MarshalIndent(status, "", "  ")
	ctx.SetBody(data)
}

func (rs *routerServer) handleNotFound(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusNotFound)
	ctx.SetContentType("application/json")

	rs.routeMu.RLock()
	availableRoutes := make([]string, 0, len(rs.routes)*2+1)
	availableRoutes = append(availableRoutes, "/status (global status)")

	for prefix, stream := range rs.routes {
		if stream.Config.HTTPServer != nil {
			availableRoutes = append(availableRoutes,
				fmt.Sprintf("%s%s (stream: %s)", prefix, stream.Config.HTTPServer.StreamPath, stream.Name),
				fmt.Sprintf("%s%s (status: %s)", prefix, stream.Config.HTTPServer.StatusPath, stream.Name),
			)
		}
	}
	rs.routeMu.RUnlock()

	response := map[string]interface{}{
		"error":            "Not Found",
		"requested_path":   string(ctx.Path()),
		"available_routes": availableRoutes,
		"hint":             "Use /status for global router status",
	}

	data, _ := json.MarshalIndent(response, "", "  ")
	ctx.SetBody(data)
}