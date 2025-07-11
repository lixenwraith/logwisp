// FILE: src/internal/service/routerserver.go
package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/sink"
	"logwisp/src/internal/version"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// routedSink represents a sink registered with the router
type routedSink struct {
	pipelineName string
	httpSink     *sink.HTTPSink
}

// routerServer handles HTTP requests for a specific port
type routerServer struct {
	port      int
	server    *fasthttp.Server
	logger    *log.Logger
	routes    map[string]*routedSink // path prefix -> sink
	routeMu   sync.RWMutex
	router    *HTTPRouter
	startTime time.Time
	requests  atomic.Uint64
}

func (rs *routerServer) requestHandler(ctx *fasthttp.RequestCtx) {
	rs.requests.Add(1)
	rs.router.totalRequests.Add(1)

	path := string(ctx.Path())
	remoteAddr := ctx.RemoteAddr().String()

	// Log request for debugging
	rs.logger.Debug("msg", "Router request",
		"component", "router_server",
		"method", string(ctx.Method()),
		"path", path,
		"remote_addr", remoteAddr)

	// Special case: global status at /status
	if path == "/status" {
		rs.handleGlobalStatus(ctx)
		return
	}

	// Find matching route
	rs.routeMu.RLock()
	var matchedSink *routedSink
	var matchedPrefix string
	var remainingPath string

	for prefix, route := range rs.routes {
		if strings.HasPrefix(path, prefix) {
			// Use longest prefix match
			if len(prefix) > len(matchedPrefix) {
				matchedPrefix = prefix
				matchedSink = route
				remainingPath = strings.TrimPrefix(path, prefix)
				// Ensure remaining path starts with / or is empty
				if remainingPath != "" && !strings.HasPrefix(remainingPath, "/") {
					remainingPath = "/" + remainingPath
				}
			}
		}
	}
	rs.routeMu.RUnlock()

	if matchedSink == nil {
		rs.router.failedRequests.Add(1)
		rs.handleNotFound(ctx)
		return
	}

	rs.router.routedRequests.Add(1)

	// Route to sink's handler
	if matchedSink.httpSink != nil {
		// Save original path
		originalPath := string(ctx.URI().Path())

		// Rewrite path to remove pipeline prefix
		if remainingPath == "" {
			// Default to stream path if no remaining path
			remainingPath = matchedSink.httpSink.GetStreamPath()
		}

		rs.logger.Debug("msg", "Routing request to pipeline",
			"component", "router_server",
			"pipeline", matchedSink.pipelineName,
			"original_path", originalPath,
			"remaining_path", remainingPath)

		ctx.URI().SetPath(remainingPath)
		matchedSink.httpSink.RouteRequest(ctx)

		// Restore original path
		ctx.URI().SetPath(originalPath)
	} else {
		ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error":    "Pipeline HTTP sink not available",
			"pipeline": matchedSink.pipelineName,
		})
	}
}

func (rs *routerServer) handleGlobalStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	rs.routeMu.RLock()
	pipelines := make(map[string]any)
	for prefix, route := range rs.routes {
		pipelineInfo := map[string]any{
			"path_prefix": prefix,
			"endpoints": map[string]string{
				"stream": prefix + route.httpSink.GetStreamPath(),
				"status": prefix + route.httpSink.GetStatusPath(),
			},
		}

		// Get sink stats
		sinkStats := route.httpSink.GetStats()
		pipelineInfo["sink"] = map[string]any{
			"type":               sinkStats.Type,
			"total_processed":    sinkStats.TotalProcessed,
			"active_connections": sinkStats.ActiveConnections,
			"details":            sinkStats.Details,
		}

		pipelines[route.pipelineName] = pipelineInfo
	}
	rs.routeMu.RUnlock()

	// Get router stats
	routerStats := rs.router.GetStats()

	status := map[string]any{
		"service":         "LogWisp Router",
		"version":         version.String(),
		"port":            rs.port,
		"pipelines":       pipelines,
		"total_pipelines": len(pipelines),
		"router":          routerStats,
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

	for prefix, route := range rs.routes {
		if route.httpSink != nil {
			availableRoutes = append(availableRoutes,
				fmt.Sprintf("%s%s (stream: %s)", prefix, route.httpSink.GetStreamPath(), route.pipelineName),
				fmt.Sprintf("%s%s (status: %s)", prefix, route.httpSink.GetStatusPath(), route.pipelineName),
			)
		}
	}
	rs.routeMu.RUnlock()

	response := map[string]any{
		"error":            "Not Found",
		"requested_path":   string(ctx.Path()),
		"available_routes": availableRoutes,
		"hint":             "Use /status for global router status",
	}

	data, _ := json.MarshalIndent(response, "", "  ")
	ctx.SetBody(data)
}