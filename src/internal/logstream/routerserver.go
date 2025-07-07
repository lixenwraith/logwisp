// FILE: src/internal/config/routerserver.go
package logstream

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
	"logwisp/src/internal/version"
)

type routerServer struct {
	port    int
	server  *fasthttp.Server
	routes  map[string]*LogStream // path prefix -> stream
	routeMu sync.RWMutex
}

func (rs *routerServer) requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

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
			}
		}
	}
	rs.routeMu.RUnlock()

	if matchedStream == nil {
		rs.handleNotFound(ctx)
		return
	}

	// Route to stream's handler
	if matchedStream.HTTPServer != nil {
		// Rewrite path to remove stream prefix
		ctx.URI().SetPath(remainingPath)
		matchedStream.HTTPServer.RouteRequest(ctx)
	} else {
		ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(map[string]string{
			"error": "Stream HTTP server not available",
		})
	}
}

func (rs *routerServer) handleGlobalStatus(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")

	rs.routeMu.RLock()
	streams := make(map[string]interface{})
	for prefix, stream := range rs.routes {
		streams[stream.Name] = map[string]interface{}{
			"path_prefix": prefix,
			"config": map[string]interface{}{
				"stream_path": stream.Config.HTTPServer.StreamPath,
				"status_path": stream.Config.HTTPServer.StatusPath,
			},
			"stats": stream.GetStats(),
		}
	}
	rs.routeMu.RUnlock()

	status := map[string]interface{}{
		"service":       "LogWisp Router",
		"version":       version.Short(),
		"port":          rs.port,
		"streams":       streams,
		"total_streams": len(streams),
	}

	data, _ := json.Marshal(status)
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
		"available_routes": availableRoutes,
	}

	data, _ := json.Marshal(response)
	ctx.SetBody(data)
}