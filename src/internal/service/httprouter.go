// FILE: logwisp/src/internal/service/httprouter.go
package service

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/sink"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

// HTTPRouter manages HTTP routing for multiple pipelines
type HTTPRouter struct {
	service *Service
	servers map[int64]*routerServer // port -> server
	mu      sync.RWMutex
	logger  *log.Logger

	// Statistics
	startTime      time.Time
	totalRequests  atomic.Uint64
	routedRequests atomic.Uint64
	failedRequests atomic.Uint64
}

// NewHTTPRouter creates a new HTTP router
func NewHTTPRouter(service *Service, logger *log.Logger) *HTTPRouter {
	return &HTTPRouter{
		service:   service,
		servers:   make(map[int64]*routerServer),
		startTime: time.Now(),
		logger:    logger,
	}
}

// RegisterPipeline registers a pipeline's HTTP sinks with the router
func (r *HTTPRouter) RegisterPipeline(pipeline *Pipeline) error {
	// Register all HTTP sinks in the pipeline
	for _, httpSink := range pipeline.HTTPSinks {
		if err := r.registerHTTPSink(pipeline.Name, httpSink); err != nil {
			return err
		}
	}
	return nil
}

// registerHTTPSink registers a single HTTP sink
func (r *HTTPRouter) registerHTTPSink(pipelineName string, httpSink *sink.HTTPSink) error {
	// Get port from sink configuration
	stats := httpSink.GetStats()
	details := stats.Details
	port := details["port"].(int64)

	r.mu.Lock()
	rs, exists := r.servers[port]
	if !exists {
		// Create new server for this port
		rs = &routerServer{
			port:      port,
			routes:    make(map[string]*routedSink),
			router:    r,
			startTime: time.Now(),
			logger:    r.logger,
		}
		rs.server = &fasthttp.Server{
			Handler:           rs.requestHandler,
			DisableKeepalive:  false,
			StreamRequestBody: true,
			CloseOnShutdown:   true,
		}
		r.servers[port] = rs

		// Startup sync channel
		startupDone := make(chan error, 1)

		// Start server in background
		go func() {
			addr := fmt.Sprintf(":%d", port)
			r.logger.Info("msg", "Starting router server",
				"component", "http_router",
				"port", port)

			// Signal that server is about to start
			startupDone <- nil

			if err := rs.server.ListenAndServe(addr); err != nil {
				r.logger.Error("msg", "Router server failed",
					"component", "http_router",
					"port", port,
					"error", err)
			}
		}()

		// Wait for server startup signal with timeout
		select {
		case err := <-startupDone:
			if err != nil {
				r.mu.Unlock()
				return fmt.Errorf("server startup failed: %w", err)
			}
		case <-time.After(5 * time.Second):
			r.mu.Unlock()
			return fmt.Errorf("server startup timeout on port %d", port)
		}
	}
	r.mu.Unlock()

	// Register routes for this sink
	rs.routeMu.Lock()
	defer rs.routeMu.Unlock()

	// Use pipeline name as path prefix
	pathPrefix := "/" + pipelineName

	// Check for conflicts
	for existingPath, existing := range rs.routes {
		if strings.HasPrefix(pathPrefix, existingPath) || strings.HasPrefix(existingPath, pathPrefix) {
			return fmt.Errorf("path conflict: '%s' conflicts with existing pipeline '%s' at '%s'",
				pathPrefix, existing.pipelineName, existingPath)
		}
	}

	// Set the sink to router mode
	httpSink.SetRouterMode()

	rs.routes[pathPrefix] = &routedSink{
		pipelineName: pipelineName,
		httpSink:     httpSink,
	}

	r.logger.Info("msg", "Registered pipeline route",
		"component", "http_router",
		"pipeline", pipelineName,
		"path", pathPrefix,
		"port", port)
	return nil
}

// UnregisterPipeline removes a pipeline's routes
func (r *HTTPRouter) UnregisterPipeline(pipelineName string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for port, rs := range r.servers {
		rs.routeMu.Lock()
		for path, route := range rs.routes {
			if route.pipelineName == pipelineName {
				delete(rs.routes, path)
				r.logger.Info("msg", "Unregistered pipeline route",
					"component", "http_router",
					"pipeline", pipelineName,
					"path", path,
					"port", port)
			}
		}

		// Check if server has no more routes
		if len(rs.routes) == 0 {
			r.logger.Info("msg", "No routes left on port, considering shutdown",
				"component", "http_router",
				"port", port)
		}
		rs.routeMu.Unlock()
	}
}

// Shutdown stops all router servers
func (r *HTTPRouter) Shutdown() {
	r.logger.Info("msg", "Starting router shutdown...")

	r.mu.Lock()
	defer r.mu.Unlock()

	var wg sync.WaitGroup
	for port, rs := range r.servers {
		wg.Add(1)
		go func(p int64, s *routerServer) {
			defer wg.Done()
			r.logger.Info("msg", "Shutting down server",
				"component", "http_router",
				"port", p)
			if err := s.server.Shutdown(); err != nil {
				r.logger.Error("msg", "Error shutting down server",
					"component", "http_router",
					"port", p,
					"error", err)
			}
		}(port, rs)
	}
	wg.Wait()

	r.logger.Info("msg", "Router shutdown complete")
}

// GetStats returns router statistics
func (r *HTTPRouter) GetStats() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	serverStats := make(map[int64]any)
	totalRoutes := 0

	for port, rs := range r.servers {
		rs.routeMu.RLock()
		routes := make([]string, 0, len(rs.routes))
		for path := range rs.routes {
			routes = append(routes, path)
			totalRoutes++
		}
		rs.routeMu.RUnlock()

		serverStats[port] = map[string]any{
			"routes":   routes,
			"requests": rs.requests.Load(),
			"uptime":   int(time.Since(rs.startTime).Seconds()),
		}
	}

	return map[string]any{
		"uptime_seconds":  int64(time.Since(r.startTime).Seconds()),
		"total_requests":  r.totalRequests.Load(),
		"routed_requests": r.routedRequests.Load(),
		"failed_requests": r.failedRequests.Load(),
		"servers":         serverStats,
		"total_routes":    totalRoutes,
	}
}