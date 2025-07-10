// FILE: src/internal/service/httprouter.go
package service

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/log"
	"github.com/valyala/fasthttp"
)

type HTTPRouter struct {
	service *Service
	servers map[int]*routerServer // port -> server
	mu      sync.RWMutex
	logger  *log.Logger

	// Statistics
	startTime      time.Time
	totalRequests  atomic.Uint64
	routedRequests atomic.Uint64
	failedRequests atomic.Uint64
}

func NewHTTPRouter(service *Service, logger *log.Logger) *HTTPRouter {
	return &HTTPRouter{
		service:   service,
		servers:   make(map[int]*routerServer),
		startTime: time.Now(),
		logger:    logger,
	}
}

func (r *HTTPRouter) RegisterStream(stream *LogStream) error {
	if stream.HTTPServer == nil || stream.Config.HTTPServer == nil {
		return nil // No HTTP server configured
	}

	port := stream.Config.HTTPServer.Port

	r.mu.Lock()
	rs, exists := r.servers[port]
	if !exists {
		// Create new server for this port
		rs = &routerServer{
			port:      port,
			routes:    make(map[string]*LogStream),
			router:    r,
			startTime: time.Now(),
			logger:    r.logger,
		}
		rs.server = &fasthttp.Server{
			Handler:           rs.requestHandler,
			DisableKeepalive:  false,
			StreamRequestBody: true,
			CloseOnShutdown:   true, // Ensure connections close on shutdown
		}
		r.servers[port] = rs

		// Start server in background
		go func() {
			addr := fmt.Sprintf(":%d", port)
			r.logger.Info("msg", "Starting router server",
				"component", "http_router",
				"port", port)
			if err := rs.server.ListenAndServe(addr); err != nil {
				r.logger.Error("msg", "Router server failed",
					"component", "http_router",
					"port", port,
					"error", err)
			}
		}()

		// Wait briefly to ensure server starts
		time.Sleep(100 * time.Millisecond)
	}
	r.mu.Unlock()

	// Register routes for this transport
	rs.routeMu.Lock()
	defer rs.routeMu.Unlock()

	// Use transport name as path prefix
	pathPrefix := "/" + stream.Name

	// Check for conflicts
	for existingPath, existingStream := range rs.routes {
		if strings.HasPrefix(pathPrefix, existingPath) || strings.HasPrefix(existingPath, pathPrefix) {
			return fmt.Errorf("path conflict: '%s' conflicts with existing transport '%s' at '%s'",
				pathPrefix, existingStream.Name, existingPath)
		}
	}

	rs.routes[pathPrefix] = stream
	r.logger.Info("msg", "Registered transport route",
		"component", "http_router",
		"transport", stream.Name,
		"path", pathPrefix,
		"port", port)
	return nil
}

func (r *HTTPRouter) UnregisterStream(streamName string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for port, rs := range r.servers {
		rs.routeMu.Lock()
		for path, stream := range rs.routes {
			if stream.Name == streamName {
				delete(rs.routes, path)
				fmt.Printf("[ROUTER] Unregistered transport '%s' from path '%s' on port %d\n",
					streamName, path, port)
			}
		}

		// Check if server has no more routes
		if len(rs.routes) == 0 {
			fmt.Printf("[ROUTER] No routes left on port %d, considering shutdown\n", port)
		}
		rs.routeMu.Unlock()
	}
}

func (r *HTTPRouter) Shutdown() {
	fmt.Println("[ROUTER] Starting router shutdown...")

	r.mu.Lock()
	defer r.mu.Unlock()

	var wg sync.WaitGroup
	for port, rs := range r.servers {
		wg.Add(1)
		go func(p int, s *routerServer) {
			defer wg.Done()
			fmt.Printf("[ROUTER] Shutting down server on port %d\n", p)
			if err := s.server.Shutdown(); err != nil {
				fmt.Printf("[ROUTER] Error shutting down server on port %d: %v\n", p, err)
			}
		}(port, rs)
	}
	wg.Wait()

	fmt.Println("[ROUTER] Router shutdown complete")
}

func (r *HTTPRouter) GetStats() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	serverStats := make(map[int]any)
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
		"uptime_seconds":  int(time.Since(r.startTime).Seconds()),
		"total_requests":  r.totalRequests.Load(),
		"routed_requests": r.routedRequests.Load(),
		"failed_requests": r.failedRequests.Load(),
		"servers":         serverStats,
		"total_routes":    totalRoutes,
	}
}