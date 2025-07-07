// FILE: src/internal/logstream/httprouter.go
package logstream

import (
	"fmt"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
)

type HTTPRouter struct {
	service *Service
	servers map[int]*routerServer // port -> server
	mu      sync.RWMutex
}

func NewHTTPRouter(service *Service) *HTTPRouter {
	return &HTTPRouter{
		service: service,
		servers: make(map[int]*routerServer),
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
			port:   port,
			routes: make(map[string]*LogStream),
		}
		rs.server = &fasthttp.Server{
			Handler:           rs.requestHandler,
			DisableKeepalive:  false,
			StreamRequestBody: true,
		}
		r.servers[port] = rs

		// Start server in background
		go func() {
			addr := fmt.Sprintf(":%d", port)
			if err := rs.server.ListenAndServe(addr); err != nil {
				// Log error but don't crash
				fmt.Printf("Router server on port %d failed: %v\n", port, err)
			}
		}()
	}
	r.mu.Unlock()

	// Register routes for this stream
	rs.routeMu.Lock()
	defer rs.routeMu.Unlock()

	// Use stream name as path prefix
	pathPrefix := "/" + stream.Name

	// Check for conflicts
	for existingPath, existingStream := range rs.routes {
		if strings.HasPrefix(pathPrefix, existingPath) || strings.HasPrefix(existingPath, pathPrefix) {
			return fmt.Errorf("path conflict: '%s' conflicts with existing stream '%s' at '%s'",
				pathPrefix, existingStream.Name, existingPath)
		}
	}

	rs.routes[pathPrefix] = stream
	return nil
}

func (r *HTTPRouter) UnregisterStream(streamName string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rs := range r.servers {
		rs.routeMu.Lock()
		for path, stream := range rs.routes {
			if stream.Name == streamName {
				delete(rs.routes, path)
			}
		}
		rs.routeMu.Unlock()
	}
}

func (r *HTTPRouter) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()

	var wg sync.WaitGroup
	for port, rs := range r.servers {
		wg.Add(1)
		go func(p int, s *routerServer) {
			defer wg.Done()
			if err := s.server.Shutdown(); err != nil {
				fmt.Printf("Error shutting down router server on port %d: %v\n", p, err)
			}
		}(port, rs)
	}
	wg.Wait()
}