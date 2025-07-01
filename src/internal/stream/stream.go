// File: logwisp/src/internal/stream/stream.go
package stream

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"logwisp/src/internal/monitor"
)

// Streamer handles Server-Sent Events streaming
type Streamer struct {
	clients    map[string]*clientConnection
	register   chan *clientConnection
	unregister chan string
	broadcast  chan monitor.LogEntry
	mu         sync.RWMutex
	bufferSize int
	done       chan struct{}
	colorMode  bool
	wg         sync.WaitGroup
}

type clientConnection struct {
	id           string
	channel      chan monitor.LogEntry
	lastActivity time.Time
	dropped      int64 // Count of dropped messages
}

// New creates a new SSE streamer
func New(bufferSize int) *Streamer {
	return NewWithOptions(bufferSize, false)
}

// NewWithOptions creates a new SSE streamer with options
func NewWithOptions(bufferSize int, colorMode bool) *Streamer {
	s := &Streamer{
		clients:    make(map[string]*clientConnection),
		register:   make(chan *clientConnection),
		unregister: make(chan string),
		broadcast:  make(chan monitor.LogEntry, bufferSize),
		bufferSize: bufferSize,
		done:       make(chan struct{}),
		colorMode:  colorMode,
	}

	s.wg.Add(1)
	go s.run()
	return s
}

// run manages client connections with timeout cleanup
func (s *Streamer) run() {
	defer s.wg.Done()

	// Add periodic cleanup for stale/slow clients
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case c := <-s.register:
			s.mu.Lock()
			s.clients[c.id] = c
			s.mu.Unlock()

		case id := <-s.unregister:
			s.mu.Lock()
			if client, ok := s.clients[id]; ok {
				close(client.channel)
				delete(s.clients, id)
			}
			s.mu.Unlock()

		case entry := <-s.broadcast:
			s.mu.RLock()
			now := time.Now()
			var toRemove []string

			for id, client := range s.clients {
				select {
				case client.channel <- entry:
					client.lastActivity = now
				default:
					// Track dropped messages and remove slow clients
					client.dropped++
					// Remove clients that have dropped >100 messages or been inactive >2min
					if client.dropped > 100 || now.Sub(client.lastActivity) > 2*time.Minute {
						toRemove = append(toRemove, id)
					}
				}
			}
			s.mu.RUnlock()

			// Remove slow/stale clients outside the read lock
			if len(toRemove) > 0 {
				s.mu.Lock()
				for _, id := range toRemove {
					if client, ok := s.clients[id]; ok {
						close(client.channel)
						delete(s.clients, id)
					}
				}
				s.mu.Unlock()
			}

		case <-cleanupTicker.C:
			// Periodic cleanup of inactive clients
			s.mu.Lock()
			now := time.Now()
			for id, client := range s.clients {
				if now.Sub(client.lastActivity) > 5*time.Minute {
					close(client.channel)
					delete(s.clients, id)
				}
			}
			s.mu.Unlock()

		case <-s.done:
			s.mu.Lock()
			for _, client := range s.clients {
				close(client.channel)
			}
			s.clients = make(map[string]*clientConnection)
			s.mu.Unlock()
			return
		}
	}
}

// Publish sends a log entry to all connected clients
func (s *Streamer) Publish(entry monitor.LogEntry) {
	select {
	case s.broadcast <- entry:
		// Sent to broadcast channel
	default:
		// Drop entry if broadcast buffer full, log occurrence
		// This prevents memory exhaustion under high load
	}
}

// ServeHTTP implements http.Handler for SSE
func (s *Streamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Create client
	clientID := fmt.Sprintf("%d", time.Now().UnixNano())
	ch := make(chan monitor.LogEntry, s.bufferSize)

	client := &clientConnection{
		id:           clientID,
		channel:      ch,
		lastActivity: time.Now(),
		dropped:      0,
	}

	// Register client
	s.register <- client
	defer func() {
		s.unregister <- clientID
	}()

	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"client_id\":\"%s\"}\n\n", clientID)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Create ticker for heartbeat
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Add timeout for slow clients
	clientTimeout := time.NewTimer(10 * time.Minute)
	defer clientTimeout.Stop()

	// Stream events
	for {
		select {
		case <-r.Context().Done():
			return

		case entry, ok := <-ch:
			if !ok {
				// Channel was closed (client removed due to slowness)
				fmt.Fprintf(w, "event: disconnected\ndata: {\"reason\":\"slow_client\"}\n\n")
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				return
			}

			// Reset client timeout on successful read
			if !clientTimeout.Stop() {
				<-clientTimeout.C
			}
			clientTimeout.Reset(10 * time.Minute)

			// Process entry for color if needed
			if s.colorMode {
				entry = s.processColorEntry(entry)
			}

			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}

			fmt.Fprintf(w, "data: %s\n\n", data)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

		case <-ticker.C:
			// Heartbeat with UTC timestamp
			fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

		case <-clientTimeout.C:
			// Client timeout - close connection
			fmt.Fprintf(w, "event: timeout\ndata: {\"reason\":\"client_timeout\"}\n\n")
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
	}
}

// Stop gracefully shuts down the streamer
func (s *Streamer) Stop() {
	close(s.done)
	s.wg.Wait()
	close(s.register)
	close(s.unregister)
	close(s.broadcast)
}

// Enhanced color processing with proper ANSI handling
func (s *Streamer) processColorEntry(entry monitor.LogEntry) monitor.LogEntry {
	// For color mode, we preserve ANSI codes but ensure they're properly handled
	// The JSON marshaling will escape them correctly for transmission
	// Client-side handling is required for proper display
	return entry
}

// Stats returns current streamer statistics
func (s *Streamer) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"active_clients": len(s.clients),
		"buffer_size":    s.bufferSize,
		"color_mode":     s.colorMode,
	}

	totalDropped := int64(0)
	for _, client := range s.clients {
		totalDropped += client.dropped
	}
	stats["total_dropped"] = totalDropped

	return stats
}