// File: logwisp/src/internal/stream/stream.go
package stream

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
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

	// Metrics
	totalDropped atomic.Int64
}

type clientConnection struct {
	id           string
	channel      chan monitor.LogEntry
	lastActivity time.Time
	dropped      atomic.Int64 // Track per-client dropped messages
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

// run manages client connections - SIMPLIFIED: no forced disconnections
func (s *Streamer) run() {
	defer s.wg.Done()

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

			for _, client := range s.clients {
				select {
				case client.channel <- entry:
					// Successfully sent
					client.lastActivity = now
					client.dropped.Store(0) // Reset dropped counter on success
				default:
					// Buffer full - skip this message for this client
					// Don't disconnect, just track dropped messages
					dropped := client.dropped.Add(1)
					s.totalDropped.Add(1)

					// Log significant drop milestones for monitoring
					if dropped == 100 || dropped == 1000 || dropped%10000 == 0 {
						// Could add logging here if needed
					}
				}
			}
			s.mu.RUnlock()

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
		// Broadcast buffer full - drop the message globally
		s.totalDropped.Add(1)
	}
}

// ServeHTTP implements http.Handler for SSE - SIMPLIFIED
func (s *Streamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	// SECURITY: Prevent XSS
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Create client
	clientID := fmt.Sprintf("%d", time.Now().UnixNano())
	ch := make(chan monitor.LogEntry, s.bufferSize)

	client := &clientConnection{
		id:           clientID,
		channel:      ch,
		lastActivity: time.Now(),
	}

	// Register client
	s.register <- client
	defer func() {
		s.unregister <- clientID
	}()

	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"client_id\":\"%s\",\"buffer_size\":%d}\n\n",
		clientID, s.bufferSize)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Create ticker for heartbeat - keeps connection alive through proxies
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Stream events until client disconnects
	for {
		select {
		case <-r.Context().Done():
			// Client disconnected
			return

		case entry, ok := <-ch:
			if !ok {
				// Channel closed
				return
			}

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
			// Send heartbeat as SSE comment
			fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().UTC().Format(time.RFC3339))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
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

// processColorEntry preserves ANSI codes in JSON
func (s *Streamer) processColorEntry(entry monitor.LogEntry) monitor.LogEntry {
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
		"total_dropped":  s.totalDropped.Load(),
	}

	// Include per-client dropped counts if any are significant
	var clientsWithDrops []map[string]interface{}
	for id, client := range s.clients {
		dropped := client.dropped.Load()
		if dropped > 0 {
			clientsWithDrops = append(clientsWithDrops, map[string]interface{}{
				"id":      id,
				"dropped": dropped,
			})
		}
	}

	if len(clientsWithDrops) > 0 {
		stats["clients_with_drops"] = clientsWithDrops
	}

	return stats
}