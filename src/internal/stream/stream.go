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
	clients    map[string]chan monitor.LogEntry
	register   chan *client
	unregister chan string
	broadcast  chan monitor.LogEntry
	mu         sync.RWMutex
	bufferSize int
	done       chan struct{}
}

type client struct {
	id      string
	channel chan monitor.LogEntry
}

// New creates a new SSE streamer
func New(bufferSize int) *Streamer {
	s := &Streamer{
		clients:    make(map[string]chan monitor.LogEntry),
		register:   make(chan *client),
		unregister: make(chan string),
		broadcast:  make(chan monitor.LogEntry, bufferSize),
		bufferSize: bufferSize,
		done:       make(chan struct{}),
	}

	go s.run()
	return s
}

// run manages client connections
func (s *Streamer) run() {
	for {
		select {
		case c := <-s.register:
			s.mu.Lock()
			s.clients[c.id] = c.channel
			s.mu.Unlock()

		case id := <-s.unregister:
			s.mu.Lock()
			if ch, ok := s.clients[id]; ok {
				close(ch)
				delete(s.clients, id)
			}
			s.mu.Unlock()

		case entry := <-s.broadcast:
			s.mu.RLock()
			for id, ch := range s.clients {
				select {
				case ch <- entry:
					// Sent successfully
				default:
					// Client buffer full, skip this entry
					// In production, might want to close slow clients
					_ = id
				}
			}
			s.mu.RUnlock()

		case <-s.done:
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
		// Broadcast buffer full, drop entry
		// In production, might want to log this
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

	c := &client{
		id:      clientID,
		channel: ch,
	}

	// Register client
	s.register <- c
	defer func() {
		s.unregister <- clientID
	}()

	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"client_id\":\"%s\"}\n\n", clientID)
	w.(http.Flusher).Flush()

	// Create ticker for heartbeat
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Stream events
	for {
		select {
		case <-r.Context().Done():
			return

		case entry := <-ch:
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}

			fmt.Fprintf(w, "data: %s\n\n", data)
			w.(http.Flusher).Flush()

		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			w.(http.Flusher).Flush()
		}
	}
}

// Stop gracefully shuts down the streamer
func (s *Streamer) Stop() {
	close(s.done)

	// Close all client channels
	s.mu.Lock()
	for id := range s.clients {
		s.unregister <- id
	}
	s.mu.Unlock()
}