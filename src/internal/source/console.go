// FILE: logwisp/src/internal/source/console.go
package source

import (
	"bufio"
	"os"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// ConsoleSource reads log entries from the standard input stream.
type ConsoleSource struct {
	// Configuration
	config *config.ConsoleSourceOptions

	// Application
	subscribers []chan core.LogEntry
	logger      *log.Logger

	// Runtime
	done chan struct{}

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

// NewConsoleSource creates a new console(stdin) source.
func NewConsoleSource(opts *config.ConsoleSourceOptions, logger *log.Logger) (*ConsoleSource, error) {
	if opts == nil {
		opts = &config.ConsoleSourceOptions{
			BufferSize: 1000, // Default
		}
	}

	source := &ConsoleSource{
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		done:        make(chan struct{}),
		logger:      logger,
		startTime:   time.Now(),
	}
	source.lastEntryTime.Store(time.Time{})
	return source, nil
}

// Subscribe returns a channel for receiving log entries.
func (s *ConsoleSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, s.config.BufferSize)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

// Start begins reading from the standard input.
func (s *ConsoleSource) Start() error {
	go s.readLoop()
	s.logger.Info("msg", "Console source started", "component", "console_source")
	return nil
}

// Stop signals the source to stop reading.
func (s *ConsoleSource) Stop() {
	close(s.done)
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.logger.Info("msg", "Console source stopped", "component", "console_source")
}

// GetStats returns the source's statistics.
func (s *ConsoleSource) GetStats() SourceStats {
	lastEntry, _ := s.lastEntryTime.Load().(time.Time)

	return SourceStats{
		Type:           "console",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details:        map[string]any{},
	}
}

// readLoop continuously reads lines from stdin and publishes them.
func (s *ConsoleSource) readLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-s.done:
			return
		default:
			// Get raw line
			lineBytes := scanner.Bytes()
			if len(lineBytes) == 0 {
				continue
			}

			// Add newline back (scanner strips it)
			lineWithNewline := append(lineBytes, '\n')

			entry := core.LogEntry{
				Time:    time.Now(),
				Source:  "console",
				Message: string(lineWithNewline), // Keep newline
				Level:   extractLogLevel(string(lineBytes)),
				RawSize: int64(len(lineWithNewline)),
			}

			s.publish(entry)
		}
	}

	if err := scanner.Err(); err != nil {
		s.logger.Error("msg", "Scanner error reading stdin",
			"component", "console_source",
			"error", err)
	}
}

// publish sends a log entry to all subscribers.
func (s *ConsoleSource) publish(entry core.LogEntry) {
	s.totalEntries.Add(1)
	s.lastEntryTime.Store(entry.Time)

	for _, ch := range s.subscribers {
		select {
		case ch <- entry:
		default:
			s.droppedEntries.Add(1)
			s.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
				"component", "console_source")
		}
	}
}