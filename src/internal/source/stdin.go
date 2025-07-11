// FILE: src/internal/source/stdin.go
package source

import (
	"bufio"
	"os"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/log"
)

// StdinSource reads log entries from standard input
type StdinSource struct {
	subscribers    []chan LogEntry
	done           chan struct{}
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
	logger         *log.Logger
}

// NewStdinSource creates a new stdin source
func NewStdinSource(options map[string]any, logger *log.Logger) (*StdinSource, error) {
	s := &StdinSource{
		done:      make(chan struct{}),
		startTime: time.Now(),
		logger:    logger,
	}
	s.lastEntryTime.Store(time.Time{})
	return s, nil
}

func (s *StdinSource) Subscribe() <-chan LogEntry {
	ch := make(chan LogEntry, 1000)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

func (s *StdinSource) Start() error {
	go s.readLoop()
	s.logger.Info("msg", "Stdin source started", "component", "stdin_source")
	return nil
}

func (s *StdinSource) Stop() {
	close(s.done)
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.logger.Info("msg", "Stdin source stopped", "component", "stdin_source")
}

func (s *StdinSource) GetStats() SourceStats {
	lastEntry, _ := s.lastEntryTime.Load().(time.Time)

	return SourceStats{
		Type:           "stdin",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details:        map[string]any{},
	}
}

func (s *StdinSource) ApplyRateLimit(entry LogEntry) (LogEntry, bool) {
	// TODO: Implement source-side rate limiting for aggregation/summarization
	// For now, just pass through unchanged
	return entry, true
}

func (s *StdinSource) readLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-s.done:
			return
		default:
			line := scanner.Text()
			if line == "" {
				continue
			}

			entry := LogEntry{
				Time:    time.Now(),
				Source:  "stdin",
				Message: line,
				Level:   extractLogLevel(line),
			}

			// Apply rate limiting
			entry, allowed := s.ApplyRateLimit(entry)
			if !allowed {
				continue
			}

			s.publish(entry)
		}
	}

	if err := scanner.Err(); err != nil {
		s.logger.Error("msg", "Scanner error reading stdin",
			"component", "stdin_source",
			"error", err)
	}
}

func (s *StdinSource) publish(entry LogEntry) {
	s.totalEntries.Add(1)
	s.lastEntryTime.Store(entry.Time)

	for _, ch := range s.subscribers {
		select {
		case ch <- entry:
		default:
			s.droppedEntries.Add(1)
			s.logger.Debug("msg", "Dropped log entry - subscriber buffer full",
				"component", "stdin_source")
		}
	}
}