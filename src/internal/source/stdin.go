// FILE: logwisp/src/internal/source/stdin.go
package source

import (
	"bufio"
	"os"
	"sync/atomic"
	"time"

	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Reads log entries from standard input
type StdinSource struct {
	subscribers    []chan core.LogEntry
	done           chan struct{}
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	bufferSize     int64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
	logger         *log.Logger
}

func NewStdinSource(options map[string]any, logger *log.Logger) (*StdinSource, error) {
	bufferSize := int64(1000) // default
	if bufSize, ok := options["buffer_size"].(int64); ok && bufSize > 0 {
		bufferSize = bufSize
	}

	source := &StdinSource{
		bufferSize:  bufferSize,
		subscribers: make([]chan core.LogEntry, 0),
		done:        make(chan struct{}),
		logger:      logger,
		startTime:   time.Now(),
	}
	source.lastEntryTime.Store(time.Time{})
	return source, nil
}

func (s *StdinSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, s.bufferSize)
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

			entry := core.LogEntry{
				Time:    time.Now(),
				Source:  "stdin",
				Message: line,
				Level:   extractLogLevel(line),
				RawSize: int64(len(line)),
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

func (s *StdinSource) publish(entry core.LogEntry) {
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