package console

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/source"

	"github.com/lixenwraith/log"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSource("console", NewConsoleSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register console source: %v", err))
	}

	// Console stdin can only have one reader
	if err := plugin.SetSourceMetadata("console", &plugin.PluginMetadata{
		Capabilities: []core.Capability{core.CapSessionAware, core.CapSingleInstance},
		MaxInstances: 1,
	}); err != nil {
		panic(fmt.Sprintf("failed to set console source metadata: %v", err))
	}
}

// One reader serves the process: after a reload the new source continues
// where the old one stopped, and no line is read twice. The channel is
// unbuffered, so a busy pipeline stops the reading of stdin, not its lines.
var (
	stdinOnce  sync.Once
	stdinLines chan string
	stdinErr   error // set before stdinLines closes
)

func lines() <-chan string {
	stdinOnce.Do(func() {
		stdinLines = make(chan string)
		go func() {
			stdinErr = readLines(os.Stdin, stdinLines)
			close(stdinLines)
		}()
	})
	return stdinLines
}

// readLines sends r's lines without their terminator (\n or \r\n), the last
// one too when unterminated, until the end of input. A line longer than
// core.MaxLogEntryBytes continues in the next one.
func readLines(r io.Reader, out chan<- string) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		for len(line) > core.MaxLogEntryBytes {
			out <- string(line[:core.MaxLogEntryBytes])
			line = append(line[:0], line[core.MaxLogEntryBytes:]...)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == nil:
			line = line[:len(line)-1]
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
		}
		if len(line) > 0 || err == nil {
			out <- string(line)
		}
		line = line[:0]
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// ConsoleSource reads log entries from the standard input stream
type ConsoleSource struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Configuration
	config *config.ConsoleSourceOptions

	// Application
	subscribers []chan core.LogEntry
	logger      *log.Logger

	// Runtime
	done     chan struct{}
	stopOnce sync.Once

	// Statistics
	totalEntries  atomic.Uint64
	startTime     time.Time
	lastEntryTime atomic.Value // time.Time
	ended         atomic.Bool  // standard input reached its end
}

const (
	DefaultConsoleSourceBufferSize = 1000
)

// NewConsoleSourcePlugin creates a console source through plugin factory
func NewConsoleSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	opts := &config.ConsoleSourceOptions{}

	// Scan config map
	if err := config.Scan(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate and apply defaults
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultConsoleSourceBufferSize
	}

	// Create and return plugin instance
	cs := &ConsoleSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		done:        make(chan struct{}),
		logger:      logger,
	}
	cs.lastEntryTime.Store(time.Time{})

	// Create session
	cs.session = proxy.CreateSession(
		"console_stdin",
		map[string]any{
			"instance_id": id,
			"type":        "console",
		},
	)

	cs.logger.Info("msg", "Console source initialized",
		"component", "console_source",
		"instance_id", id)

	return cs, nil
}

// Capabilities returns supported capabilities
func (s *ConsoleSource) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware, // Single console session
	}
}

// Subscribe returns a channel for receiving log entries.
func (s *ConsoleSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, s.config.BufferSize)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

// Start begins reading from the standard input.
func (s *ConsoleSource) Start() error {
	s.startTime = time.Now()
	go s.readLoop(lines())

	// Update session activity
	s.proxy.UpdateActivity(s.session.ID)

	s.logger.Info("msg", "Console source started",
		"component", "console_source",
		"instance_id", s.id)
	return nil
}

// Stop signals the source to stop reading; readLoop closes the subscribers.
func (s *ConsoleSource) Stop() {
	s.stopOnce.Do(func() { close(s.done) })

	// Remove session
	if s.session != nil {
		s.proxy.RemoveSession(s.session.ID)
	}

	s.logger.Info("msg", "Console source stopped",
		"component", "console_source",
		"instance_id", s.id)
}

// GetStats returns the source's statistics
func (s *ConsoleSource) GetStats() source.SourceStats {
	lastEntry, _ := s.lastEntryTime.Load().(time.Time)

	return source.SourceStats{
		ID:            s.id,
		Type:          "console",
		TotalEntries:  s.totalEntries.Load(),
		StartTime:     s.startTime,
		LastEntryTime: lastEntry,
		Details:       map[string]any{"ended": s.ended.Load()},
	}
}

// readLoop publishes stdin's lines until Stop or the end of input, then
// closes the subscriber channels: it is their only sender.
func (s *ConsoleSource) readLoop(lines <-chan string) {
	defer func() {
		for _, ch := range s.subscribers {
			close(ch)
		}
	}()
	for {
		select {
		case <-s.done:
			return
		case line, ok := <-lines:
			if !ok {
				s.ended.Store(true)
				if stdinErr != nil {
					s.logger.Error("msg", "Failed to read standard input",
						"component", "console_source",
						"instance_id", s.id,
						"error", stdinErr)
				}
				s.logger.Info("msg", "Standard input ended",
					"component", "console_source",
					"instance_id", s.id)
				return
			}
			if line == "" {
				continue
			}
			s.proxy.UpdateActivity(s.session.ID)
			entry := core.LogEntry{
				Time:    time.Now(),
				Source:  "console",
				Message: line,
				Level:   source.ExtractLogLevel(line),
				RawSize: int64(len(line)),
			}
			if !s.publish(entry) {
				return
			}
		}
	}
}

// publish waits for every subscriber: stdin is pulled, so a full pipeline
// slows the reading instead of losing lines. False when stopped meanwhile.
func (s *ConsoleSource) publish(entry core.LogEntry) bool {
	s.totalEntries.Add(1)
	s.lastEntryTime.Store(entry.Time)

	for _, ch := range s.subscribers {
		select {
		case ch <- entry:
		case <-s.done:
			return false
		}
	}
	return true
}
