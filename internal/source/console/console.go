package console

import (
	"bufio"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/source"

	lconfig "github.com/lixenwraith/config"
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
	done chan struct{}

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
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
	if err := lconfig.ScanMap(configMap, opts); err != nil {
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
	go s.readLoop()

	// Update session activity
	s.proxy.UpdateActivity(s.session.ID)

	s.logger.Info("msg", "Console source started",
		"component", "console_source",
		"instance_id", s.id)
	return nil
}

// Stop signals the source to stop reading.
func (s *ConsoleSource) Stop() {
	close(s.done)

	// Remove session
	if s.session != nil {
		s.proxy.RemoveSession(s.session.ID)
	}

	// Close subscriber channels
	for _, ch := range s.subscribers {
		close(ch)
	}

	s.logger.Info("msg", "Console source stopped",
		"component", "console_source",
		"instance_id", s.id)
}

// GetStats returns the source's statistics
func (s *ConsoleSource) GetStats() source.SourceStats {
	lastEntry, _ := s.lastEntryTime.Load().(time.Time)

	return source.SourceStats{
		Type:           "console",
		TotalEntries:   s.totalEntries.Load(),
		DroppedEntries: s.droppedEntries.Load(),
		StartTime:      s.startTime,
		LastEntryTime:  lastEntry,
		Details:        map[string]any{},
	}
}

// readLoop continuously reads lines from stdin and publishes them
func (s *ConsoleSource) readLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-s.done:
			return
		default:
			// Update session activity on each read
			s.proxy.UpdateActivity(s.session.ID)

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
				Level:   source.ExtractLogLevel(string(lineBytes)),
				RawSize: int64(len(lineWithNewline)),
			}

			s.publish(entry)
		}
	}

	if err := scanner.Err(); err != nil {
		s.logger.Error("msg", "Scanner error reading stdin",
			"component", "console_source",
			"instance_id", s.id,
			"error", err)
	}
}

// publish sends a log entry to all subscribers
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