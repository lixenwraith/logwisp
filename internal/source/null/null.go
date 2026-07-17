package null

import (
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/source"

	"github.com/lixenwraith/log"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSource("null", NewNullSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register null source: %v", err))
	}
}

// NullSource generates no log entries, used for testing
type NullSource struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Application
	subscribers []chan core.LogEntry
	logger      *log.Logger

	// Runtime
	done chan struct{}

	// Statistics
	totalEntries  atomic.Uint64
	startTime     time.Time
	lastEntryTime atomic.Value // time.Time
}

// NewNullSourcePlugin creates a null source through plugin factory
func NewNullSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	ns := &NullSource{
		id:          id,
		proxy:       proxy,
		subscribers: make([]chan core.LogEntry, 0),
		done:        make(chan struct{}),
		logger:      logger,
	}
	ns.lastEntryTime.Store(time.Time{})

	// Create session for null source
	ns.session = proxy.CreateSession(
		"null://void",
		map[string]any{
			"instance_id": id,
			"type":        "null",
		},
	)

	logger.Debug("msg", "Null source initialized",
		"component", "null_source",
		"instance_id", id)

	return ns, nil
}

// Capabilities returns supported capabilities
func (ns *NullSource) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
	}
}

// Subscribe returns a channel for receiving log entries
func (ns *NullSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, 1000)
	ns.subscribers = append(ns.subscribers, ch)
	return ch
}

// Start begins the source operation (no-op for null source)
func (ns *NullSource) Start() error {
	ns.startTime = time.Now()
	ns.proxy.UpdateActivity(ns.session.ID)
	ns.logger.Debug("msg", "Null source started",
		"component", "null_source",
		"instance_id", ns.id)
	return nil
}

// Stop signals the source to stop
func (ns *NullSource) Stop() {
	close(ns.done)
	if ns.session != nil {
		ns.proxy.RemoveSession(ns.session.ID)
	}
	for _, ch := range ns.subscribers {
		close(ch)
	}
	ns.logger.Debug("msg", "Null source stopped",
		"component", "null_source",
		"instance_id", ns.id)
}

// GetStats returns the source's statistics
func (ns *NullSource) GetStats() source.SourceStats {
	lastEntry, _ := ns.lastEntryTime.Load().(time.Time)

	return source.SourceStats{
		ID:            ns.id,
		Type:          "null",
		TotalEntries:  ns.totalEntries.Load(),
		StartTime:     ns.startTime,
		LastEntryTime: lastEntry,
		Details:       map[string]any{},
	}
}