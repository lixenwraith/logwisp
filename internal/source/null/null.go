package null

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/source"

	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSource("null", NewNullSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register null source: %v", err))
	}
}

// NullSource generates nothing: it holds a source's place until one is chosen
type NullSource struct {
	id      string
	proxy   *session.Proxy
	session *session.Session

	subscribers []chan core.LogEntry
	logger      *log.Logger

	done chan struct{}

	totalEntries  atomic.Uint64
	startTime     time.Time
	lastEntryTime atomic.Value // time.Time
}

func NewNullSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	if _, err := config.Decode[config.NullSourceOptions]("source", "null", configMap); err != nil {
		return nil, err
	}
	ns := &NullSource{
		id:          id,
		proxy:       proxy,
		subscribers: make([]chan core.LogEntry, 0),
		done:        make(chan struct{}),
		logger:      logger,
	}
	ns.lastEntryTime.Store(time.Time{})

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

func (ns *NullSource) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
	}
}

func (ns *NullSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, 1000)
	ns.subscribers = append(ns.subscribers, ch)
	return ch
}

func (ns *NullSource) Start() error {
	ns.startTime = time.Now()
	ns.proxy.UpdateActivity(ns.session.ID)
	ns.logger.Debug("msg", "Null source started",
		"component", "null_source",
		"instance_id", ns.id)
	return nil
}

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
