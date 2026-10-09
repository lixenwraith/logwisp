package plugin

import (
	"fmt"
	"sync"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/source"

	"github.com/lixenwraith/log"
)

// SourceFactory creates source instances
type SourceFactory func(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	sessions *session.Proxy,
) (source.Source, error)

// SinkFactory creates sink instances
type SinkFactory func(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	sessions *session.Proxy,
) (sink.Sink, error)

// registry encapsulates all plugin factories with lazy initialization
type registry struct {
	sourceFactories map[string]SourceFactory
	sinkFactories   map[string]SinkFactory
	mu              sync.RWMutex
}

var (
	globalRegistry *registry
	once           sync.Once
)

// getRegistry returns the singleton registry, initializing on first access
func getRegistry() *registry {
	once.Do(func() {
		globalRegistry = &registry{
			sourceFactories: make(map[string]SourceFactory),
			sinkFactories:   make(map[string]SinkFactory),
		}
	})
	return globalRegistry
}

// RegisterSource registers a source factory function for a type the
// catalogue (config.LookupPlugin) has a row for
func RegisterSource(name string, constructor SourceFactory) error {
	if _, ok := config.LookupPlugin("source", name); !ok {
		return fmt.Errorf("source type %s has no catalogue row", name)
	}
	r := getRegistry()
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sourceFactories[name]; exists {
		return fmt.Errorf("source type %s already registered", name)
	}
	r.sourceFactories[name] = constructor
	return nil
}

// RegisterSink registers a sink factory function for a type the catalogue
// has a row for
func RegisterSink(name string, constructor SinkFactory) error {
	if _, ok := config.LookupPlugin("sink", name); !ok {
		return fmt.Errorf("sink type %s has no catalogue row", name)
	}
	r := getRegistry()
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sinkFactories[name]; exists {
		return fmt.Errorf("sink type %s already registered", name)
	}
	r.sinkFactories[name] = constructor
	return nil
}

// GetSource retrieves a source factory function
func GetSource(name string) (SourceFactory, bool) {
	r := getRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()
	constructor, exists := r.sourceFactories[name]
	return constructor, exists
}

// GetSink retrieves a sink factory function
func GetSink(name string) (SinkFactory, bool) {
	r := getRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()
	constructor, exists := r.sinkFactories[name]
	return constructor, exists
}

// ListSources returns all registered source types
func ListSources() []string {
	r := getRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.sourceFactories))
	for t := range r.sourceFactories {
		types = append(types, t)
	}
	return types
}

// ListSinks returns all registered sink types
func ListSinks() []string {
	r := getRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.sinkFactories))
	for t := range r.sinkFactories {
		types = append(types, t)
	}
	return types
}
