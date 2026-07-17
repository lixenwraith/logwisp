package plugin

import (
	"fmt"
	"sync"

	"logwisp/internal/core"
	"logwisp/internal/session"
	"logwisp/internal/sink"
	"logwisp/internal/source"

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

// PluginMetadata stores metadata about a plugin type
type PluginMetadata struct {
	Capabilities []core.Capability
	MaxInstances int // 0 = unlimited, 1 = single instance only
}

// registry encapsulates all plugin factories with lazy initialization
type registry struct {
	sourceFactories map[string]SourceFactory
	sinkFactories   map[string]SinkFactory
	sourceMetadata  map[string]*PluginMetadata
	sinkMetadata    map[string]*PluginMetadata
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
			sourceMetadata:  make(map[string]*PluginMetadata),
			sinkMetadata:    make(map[string]*PluginMetadata),
		}
	})
	return globalRegistry
}

// RegisterSource registers a source factory function
func RegisterSource(name string, constructor SourceFactory) error {
	r := getRegistry()
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sourceFactories[name]; exists {
		return fmt.Errorf("source type %s already registered", name)
	}
	r.sourceFactories[name] = constructor

	// Set default metadata
	r.sourceMetadata[name] = &PluginMetadata{
		MaxInstances: 0, // Unlimited by default
	}

	return nil
}

// RegisterSink registers a sink factory function
func RegisterSink(name string, constructor SinkFactory) error {
	r := getRegistry()
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sinkFactories[name]; exists {
		return fmt.Errorf("sink type %s already registered", name)
	}
	r.sinkFactories[name] = constructor

	// Set default metadata
	r.sinkMetadata[name] = &PluginMetadata{
		MaxInstances: 0, // Unlimited by default
	}

	return nil
}

// SetSourceMetadata sets metadata for a source type (call after RegisterSource)
func SetSourceMetadata(name string, metadata *PluginMetadata) error {
	r := getRegistry()
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sourceFactories[name]; !exists {
		return fmt.Errorf("source type %s not registered", name)
	}
	r.sourceMetadata[name] = metadata

	return nil
}

// SetSinkMetadata sets metadata for a sink type (call after RegisterSink)
func SetSinkMetadata(name string, metadata *PluginMetadata) error {
	r := getRegistry()
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sinkFactories[name]; !exists {
		return fmt.Errorf("sink type %s not registered", name)
	}
	r.sinkMetadata[name] = metadata
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

// GetSourceMetadata retrieves metadata for a source type
func GetSourceMetadata(name string) (*PluginMetadata, bool) {
	r := getRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()
	meta, exists := r.sourceMetadata[name]
	return meta, exists
}

// GetSinkMetadata retrieves metadata for a sink type
func GetSinkMetadata(name string) (*PluginMetadata, bool) {
	r := getRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()
	meta, exists := r.sinkMetadata[name]
	return meta, exists
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