// FILE: src/internal/plugin/factory.go
package plugin

import (
	"fmt"
	"sync"

	"logwisp/src/internal/core"
	"logwisp/src/internal/session"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

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

// global variables holding available source and sink plugins
var (
	sourceFactories map[string]SourceFactory
	sinkFactories   map[string]SinkFactory
	sourceMetadata  map[string]*PluginMetadata
	sinkMetadata    map[string]*PluginMetadata
	mu              sync.RWMutex
	// once            sync.Once
)

func init() {
	sourceFactories = make(map[string]SourceFactory)
	sinkFactories = make(map[string]SinkFactory)
}

// RegisterSource registers a source factory function
func RegisterSource(name string, constructor SourceFactory) error {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := sourceFactories[name]; exists {
		return fmt.Errorf("source type %s already registered", name)
	}
	sourceFactories[name] = constructor

	// Set default metadata
	sourceMetadata[name] = &PluginMetadata{
		MaxInstances: 0, // Unlimited by default
	}

	return nil
}

// RegisterSink registers a sink factory function
func RegisterSink(name string, constructor SinkFactory) error {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := sinkFactories[name]; exists {
		return fmt.Errorf("sink type %s already registered", name)
	}
	sinkFactories[name] = constructor

	// Set default metadata
	sinkMetadata[name] = &PluginMetadata{
		MaxInstances: 0, // Unlimited by default
	}

	return nil
}

// SetSourceMetadata sets metadata for a source type (call after RegisterSource)
func SetSourceMetadata(name string, metadata *PluginMetadata) error {
	mu.Lock()

	defer mu.Unlock()

	if _, exists := sourceFactories[name]; !exists {
		return fmt.Errorf("source type %s not registered", name)
	}
	sourceMetadata[name] = metadata

	return nil
}

// SetSinkMetadata sets metadata for a sink type (call after RegisterSink)
func SetSinkMetadata(name string, metadata *PluginMetadata) error {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := sinkFactories[name]; !exists {
		return fmt.Errorf("sink type %s not registered", name)
	}
	sinkMetadata[name] = metadata
	return nil
}

// GetSource retrieves a source factory function
func GetSource(name string) (SourceFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	constructor, exists := sourceFactories[name]
	return constructor, exists
}

// GetSink retrieves a sink factory function
func GetSink(name string) (SinkFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	constructor, exists := sinkFactories[name]
	return constructor, exists
}

// GetSourceMetadata retrieves metadata for a source type
func GetSourceMetadata(name string) (*PluginMetadata, bool) {
	mu.RLock()
	defer mu.RUnlock()
	meta, exists := sourceMetadata[name]
	return meta, exists
}

// GetSinkMetadata retrieves metadata for a sink type
func GetSinkMetadata(name string) (*PluginMetadata, bool) {
	mu.RLock()
	defer mu.RUnlock()
	meta, exists := sinkMetadata[name]
	return meta, exists
}

// ListSources returns all registered source types
func ListSources() []string {
	mu.RLock()
	defer mu.RUnlock()

	types := make([]string, 0, len(sourceFactories))
	for t := range sourceFactories {
		types = append(types, t)
	}
	return types
}

// ListSinks returns all registered sink types
func ListSinks() []string {
	mu.RLock()
	defer mu.RUnlock()

	types := make([]string, 0, len(sinkFactories))
	for t := range sinkFactories {
		types = append(types, t)
	}
	return types
}