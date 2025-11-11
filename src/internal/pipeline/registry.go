// FILE: src/internal/pipeline/registry.go
package pipeline

import (
	"fmt"
	"logwisp/src/internal/plugin"
	"sync"

	"logwisp/src/internal/session"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// SourceFactory creates source instances with required dependencies
type SourceFactory func(
	id string,
	config map[string]any,
	logger *log.Logger,
	sessions *session.Proxy,
) (source.Source, error)

// SinkFactory creates sink instances with required dependencies
type SinkFactory func(
	id string,
	config map[string]any,
	logger *log.Logger,
	sessions *session.Proxy,
) (sink.Sink, error)

// Registry manages plugin instances for a single pipeline
type Registry struct {
	pipelineName string

	// Instance tracking
	sourceInstances map[string]source.Source
	sinkInstances   map[string]sink.Sink
	// Type count tracking (for single instance enforcement)
	sourceTypeCounts map[string]int
	sinkTypeCounts   map[string]int

	mu     sync.RWMutex
	logger *log.Logger
}

// NewRegistry creates a new registry for a pipeline
func NewRegistry(pipelineName string, logger *log.Logger) *Registry {
	return &Registry{
		pipelineName:    pipelineName,
		sourceInstances: make(map[string]source.Source),
		sinkInstances:   make(map[string]sink.Sink),
		logger:          logger,
	}
}

// CreateSource creates and tracks a source instance
func (r *Registry) CreateSource(
	id string,
	pluginType string,
	config map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate instance ID
	if _, exists := r.sourceInstances[id]; exists {
		return nil, fmt.Errorf("source instance with ID %s already exists", id)
	}

	// Check single instance constraint
	if meta, ok := plugin.GetSourceMetadata(pluginType); ok {
		if meta.MaxInstances == 1 && r.sourceTypeCounts[pluginType] >= 1 {
			return nil, fmt.Errorf("source type %s only allows single instance", pluginType)
		}
	}

	// Get source constructor
	constructor, ok := plugin.GetSource(pluginType)
	if !ok {
		return nil, fmt.Errorf("unknown source type: %s", pluginType)
	}

	// Create instance
	src, err := constructor(id, config, logger, proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to create source %s: %w", id, err)
	}

	// Track instance
	r.sourceInstances[id] = src
	r.sourceTypeCounts[pluginType]++

	r.logger.Info("msg", "Created source instance",
		"pipeline", r.pipelineName,
		"id", id,
		"type", pluginType)

	return src, nil
}

// CreateSink creates and tracks a sink instance
func (r *Registry) CreateSink(
	id string,
	pluginType string,
	config map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate instance ID
	if _, exists := r.sinkInstances[id]; exists {
		return nil, fmt.Errorf("sink instance with ID %s already exists", id)
	}

	// Check single instance constraint
	if meta, ok := plugin.GetSinkMetadata(pluginType); ok {
		if meta.MaxInstances == 1 && r.sinkTypeCounts[pluginType] >= 1 {
			return nil, fmt.Errorf("sink type %s only allows single instance", pluginType)
		}
	}

	// Get sink constructor
	constructor, ok := plugin.GetSink(pluginType)
	if !ok {
		return nil, fmt.Errorf("unknown sink type: %s", pluginType)
	}

	// Create instance
	snk, err := constructor(id, config, logger, proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to create sink %s: %w", id, err)
	}

	// Track instance
	r.sinkInstances[id] = snk
	r.sinkTypeCounts[pluginType]++

	r.logger.Info("msg", "Created sink instance",
		"pipeline", r.pipelineName,
		"id", id,
		"type", pluginType)

	return snk, nil
}

// GetSourceInstance retrieves a source instance by ID
func (r *Registry) GetSourceInstance(id string) (source.Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src, exists := r.sourceInstances[id]
	return src, exists
}

// GetSinkInstance retrieves a sink instance by ID
func (r *Registry) GetSinkInstance(id string) (sink.Sink, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snk, exists := r.sinkInstances[id]
	return snk, exists
}

// GetAllSources returns all source instances
func (r *Registry) GetAllSources() map[string]source.Source {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sources := make(map[string]source.Source, len(r.sourceInstances))
	for k, v := range r.sourceInstances {
		sources[k] = v
	}
	return sources
}

// GetAllSinks returns all sink instances
func (r *Registry) GetAllSinks() map[string]sink.Sink {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sinks := make(map[string]sink.Sink, len(r.sinkInstances))
	for k, v := range r.sinkInstances {
		sinks[k] = v
	}
	return sinks
}

// RemoveSource removes a source instance
func (r *Registry) RemoveSource(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Decrement type count
	if src, exists := r.sourceInstances[id]; exists {
		stats := src.GetStats()
		if pluginType, ok := stats.Details["type"].(string); ok {
			r.sourceTypeCounts[pluginType]--
		}
	}

	delete(r.sourceInstances, id)
}

// RemoveSink removes a sink instance
func (r *Registry) RemoveSink(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Decrement type count
	if snk, exists := r.sinkInstances[id]; exists {
		stats := snk.GetStats()
		if pluginType, ok := stats.Details["type"].(string); ok {
			r.sinkTypeCounts[pluginType]--
		}
	}

	delete(r.sinkInstances, id)
}