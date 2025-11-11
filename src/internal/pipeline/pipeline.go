// FILE: logwisp/src/internal/pipeline/pipeline.go
package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/flow"
	"logwisp/src/internal/session"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Pipeline manages the flow of data from sources, through filters, to sinks
type Pipeline struct {
	Config *config.PipelineConfig

	// Components
	Registry *Registry
	Sources  map[string]source.Source // Track instances by ID
	Sinks    map[string]sink.Sink
	Sessions *session.Manager

	// Pipeline flow
	Flow   *flow.Flow
	Stats  *PipelineStats
	logger *log.Logger

	// Runtime
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PipelineStats contains runtime statistics for a pipeline.
type PipelineStats struct {
	StartTime                      time.Time
	TotalEntriesProcessed          atomic.Uint64
	TotalEntriesDroppedByRateLimit atomic.Uint64
	TotalEntriesFiltered           atomic.Uint64
	SourceStats                    []source.SourceStats
	SinkStats                      []sink.SinkStats
	FlowStats                      map[string]any
}

// NewPipeline creates a new pipeline with registry support
func NewPipeline(
	cfg *config.PipelineConfig,
	logger *log.Logger,
) (*Pipeline, error) {
	// Create pipeline context
	pipelineCtx, pipelineCancel := context.WithCancel(context.Background())

	// Create session manager with default timeout
	sessionManager := session.NewManager(core.SessionDefaultMaxIdleTime)

	// Create pipeline instance with registry
	pipeline := &Pipeline{
		Config:   cfg,
		Registry: NewRegistry(cfg.Name, logger),
		Sessions: sessionManager,
		Sources:  make(map[string]source.Source),
		Sinks:    make(map[string]sink.Sink),
		ctx:      pipelineCtx,
		cancel:   pipelineCancel,
		logger:   logger,
	}

	// Create flow processor
	flowProcessor, err := flow.NewFlow(cfg.Flow, logger)
	if err != nil {
		pipelineCancel()
		return nil, fmt.Errorf("failed to create flow processor: %w", err)
	}
	pipeline.Flow = flowProcessor

	// Initialize sources and sinks
	if err := pipeline.initializeComponents(); err != nil {
		pipelineCancel()
		return nil, err
	}

	return pipeline, nil
}

func (p *Pipeline) initializeComponents() error {
	// Create sources based on plugin config if available
	if len(p.Config.PluginSources) > 0 {
		for _, srcCfg := range p.Config.PluginSources {
			// Create session proxy for this source instance
			sessionProxy := session.NewProxy(p.Sessions, srcCfg.ID)

			src, err := p.Registry.CreateSource(
				srcCfg.ID,
				srcCfg.Type,
				srcCfg.Config,
				p.logger,
				sessionProxy,
			)
			if err != nil {
				return fmt.Errorf("failed to create source %s: %w", srcCfg.ID, err)
			}

			// Check and inject capabilities using core interfaces
			if err := p.initSourceCapabilities(src, srcCfg); err != nil {
				return fmt.Errorf("failed to initiate capabilities for source %s: %w", srcCfg.ID, err)
			}

			p.Sources[srcCfg.ID] = src
		}
	} else {
		return fmt.Errorf("no plugin sources defined")
	}

	// Create sinks based on plugin config if available
	if len(p.Config.PluginSinks) > 0 {
		for _, sinkCfg := range p.Config.PluginSinks {
			// Create session proxy for this sink instance
			sessionProxy := session.NewProxy(p.Sessions, sinkCfg.ID)

			snk, err := p.Registry.CreateSink(
				sinkCfg.ID,
				sinkCfg.Type,
				sinkCfg.Config,
				p.logger,
				sessionProxy,
			)
			if err != nil {
				return fmt.Errorf("failed to create sink %s: %w", sinkCfg.ID, err)
			}

			// Check and inject capabilities using core interfaces
			if err := p.initSinkCapabilities(snk, sinkCfg); err != nil {
				return fmt.Errorf("failed to initiate capabilities for sink %s: %w", sinkCfg.ID, err)
			}

			p.Sinks[sinkCfg.ID] = snk
		}
	} else {
		return fmt.Errorf("no plugin sinks defined")
	}

	return nil
}

// initSourceCapabilities checks and injects optional capabilities
func (p *Pipeline) initSourceCapabilities(s source.Source, cfg config.PluginSourceConfig) error {
	// Initiate and activate source capabilities
	for _, c := range s.Capabilities() {
		switch c {
		// Network capabilities
		case core.CapNetLimit, core.CapTLS, core.CapAuth:
			continue // No-op for now, placeholder

		// Session capabilities
		case core.CapSessionAware:
		case core.CapMultiSession:
			continue // TODO

		default:
			return fmt.Errorf("unknown capability type: %s", c)
		}
	}

	return nil
}

// initSinkCapabilities checks and injects optional capabilities
func (p *Pipeline) initSinkCapabilities(s sink.Sink, cfg config.PluginSinkConfig) error {
	// Initiate and activate source capabilities
	for _, c := range s.Capabilities() {
		switch c {
		// Network capabilities
		case core.CapNetLimit, core.CapTLS, core.CapAuth:
			continue // No-op for now, placeholder

		// Session capabilities
		case core.CapSessionAware:
		case core.CapMultiSession:
			continue // TODO

		default:
			return fmt.Errorf("unknown capability type: %s", c)
		}
	}

	return nil
}

// Shutdown gracefully stops the pipeline and all its components.
func (p *Pipeline) Shutdown() {
	p.logger.Info("msg", "Shutting down pipeline",
		"component", "pipeline",
		"pipeline", p.Config.Name)

	// Cancel context to stop processing
	p.cancel()

	// Stop all sinks first
	var wg sync.WaitGroup
	for _, s := range p.Sinks {
		wg.Add(1)
		go func(sink sink.Sink) {
			defer wg.Done()
			sink.Stop()
		}(s)
	}
	wg.Wait()

	// Stop all sources
	for _, src := range p.Sources {
		wg.Add(1)
		go func(source source.Source) {
			defer wg.Done()
			source.Stop()
		}(src)
	}
	wg.Wait()

	// Wait for processing goroutines
	p.wg.Wait()

	p.logger.Info("msg", "Pipeline shutdown complete",
		"component", "pipeline",
		"pipeline", p.Config.Name)
}

// GetStats returns a map of the pipeline's current statistics.
func (p *Pipeline) GetStats() map[string]any {
	// Recovery to handle concurrent access during shutdown
	// When service is shutting down, sources/sinks might be nil or partially stopped
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("msg", "Panic getting pipeline stats",
				"pipeline", p.Config.Name,
				"panic", r)
		}
	}()

	// Collect source stats
	sourceStats := make([]map[string]any, 0, len(p.Sources))
	for _, src := range p.Sources {
		if src == nil {
			continue // Skip nil sources
		}

		stats := src.GetStats()
		sourceStats = append(sourceStats, map[string]any{
			"id":              stats.ID,
			"type":            stats.Type,
			"total_entries":   stats.TotalEntries,
			"dropped_entries": stats.DroppedEntries,
			"start_time":      stats.StartTime,
			"last_entry_time": stats.LastEntryTime,
			"details":         stats.Details,
		})
	}

	// Collect sink stats
	sinkStats := make([]map[string]any, 0, len(p.Sinks))
	for _, s := range p.Sinks {
		if s == nil {
			continue // Skip nil sinks
		}

		stats := s.GetStats()
		sinkStats = append(sinkStats, map[string]any{
			"id":                 stats.ID,
			"type":               stats.Type,
			"total_processed":    stats.TotalProcessed,
			"active_connections": stats.ActiveConnections,
			"start_time":         stats.StartTime,
			"last_processed":     stats.LastProcessed,
			"details":            stats.Details,
		})
	}

	// Get flow stats
	var flowStats map[string]any
	if p.Flow != nil {
		flowStats = p.Flow.GetStats()
	}

	return map[string]any{
		"name":            p.Config.Name,
		"uptime_seconds":  int(time.Since(p.Stats.StartTime).Seconds()),
		"total_processed": p.Stats.TotalEntriesProcessed.Load(),
		"source_count":    len(p.Sources),
		"sources":         sourceStats,
		"sink_count":      len(p.Sinks),
		"sinks":           sinkStats,
		"flow":            flowStats,
	}
}

// TODO: incomplete implementation
// startStatsUpdater runs a periodic stats updater.
func (p *Pipeline) startStatsUpdater(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(core.ServiceStatsUpdateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Periodic stats updates if needed
			}
		}
	}()
}