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
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool
}

// PipelineStats contains runtime statistics for a pipeline
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
		Stats:    &PipelineStats{},
		logger:   logger,
		ctx:      pipelineCtx,
		cancel:   pipelineCancel,
	}

	// Create flow processor
	// Create flow processor
	flowProcessor, err := flow.NewFlow(cfg.Flow, logger)
	if err != nil {
		// If flow fails, stop session manager
		sessionManager.Stop()
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

// run is the central processing loop that connects sources, flow, and sinks
func (p *Pipeline) run() {
	defer p.wg.Done()
	defer p.logger.Info("msg", "Pipeline processing loop stopped", "pipeline", p.Config.Name)

	var componentWg sync.WaitGroup

	// Start a goroutine for each source to fan-in data
	for _, src := range p.Sources {
		componentWg.Add(1)
		go func(s source.Source) {
			defer componentWg.Done()
			ch := s.Subscribe()
			for {
				select {
				case entry, ok := <-ch:
					if !ok {
						return
					}
					// Process and distribute the log entry
					if event, passed := p.Flow.Process(entry); passed {
						// Fan-out to all sinks
						for _, snk := range p.Sinks {
							snk.Input() <- event
						}
					}
				case <-p.ctx.Done():
					return
				}
			}
		}(src)
	}

	// Start heartbeat generator if enabled
	if heartbeatCh := p.Flow.StartHeartbeat(p.ctx); heartbeatCh != nil {
		componentWg.Add(1)
		go func() {
			defer componentWg.Done()
			for {
				select {
				case event, ok := <-heartbeatCh:
					if !ok {
						return
					}
					// Fan-out heartbeat to all sinks
					for _, snk := range p.Sinks {
						snk.Input() <- event
					}
				case <-p.ctx.Done():
					return
				}
			}
		}()
	}

	componentWg.Wait()
}

// Start starts the pipeline operation and all its components including flow, sources, and sinks
func (p *Pipeline) Start() error {
	if !p.running.CompareAndSwap(false, true) {
		return fmt.Errorf("pipeline %s is already running", p.Config.Name)
	}

	p.logger.Info("msg", "Starting pipeline", "pipeline", p.Config.Name)
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Start all sinks
	for id, s := range p.Sinks {
		if err := s.Start(p.ctx); err != nil {
			return fmt.Errorf("failed to start sink %s: %w", id, err)
		}
	}

	// Start all sources
	for id, src := range p.Sources {
		if err := src.Start(); err != nil {
			return fmt.Errorf("failed to start source %s: %w", id, err)
		}
	}

	// Start the central processing loop
	p.Stats.StartTime = time.Now()
	p.wg.Add(1)
	go p.run()

	return nil
}

// Stop stops the pipeline operation and all its components including flow, sources, and sinks
func (p *Pipeline) Stop() error {
	if !p.running.CompareAndSwap(true, false) {
		return fmt.Errorf("pipeline %s is not running", p.Config.Name)
	}

	p.logger.Info("msg", "Stopping pipeline", "pipeline", p.Config.Name)

	// Signal all components and the run loop to stop
	p.cancel()

	// Stop all sources concurrently to halt new data ingress
	var sourceWg sync.WaitGroup
	for _, src := range p.Sources {
		sourceWg.Add(1)
		go func(s source.Source) {
			defer sourceWg.Done()
			s.Stop()
		}(src)
	}
	sourceWg.Wait()

	// Wait for the run loop to finish processing and sending all in-flight data
	p.wg.Wait()

	// Stop all sinks concurrently now that no new data will be sent
	var sinkWg sync.WaitGroup
	for _, s := range p.Sinks {
		sinkWg.Add(1)
		go func(snk sink.Sink) {
			defer sinkWg.Done()
			snk.Stop()
		}(s)
	}
	sinkWg.Wait()

	p.logger.Info("msg", "Pipeline stopped", "pipeline", p.Config.Name)
	return nil
}

// Shutdown gracefully stops the pipeline and all its components, deinitializing them for app shutdown or complete pipeline removal by service
func (p *Pipeline) Shutdown() {
	p.logger.Info("msg", "Shutting down pipeline",
		"component", "pipeline",
		"pipeline", p.Config.Name)

	// Ensure the pipeline is stopped before shutting down
	if p.running.Load() {
		if err := p.Stop(); err != nil {
			p.logger.Error("msg", "Error stopping pipeline during shutdown", "error", err)
		}
	}

	// Stop long-running components
	if p.Sessions != nil {
		p.Sessions.Stop()
	}

	p.logger.Info("msg", "Pipeline shutdown complete",
		"component", "pipeline",
		"pipeline", p.Config.Name)
}

// GetStats returns a map of pipeline statistics
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
	var totalFiltered uint64
	if p.Flow != nil {
		flowStats = p.Flow.GetStats()
		// Extract total_filtered from flow for top-level visibility
		if filters, ok := flowStats["filters"].(map[string]any); ok {
			if totalPassed, ok := filters["total_passed"].(uint64); ok {
				if totalProcessed, ok := filters["total_processed"].(uint64); ok {
					totalFiltered = totalProcessed - totalPassed
				}
			}
		}
	}

	var uptime int
	if p.running.Load() && !p.Stats.StartTime.IsZero() {
		uptime = int(time.Since(p.Stats.StartTime).Seconds())
	}

	return map[string]any{
		"name":            p.Config.Name,
		"running":         p.running.Load(),
		"uptime_seconds":  uptime,
		"total_processed": p.Stats.TotalEntriesProcessed.Load(),
		"total_filtered":  totalFiltered,
		"source_count":    len(p.Sources),
		"sources":         sourceStats,
		"sink_count":      len(p.Sinks),
		"sinks":           sinkStats,
		"flow":            flowStats,
	}
}

// TODO: incomplete implementation
// startStatsUpdater runs a periodic stats updater
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