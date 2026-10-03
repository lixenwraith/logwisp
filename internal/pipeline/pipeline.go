package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/flow"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/source"

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

	// Sinks that stall dispatch rather than drop (core.CapBackpressure)
	backpressure map[string]bool

	// Runtime
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	running      atomic.Bool
	halt         chan struct{} // closed by Stop: backpressure sinks drop again
	finished     chan struct{} // closed when every source has ended
	finishedOnce sync.Once
}

// PipelineStats contains runtime statistics for a pipeline
type PipelineStats struct {
	StartTime                 time.Time
	TotalEntriesDroppedBySink atomic.Uint64
	SourceStats               []source.SourceStats
	SinkStats                 []sink.SinkStats
	FlowStats                 map[string]any
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

		backpressure: make(map[string]bool),
		finished:     make(chan struct{}),
	}

	// Create flow processor
	flowProcessor, err := flow.NewFlow(cfg.Flow, logger)
	if err != nil {
		// If flow fails, stop session manager
		pipelineCancel()
		sessionManager.Stop()
		return nil, fmt.Errorf("failed to create flow processor: %w", err)
	}
	pipeline.Flow = flowProcessor

	// Initialize sources and sinks
	if err := pipeline.initializeComponents(); err != nil {
		pipelineCancel()
		sessionManager.Stop()
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
	var hasTLS, hasAuth bool
	for _, c := range s.Capabilities() {
		switch c {
		// Network capabilities
		case core.CapNetLimit:
			continue // No-op for now, placeholder
		case core.CapTLS, core.CapProxyTLS:
			hasTLS = true
		case core.CapAuth:
			hasAuth = true

		// Session capabilities
		case core.CapSessionAware:
		case core.CapMultiSession:
			continue // TODO

		default:
			return fmt.Errorf("unknown capability type: %s", c)
		}
	}

	if err := checkAuthCapability(hasTLS, hasAuth); err != nil {
		return fmt.Errorf("source %s: %w", cfg.ID, err)
	}

	return nil
}

// checkAuthCapability rejects a plugin that decides on peer identity without a
// transport that verifies one - the decision would rest on an unauthenticated
// claim
func checkAuthCapability(hasTLS, hasAuth bool) error {
	if hasAuth && !hasTLS {
		return fmt.Errorf("capability %q requires %q", core.CapAuth, core.CapTLS)
	}
	return nil
}

// initSinkCapabilities checks and injects optional capabilities
func (p *Pipeline) initSinkCapabilities(s sink.Sink, cfg config.PluginSinkConfig) error {
	// Initiate and activate sink capabilities
	var hasTLS, hasAuth bool
	for _, c := range s.Capabilities() {
		switch c {
		case core.CapBackpressure:
			p.backpressure[cfg.ID] = true

		// Network capabilities
		case core.CapNetLimit:
			continue // No-op for now, placeholder
		case core.CapTLS, core.CapProxyTLS:
			hasTLS = true
		case core.CapAuth:
			hasAuth = true

		// Session capabilities
		case core.CapSessionAware:
		case core.CapMultiSession:
			continue // TODO

		default:
			return fmt.Errorf("unknown capability type: %s", c)
		}
	}

	if err := checkAuthCapability(hasTLS, hasAuth); err != nil {
		return fmt.Errorf("sink %s: %w", cfg.ID, err)
	}

	return nil
}

// run connects the subscribed sources through the flow to the sinks. It
// returns once every source channel has closed, at Stop or at end of input.
func (p *Pipeline) run(subscriptions []<-chan core.LogEntry) {
	defer p.wg.Done()
	defer p.finish()
	defer p.logger.Info("msg", "Pipeline processing loop stopped", "pipeline", p.Config.Name)

	var componentWg sync.WaitGroup
	for _, ch := range subscriptions {
		componentWg.Add(1)
		go func() {
			defer componentWg.Done()
			// Range drains in-flight entries once the source closes the channel
			for entry := range ch {
				if event, passed := p.Flow.Process(entry); passed {
					p.dispatch(event)
				}
			}
		}()
	}

	// Sinks keep p.ctx until Stop, so the heartbeat ends on its own context
	hbCtx, hbCancel := context.WithCancel(p.ctx)
	var hbWg sync.WaitGroup
	if heartbeatCh := p.Flow.StartHeartbeat(hbCtx); heartbeatCh != nil {
		hbWg.Add(1)
		go func() {
			defer hbWg.Done()
			for {
				select {
				case event, ok := <-heartbeatCh:
					if !ok {
						return
					}
					p.dispatch(event)
				case <-hbCtx.Done():
					return
				}
			}
		}()
	}

	componentWg.Wait()
	hbCancel()
	hbWg.Wait()
}

// dispatch sends to every sink. A full sink drops the event so it cannot
// stall its siblings, except a backpressure sink, which waits until Stop.
func (p *Pipeline) dispatch(event core.TransportEvent) {
	for id, snk := range p.Sinks {
		if p.backpressure[id] {
			select {
			case snk.Input() <- event:
			case <-p.halt:
				p.Stats.TotalEntriesDroppedBySink.Add(1)
			}
			continue
		}
		select {
		case snk.Input() <- event:
		default:
			p.Stats.TotalEntriesDroppedBySink.Add(1)
		}
	}
}

func (p *Pipeline) finish() { p.finishedOnce.Do(func() { close(p.finished) }) }

// Finished is closed when every source has ended, or the pipeline shut down.
// Only a finite source (console at end of input) ends without Stop.
func (p *Pipeline) Finished() <-chan struct{} { return p.finished }

// Start starts the pipeline operation and all its components including flow, sources, and sinks
func (p *Pipeline) Start() error {
	if !p.running.CompareAndSwap(false, true) {
		return fmt.Errorf("pipeline %s is already running", p.Config.Name)
	}

	p.logger.Info("msg", "Starting pipeline", "pipeline", p.Config.Name)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.halt = make(chan struct{})

	// Start all sinks
	for id, s := range p.Sinks {
		if err := s.Start(p.ctx); err != nil {
			return fmt.Errorf("failed to start sink %s: %w", id, err)
		}
	}

	// Subscribed before Start: a source publishes from its first entry on
	subscriptions := make([]<-chan core.LogEntry, 0, len(p.Sources))
	for _, src := range p.Sources {
		subscriptions = append(subscriptions, src.Subscribe())
	}
	for id, src := range p.Sources {
		if err := src.Start(); err != nil {
			return fmt.Errorf("failed to start source %s: %w", id, err)
		}
	}

	// Start the central processing loop
	p.Stats.StartTime = time.Now()
	p.wg.Add(1)
	go p.run(subscriptions)

	return nil
}

// Stop stops the pipeline operation and all its components including flow, sources, and sinks
func (p *Pipeline) Stop() error {
	if !p.running.CompareAndSwap(true, false) {
		return fmt.Errorf("pipeline %s is not running", p.Config.Name)
	}

	p.logger.Info("msg", "Stopping pipeline", "pipeline", p.Config.Name)
	close(p.halt)

	// 1. Stop all sources concurrently to halt new data ingress and close their channels
	var sourceWg sync.WaitGroup
	for _, src := range p.Sources {
		sourceWg.Add(1)
		go func(s source.Source) {
			defer sourceWg.Done()
			s.Stop()
		}(src)
	}
	sourceWg.Wait()

	// 2. Wait for the run loop to finish processing and sending all in-flight data
	p.wg.Wait()

	// 3. Stop all sinks concurrently now that no new data will be sent
	var sinkWg sync.WaitGroup
	for _, s := range p.Sinks {
		sinkWg.Add(1)
		go func(snk sink.Sink) {
			defer sinkWg.Done()
			snk.Stop()
		}(s)
	}
	sinkWg.Wait()
	p.cancel()

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
	p.finish() // a pipeline that never started has no run loop to close it

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

	// 1. Live collect source stats
	sources := make([]map[string]any, 0, len(p.Sources))
	for _, src := range p.Sources {
		if src == nil {
			continue
		}
		s := src.GetStats()
		sources = append(sources, map[string]any{
			"id":              s.ID,
			"type":            s.Type,
			"total_entries":   s.TotalEntries,
			"dropped_entries": s.DroppedEntries,
			"start_time":      s.StartTime,
			"last_entry_time": s.LastEntryTime,
			"details":         s.Details,
		})
	}

	// 2. Live collect sink stats
	sinks := make([]map[string]any, 0, len(p.Sinks))
	for _, snk := range p.Sinks {
		if snk == nil {
			continue
		}
		s := snk.GetStats()
		sinks = append(sinks, map[string]any{
			"id":                 s.ID,
			"type":               s.Type,
			"total_processed":    s.TotalProcessed,
			"active_connections": s.ActiveConnections,
			"start_time":         s.StartTime,
			"last_processed":     s.LastProcessed,
			"details":            s.Details,
		})
	}

	// 3. Collect flow stats and calculate filtered total
	var flowStats map[string]any
	var totalFiltered uint64
	var totalProcessed uint64

	if p.Flow != nil {
		flowStats = p.Flow.GetStats()

		// Map the top-level processed counter directly from Flow's source of truth
		if tp, ok := flowStats["total_processed"].(uint64); ok {
			totalProcessed = tp
		}

		// Calculate total dropped specifically by the filter chain
		if filters, ok := flowStats["filters"].(map[string]any); ok {
			if totalPassed, ok := filters["total_passed"].(uint64); ok {
				if tProc, ok := filters["total_processed"].(uint64); ok {
					totalFiltered = tProc - totalPassed
				}
			}
		}
	}

	// 4. Calculate Uptime
	var uptime int
	if p.running.Load() && !p.Stats.StartTime.IsZero() {
		uptime = int(time.Since(p.Stats.StartTime).Seconds())
	}

	return map[string]any{
		"name":                  p.Config.Name,
		"running":               p.running.Load(),
		"uptime_seconds":        uptime,
		"total_processed":       totalProcessed,
		"total_filtered":        totalFiltered,
		"total_dropped_by_sink": p.Stats.TotalEntriesDroppedBySink.Load(),
		"source_count":          len(p.Sources),
		"sources":               sources,
		"sink_count":            len(p.Sinks),
		"sinks":                 sinks,
		"flow":                  flowStats,
	}
}
