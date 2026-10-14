// Package pipeline runs one pipeline: its sources through the flow to its
// sinks, each plugin made by the factory its type registered. Sinks start
// before the sources and stop after them, so entries in flight arrive; a full
// sink drops its event unless it declares core.CapBackpressure. A tap gives a
// viewer a copy of what the flow decides.
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

	Registry *Registry
	Sources  map[string]source.Source
	Sinks    map[string]sink.Sink
	Sessions *session.Manager

	Flow   *flow.Flow
	Stats  *PipelineStats
	logger *log.Logger

	// Sinks that stall dispatch rather than drop (core.CapBackpressure)
	backpressure map[string]bool

	tap atomic.Pointer[core.Tap] // a viewer's copy of what the flow decides

	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	running      atomic.Bool
	halt         chan struct{} // closed by Stop: backpressure events may then drop, room or not
	finished     chan struct{} // closed when every source has ended
	finishedOnce sync.Once
}

type PipelineStats struct {
	StartTime                 time.Time
	TotalEntriesDroppedBySink atomic.Uint64
	SourceStats               []source.SourceStats
	SinkStats                 []sink.SinkStats
	FlowStats                 map[string]any
}

func NewPipeline(
	cfg *config.PipelineConfig,
	logger *log.Logger,
) (*Pipeline, error) {
	pipelineCtx, pipelineCancel := context.WithCancel(context.Background())

	sessionManager := session.NewManager(core.SessionDefaultMaxIdleTime)

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

	flowProcessor, err := flow.NewFlow(cfg.Flow, logger)
	if err != nil {
		pipelineCancel()
		sessionManager.Stop()
		return nil, fmt.Errorf("failed to create flow processor: %w", err)
	}
	pipeline.Flow = flowProcessor

	if err := pipeline.initializeComponents(); err != nil {
		pipelineCancel()
		sessionManager.Stop()
		return nil, err
	}

	return pipeline, nil
}

func (p *Pipeline) initializeComponents() error {
	if len(p.Config.PluginSources) > 0 {
		for _, srcCfg := range p.Config.PluginSources {
			sessionProxy := session.NewProxy(p.Sessions, srcCfg.ID)

			src, err := p.Registry.CreateSource(
				srcCfg.ID,
				srcCfg.Type,
				srcCfg.Config,
				p.logger,
				sessionProxy,
			)
			if err != nil {
				return p.part("source", srcCfg.ID, err) // the registry names the plugin
			}

			if err := p.initSourceCapabilities(src, srcCfg); err != nil {
				return p.part("source", srcCfg.ID, fmt.Errorf("failed to initiate capabilities for source %s: %w", srcCfg.ID, err))
			}

			p.Sources[srcCfg.ID] = src
		}
	} else {
		return fmt.Errorf("no plugin sources defined")
	}

	if len(p.Config.PluginSinks) > 0 {
		for _, sinkCfg := range p.Config.PluginSinks {
			sessionProxy := session.NewProxy(p.Sessions, sinkCfg.ID)

			snk, err := p.Registry.CreateSink(
				sinkCfg.ID,
				sinkCfg.Type,
				sinkCfg.Config,
				p.logger,
				sessionProxy,
			)
			if err != nil {
				return p.part("sink", sinkCfg.ID, err) // the registry names the plugin
			}

			if err := p.initSinkCapabilities(snk, sinkCfg); err != nil {
				return p.part("sink", sinkCfg.ID, fmt.Errorf("failed to initiate capabilities for sink %s: %w", sinkCfg.ID, err))
			}

			p.Sinks[sinkCfg.ID] = snk
		}
	} else {
		return fmt.Errorf("no plugin sinks defined")
	}

	return nil
}

// PartError is a source's or sink's error, which names its part for a screen
// to place; its text is the error's own
type PartError struct {
	Pipeline, Role, ID string
	Err                error
}

func (e *PartError) Error() string { return e.Err.Error() }
func (e *PartError) Unwrap() error { return e.Err }

func (p *Pipeline) part(role, id string, err error) error {
	return &PartError{p.Config.Name, role, id, err}
}

func (p *Pipeline) initSourceCapabilities(s source.Source, cfg config.PluginSourceConfig) error {
	var hasTLS, hasAuth bool
	for _, c := range s.Capabilities() {
		switch c {
		case core.CapNetLimit:
			continue
		case core.CapTLS, core.CapProxyTLS:
			hasTLS = true
		case core.CapAuth:
			hasAuth = true

		case core.CapSessionAware:
		case core.CapMultiSession:
			continue

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

func (p *Pipeline) initSinkCapabilities(s sink.Sink, cfg config.PluginSinkConfig) error {
	var hasTLS, hasAuth bool
	for _, c := range s.Capabilities() {
		switch c {
		case core.CapBackpressure:
			p.backpressure[cfg.ID] = true

		case core.CapNetLimit:
			continue
		case core.CapTLS, core.CapProxyTLS:
			hasTLS = true
		case core.CapAuth:
			hasAuth = true

		case core.CapSessionAware:
		case core.CapMultiSession:
			continue

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
func (p *Pipeline) run(ids []string, subscriptions []<-chan core.LogEntry) {
	defer p.wg.Done()
	defer p.finish()
	defer p.logger.Info("msg", "Pipeline processing loop stopped", "pipeline", p.Config.Name)

	var componentWg sync.WaitGroup
	for i, ch := range subscriptions {
		componentWg.Add(1)
		go func() {
			defer componentWg.Done()
			// Range drains in-flight entries once the source closes the channel
			for entry := range ch {
				event, stage, index := p.Flow.Process(entry)
				if t := p.tap.Load(); t != nil {
					t.Offer(core.Tapped{Pipeline: p.Config.Name, Source: ids[i], Stage: stage, Index: index, Event: event})
				}
				if stage == "" {
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
					if t := p.tap.Load(); t != nil {
						t.Offer(core.Tapped{Pipeline: p.Config.Name, Event: event})
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

// SetTap offers what the flow decides to t from the next entry on; nil stops
func (p *Pipeline) SetTap(t *core.Tap) { p.tap.Store(t) }

func (p *Pipeline) finish() { p.finishedOnce.Do(func() { close(p.finished) }) }

// Finished is closed when every source has ended, or the pipeline shut down.
// Only a finite source (console at end of input) ends without Stop.
func (p *Pipeline) Finished() <-chan struct{} { return p.finished }

// Start starts the sinks before the sources, so the first entry has somewhere to go
func (p *Pipeline) Start() error {
	if !p.running.CompareAndSwap(false, true) {
		return fmt.Errorf("pipeline %s is already running", p.Config.Name)
	}

	p.logger.Info("msg", "Starting pipeline", "pipeline", p.Config.Name)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.halt = make(chan struct{})

	for id, s := range p.Sinks {
		if err := s.Start(p.ctx); err != nil {
			return p.part("sink", id, fmt.Errorf("failed to start sink %s: %w", id, err))
		}
	}

	// Subscribed before Start: a source publishes from its first entry on. One
	// loop keeps ids beside their channels; map order differs between loops.
	ids := make([]string, 0, len(p.Sources))
	subscriptions := make([]<-chan core.LogEntry, 0, len(p.Sources))
	for id, src := range p.Sources {
		ids, subscriptions = append(ids, id), append(subscriptions, src.Subscribe())
	}
	for id, src := range p.Sources {
		if err := src.Start(); err != nil {
			return p.part("source", id, fmt.Errorf("failed to start source %s: %w", id, err))
		}
	}

	p.Stats.StartTime = time.Now()
	p.wg.Add(1)
	go p.run(ids, subscriptions)

	return nil
}

// Stop stops the sources, lets the run loop drain, then stops the sinks, so
// entries in flight reach them
func (p *Pipeline) Stop() error {
	if !p.running.CompareAndSwap(true, false) {
		return fmt.Errorf("pipeline %s is not running", p.Config.Name)
	}

	p.logger.Info("msg", "Stopping pipeline", "pipeline", p.Config.Name)
	close(p.halt)

	var sourceWg sync.WaitGroup
	for _, src := range p.Sources {
		sourceWg.Add(1)
		go func(s source.Source) {
			defer sourceWg.Done()
			s.Stop()
		}(src)
	}
	sourceWg.Wait()

	p.wg.Wait()

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

// Shutdown stops the pipeline for good, with its session manager
func (p *Pipeline) Shutdown() {
	p.logger.Info("msg", "Shutting down pipeline",
		"component", "pipeline",
		"pipeline", p.Config.Name)

	if p.running.Load() {
		if err := p.Stop(); err != nil {
			p.logger.Error("msg", "Error stopping pipeline during shutdown", "error", err)
		}
	}

	if p.Sessions != nil {
		p.Sessions.Stop()
	}
	p.finish() // a pipeline that never started has no run loop to close it

	p.logger.Info("msg", "Pipeline shutdown complete",
		"component", "pipeline",
		"pipeline", p.Config.Name)
}

func (p *Pipeline) GetStats() map[string]any {
	// Sources and sinks may be partly stopped while the service shuts down
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("msg", "Panic getting pipeline stats",
				"pipeline", p.Config.Name,
				"panic", r)
		}
	}()

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

	var flowStats map[string]any
	var totalFiltered uint64
	var totalProcessed uint64

	if p.Flow != nil {
		flowStats = p.Flow.GetStats()

		if tp, ok := flowStats["total_processed"].(uint64); ok {
			totalProcessed = tp
		}

		if filters, ok := flowStats["filters"].(map[string]any); ok {
			if totalPassed, ok := filters["total_passed"].(uint64); ok {
				if tProc, ok := filters["total_processed"].(uint64); ok {
					totalFiltered = tProc - totalPassed
				}
			}
		}
	}

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
