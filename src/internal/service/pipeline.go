// FILE: logwisp/src/internal/service/pipeline.go
package service

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/filter"
	"logwisp/src/internal/format"
	"logwisp/src/internal/limit"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Manages the flow of data from sources through filters to sinks
type Pipeline struct {
	Config      *config.PipelineConfig
	Sources     []source.Source
	RateLimiter *limit.RateLimiter
	FilterChain *filter.Chain
	Sinks       []sink.Sink
	Stats       *PipelineStats
	logger      *log.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Contains statistics for a pipeline
type PipelineStats struct {
	StartTime                      time.Time
	TotalEntriesProcessed          atomic.Uint64
	TotalEntriesDroppedByRateLimit atomic.Uint64
	TotalEntriesFiltered           atomic.Uint64
	SourceStats                    []source.SourceStats
	SinkStats                      []sink.SinkStats
	FilterStats                    map[string]any
}

// Creates and starts a new pipeline
func (s *Service) NewPipeline(cfg *config.PipelineConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pipelines[cfg.Name]; exists {
		err := fmt.Errorf("pipeline '%s' already exists", cfg.Name)
		s.logger.Error("msg", "Failed to create pipeline - duplicate name",
			"component", "service",
			"pipeline", cfg.Name,
			"error", err)
		return err
	}

	s.logger.Debug("msg", "Creating pipeline", "pipeline", cfg.Name)

	// Create pipeline context
	pipelineCtx, pipelineCancel := context.WithCancel(s.ctx)

	// Create pipeline instance
	pipeline := &Pipeline{
		Config: cfg,
		Stats: &PipelineStats{
			StartTime: time.Now(),
		},
		ctx:    pipelineCtx,
		cancel: pipelineCancel,
		logger: s.logger,
	}

	// Create sources
	for i, srcCfg := range cfg.Sources {
		src, err := s.createSource(&srcCfg)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create source[%d]: %w", i, err)
		}
		pipeline.Sources = append(pipeline.Sources, src)
	}

	// Create pipeline rate limiter
	if cfg.RateLimit != nil {
		limiter, err := limit.NewRateLimiter(*cfg.RateLimit, s.logger)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create pipeline rate limiter: %w", err)
		}
		pipeline.RateLimiter = limiter
	}

	// Create filter chain
	if len(cfg.Filters) > 0 {
		chain, err := filter.NewChain(cfg.Filters, s.logger)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create filter chain: %w", err)
		}
		pipeline.FilterChain = chain
	}

	// Create formatter for the pipeline
	formatter, err := format.NewFormatter(cfg.Format, s.logger)
	if err != nil {
		pipelineCancel()
		return fmt.Errorf("failed to create formatter: %w", err)
	}

	// Create sinks
	for i, sinkCfg := range cfg.Sinks {
		sinkInst, err := s.createSink(sinkCfg, formatter)
		if err != nil {
			pipelineCancel()
			return fmt.Errorf("failed to create sink[%d]: %w", i, err)
		}
		pipeline.Sinks = append(pipeline.Sinks, sinkInst)
	}

	// Start all sources
	for i, src := range pipeline.Sources {
		if err := src.Start(); err != nil {
			pipeline.Shutdown()
			return fmt.Errorf("failed to start source[%d]: %w", i, err)
		}
	}

	// Start all sinks
	for i, sinkInst := range pipeline.Sinks {
		if err := sinkInst.Start(pipelineCtx); err != nil {
			pipeline.Shutdown()
			return fmt.Errorf("failed to start sink[%d]: %w", i, err)
		}
	}

	// Wire sources to sinks through filters
	s.wirePipeline(pipeline)

	// Start stats updater
	pipeline.startStatsUpdater(pipelineCtx)

	s.pipelines[cfg.Name] = pipeline
	s.logger.Info("msg", "Pipeline created successfully",
		"pipeline", cfg.Name)
	return nil
}

// Gracefully stops the pipeline
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

// Returns pipeline statistics
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
			"type":            stats.Type,
			"total_entries":   stats.TotalEntries,
			"dropped_entries": stats.DroppedEntries,
			"start_time":      stats.StartTime,
			"last_entry_time": stats.LastEntryTime,
			"details":         stats.Details,
		})
	}

	// Collect rate limit stats
	var rateLimitStats map[string]any
	if p.RateLimiter != nil {
		rateLimitStats = p.RateLimiter.GetStats()
	}

	// Collect filter stats
	var filterStats map[string]any
	if p.FilterChain != nil {
		filterStats = p.FilterChain.GetStats()
	}

	// Collect sink stats
	sinkStats := make([]map[string]any, 0, len(p.Sinks))
	for _, s := range p.Sinks {
		if s == nil {
			continue // Skip nil sinks
		}

		stats := s.GetStats()
		sinkStats = append(sinkStats, map[string]any{
			"type":               stats.Type,
			"total_processed":    stats.TotalProcessed,
			"active_connections": stats.ActiveConnections,
			"start_time":         stats.StartTime,
			"last_processed":     stats.LastProcessed,
			"details":            stats.Details,
		})
	}

	return map[string]any{
		"name":                     p.Config.Name,
		"uptime_seconds":           int(time.Since(p.Stats.StartTime).Seconds()),
		"total_processed":          p.Stats.TotalEntriesProcessed.Load(),
		"total_dropped_rate_limit": p.Stats.TotalEntriesDroppedByRateLimit.Load(),
		"total_filtered":           p.Stats.TotalEntriesFiltered.Load(),
		"sources":                  sourceStats,
		"rate_limiter":             rateLimitStats,
		"sinks":                    sinkStats,
		"filters":                  filterStats,
		"source_count":             len(p.Sources),
		"sink_count":               len(p.Sinks),
		"filter_count":             len(p.Config.Filters),
	}
}

// Runs periodic stats updates
func (p *Pipeline) startStatsUpdater(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
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