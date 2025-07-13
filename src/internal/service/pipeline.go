// FILE: src/internal/service/pipeline.go
package service

import (
	"context"
	"logwisp/src/internal/ratelimit"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/filter"
	"logwisp/src/internal/sink"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Pipeline manages the flow of data from sources through filters to sinks
type Pipeline struct {
	Name        string
	Config      config.PipelineConfig
	Sources     []source.Source
	RateLimiter *ratelimit.Limiter
	FilterChain *filter.Chain
	Sinks       []sink.Sink
	Stats       *PipelineStats
	logger      *log.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// For HTTP sinks in router mode
	HTTPSinks []*sink.HTTPSink
	TCPSinks  []*sink.TCPSink
}

// PipelineStats contains statistics for a pipeline
type PipelineStats struct {
	StartTime                      time.Time
	TotalEntriesProcessed          atomic.Uint64
	TotalEntriesDroppedByRateLimit atomic.Uint64
	TotalEntriesFiltered           atomic.Uint64
	SourceStats                    []source.SourceStats
	SinkStats                      []sink.SinkStats
	FilterStats                    map[string]any
}

// Shutdown gracefully stops the pipeline
func (p *Pipeline) Shutdown() {
	p.logger.Info("msg", "Shutting down pipeline",
		"component", "pipeline",
		"pipeline", p.Name)

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
		"pipeline", p.Name)
}

// GetStats returns pipeline statistics
func (p *Pipeline) GetStats() map[string]any {
	// Recovery to handle concurrent access during shutdown
	// When service is shutting down, sources/sinks might be nil or partially stopped
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("msg", "Panic getting pipeline stats",
				"pipeline", p.Name,
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
		"name":                     p.Name,
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

// startStatsUpdater runs periodic stats updates
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