package flow

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/filter"
	"github.com/lixenwraith/logwisp/internal/format"

	"github.com/lixenwraith/log"
)

// Flow takes a pipeline's entries through rate limit, filters and format to
// the TransportEvent its sinks get
type Flow struct {
	rateLimiter *RateLimiter
	filterChain *filter.Chain
	formatter   format.Formatter
	heartbeat   *HeartbeatGenerator
	logger      *log.Logger

	totalProcessed atomic.Uint64
	totalDropped   atomic.Uint64
	totalFormatted atomic.Uint64
}

func NewFlow(cfg *config.FlowConfig, logger *log.Logger) (*Flow, error) {
	if cfg == nil {
		cfg = &config.FlowConfig{}
	}

	f := &Flow{
		logger: logger,
	}

	if cfg.RateLimit != nil {
		limiter, err := NewRateLimiter(*cfg.RateLimit, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create rate limiter: %w", err)
		}
		f.rateLimiter = limiter
	}

	if len(cfg.Filters) > 0 {
		chain, err := filter.NewChain(cfg.Filters, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create filter chain: %w", err)
		}
		f.filterChain = chain
	}

	formatter, err := format.NewFormatter(cfg.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to create formatter: %w", err)
	}
	f.formatter = formatter

	// Heartbeats are written like the entries
	if cfg.Heartbeat != nil {
		hb, err := NewHeartbeatGenerator(cfg.Heartbeat, formatter, logger)
		if err != nil {
			return nil, fmt.Errorf("heartbeat: %w", err)
		}
		f.heartbeat = hb
	}

	logger.Info("msg", "Flow processor created",
		"component", "flow",
		"rate_limiter", f.rateLimiter != nil,
		"filter_chain", f.filterChain != nil,
		"formatter", formatter.Name(),
		"heartbeat", f.heartbeat != nil)

	return f, nil
}

// Process applies the flow's stages to an entry and returns the event for the
// sinks, or the stage that dropped it and, for filters, which one
func (f *Flow) Process(entry core.LogEntry) (event core.TransportEvent, stage string, index int) {
	f.totalProcessed.Add(1)
	if f.rateLimiter != nil && !f.rateLimiter.Allow(entry) {
		f.totalDropped.Add(1)
		return core.TransportEvent{Entry: entry}, "rate_limit", 0
	}
	if f.filterChain != nil {
		if i := f.filterChain.Apply(entry); i >= 0 {
			f.totalDropped.Add(1)
			return core.TransportEvent{Entry: entry}, "filters", i
		}
	}
	formatted, err := f.formatter.Format(entry)
	if err != nil {
		f.logger.Error("msg", "Failed to format log entry",
			"component", "flow",
			"error", err)
		f.totalDropped.Add(1)
		return core.TransportEvent{Entry: entry}, "format", 0
	}
	f.totalFormatted.Add(1)
	// The structured entry rides along so chain sinks are format-independent
	return core.TransportEvent{Time: entry.Time, Payload: formatted, Entry: entry}, "", 0
}

// StartHeartbeat returns the heartbeat events until ctx ends, or nil without
// a heartbeat
func (f *Flow) StartHeartbeat(ctx context.Context) <-chan core.TransportEvent {
	if f.heartbeat == nil {
		return nil
	}
	return f.heartbeat.Start(ctx)
}

func (f *Flow) GetStats() map[string]any {
	stats := map[string]any{
		"total_processed": f.totalProcessed.Load(),
		"total_dropped":   f.totalDropped.Load(),
		"total_formatted": f.totalFormatted.Load(),
	}

	if f.rateLimiter != nil {
		stats["rate_limiter"] = f.rateLimiter.GetStats()
	}

	if f.filterChain != nil {
		stats["filters"] = f.filterChain.GetStats()
	}

	if f.formatter != nil {
		stats["formatter"] = f.formatter.Name()
	}

	if f.heartbeat != nil {
		stats["heartbeat_enabled"] = true
		stats["heartbeat_interval_ms"] = f.heartbeat.IntervalMS()
	}

	return stats
}
