package flow

import (
	"context"
	"fmt"
	"sync/atomic"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/filter"
	"logwisp/src/internal/format"

	"github.com/lixenwraith/log"
)

// Flow manages the complete processing pipeline for log entries:
// LogEntry -> Rate Limiter -> Filters -> Formatter (with Sanitizer) -> TransportEvent
type Flow struct {
	rateLimiter *RateLimiter
	filterChain *filter.Chain
	formatter   format.Formatter
	heartbeat   *HeartbeatGenerator
	logger      *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	totalDropped   atomic.Uint64
	totalFormatted atomic.Uint64
}

// NewFlow creates a flow processor from configuration
func NewFlow(cfg *config.FlowConfig, logger *log.Logger) (*Flow, error) {
	if cfg == nil {
		cfg = &config.FlowConfig{}
	}

	f := &Flow{
		logger: logger,
	}

	// Create rate limiter if configured
	if cfg.RateLimit != nil {
		limiter, err := NewRateLimiter(*cfg.RateLimit, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create rate limiter: %w", err)
		}
		f.rateLimiter = limiter
	}

	// Create filter chain if configured
	if len(cfg.Filters) > 0 {
		chain, err := filter.NewChain(cfg.Filters, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create filter chain: %w", err)
		}
		f.filterChain = chain
	}

	// Create formatter with sanitizer integration
	formatter, err := format.NewFormatter(cfg.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to create formatter: %w", err)
	}
	f.formatter = formatter

	// Create heartbeat generator with the same formatter if configured
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

// Process applies all flow stages to a log entry
// Returns TransportEvent and whether entry passed all stages
func (f *Flow) Process(entry core.LogEntry) (core.TransportEvent, bool) {
	f.totalProcessed.Add(1)

	// Stage 1: Rate limiting
	if f.rateLimiter != nil {
		if !f.rateLimiter.Allow(entry) {
			f.totalDropped.Add(1)
			return core.TransportEvent{}, false
		}
	}

	// Stage 2: Filtering
	if f.filterChain != nil {
		if !f.filterChain.Apply(entry) {
			f.totalDropped.Add(1)
			return core.TransportEvent{}, false
		}
	}

	// Stage 3: Formatting
	formatted, err := f.formatter.Format(entry)
	if err != nil {
		f.logger.Error("msg", "Failed to format log entry",
			"component", "flow",
			"error", err)
		f.totalDropped.Add(1)
		return core.TransportEvent{}, false
	}

	f.totalFormatted.Add(1)

	// Create transport event
	event := core.TransportEvent{
		Time:    entry.Time,
		Payload: formatted,
	}

	return event, true
}

// StartHeartbeat starts the heartbeat generator if configured
// Returns channel that emits heartbeat events
func (f *Flow) StartHeartbeat(ctx context.Context) <-chan core.TransportEvent {
	if f.heartbeat == nil {
		return nil
	}
	return f.heartbeat.Start(ctx)
}

// GetStats returns flow statistics
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