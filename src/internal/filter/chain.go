// FILE: logwisp/src/internal/filter/chain.go
package filter

import (
	"fmt"
	"sync/atomic"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Chain manages multiple filters in sequence
type Chain struct {
	filters []*Filter
	logger  *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	totalPassed    atomic.Uint64
}

// NewChain creates a new filter chain from configurations
func NewChain(configs []config.FilterConfig, logger *log.Logger) (*Chain, error) {
	chain := &Chain{
		filters: make([]*Filter, 0, len(configs)),
		logger:  logger,
	}

	for i, cfg := range configs {
		filter, err := New(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("filter[%d]: %w", i, err)
		}
		chain.filters = append(chain.filters, filter)
	}

	logger.Info("msg", "Filter chain created",
		"component", "filter_chain",
		"filter_count", len(configs))
	return chain, nil
}

// Apply runs all filters in sequence
// Returns true if the entry passes all filters
func (c *Chain) Apply(entry core.LogEntry) bool {
	c.totalProcessed.Add(1)

	// No filters means pass everything
	if len(c.filters) == 0 {
		c.totalPassed.Add(1)
		return true
	}

	// All filters must pass
	for i, filter := range c.filters {
		if !filter.Apply(entry) {
			c.logger.Debug("msg", "Entry filtered out",
				"component", "filter_chain",
				"filter_index", i,
				"filter_type", filter.config.Type)
			return false
		}
	}

	c.totalPassed.Add(1)
	return true
}

// GetStats returns chain statistics
func (c *Chain) GetStats() map[string]any {
	filterStats := make([]map[string]any, len(c.filters))
	for i, filter := range c.filters {
		filterStats[i] = filter.GetStats()
	}

	return map[string]any{
		"filter_count":    len(c.filters),
		"total_processed": c.totalProcessed.Load(),
		"total_passed":    c.totalPassed.Load(),
		"filters":         filterStats,
	}
}