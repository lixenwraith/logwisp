// FILE: src/internal/filter/chain.go
package filter

import (
	"fmt"
	"sync/atomic"

	"logwisp/src/internal/monitor"
)

// Chain manages multiple filters in sequence
type Chain struct {
	filters []*Filter

	// Statistics
	totalProcessed atomic.Uint64
	totalPassed    atomic.Uint64
}

// NewChain creates a new filter chain from configurations
func NewChain(configs []Config) (*Chain, error) {
	chain := &Chain{
		filters: make([]*Filter, 0, len(configs)),
	}

	for i, cfg := range configs {
		filter, err := New(cfg)
		if err != nil {
			return nil, fmt.Errorf("filter[%d]: %w", i, err)
		}
		chain.filters = append(chain.filters, filter)
	}

	return chain, nil
}

// Apply runs all filters in sequence
// Returns true if the entry passes all filters
func (c *Chain) Apply(entry monitor.LogEntry) bool {
	c.totalProcessed.Add(1)

	// No filters means pass everything
	if len(c.filters) == 0 {
		c.totalPassed.Add(1)
		return true
	}

	// All filters must pass
	for _, filter := range c.filters {
		if !filter.Apply(entry) {
			return false
		}
	}

	c.totalPassed.Add(1)
	return true
}

// GetStats returns chain statistics
func (c *Chain) GetStats() map[string]interface{} {
	filterStats := make([]map[string]interface{}, len(c.filters))
	for i, filter := range c.filters {
		filterStats[i] = filter.GetStats()
	}

	return map[string]interface{}{
		"filter_count":    len(c.filters),
		"total_processed": c.totalProcessed.Load(),
		"total_passed":    c.totalPassed.Load(),
		"filters":         filterStats,
	}
}