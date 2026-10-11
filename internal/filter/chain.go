package filter

import (
	"fmt"
	"sync/atomic"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/log"
)

// Chain is a pipeline's filters, applied in order
type Chain struct {
	filters []*Filter
	logger  *log.Logger

	totalProcessed atomic.Uint64
	totalPassed    atomic.Uint64
}

func NewChain(configs []config.FilterConfig, logger *log.Logger) (*Chain, error) {
	chain := &Chain{
		filters: make([]*Filter, 0, len(configs)),
		logger:  logger,
	}

	for i, cfg := range configs {
		filter, err := NewFilter(cfg, logger)
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

// Apply runs an entry through the filters in order and returns the index of
// the one that dropped it, or -1
func (c *Chain) Apply(entry core.LogEntry) int {
	c.totalProcessed.Add(1)
	for i, filter := range c.filters {
		if !filter.Apply(entry) {
			c.logger.Debug("msg", "Entry filtered out",
				"component", "filter_chain",
				"filter_index", i,
				"filter_type", filter.config.Type)
			return i
		}
	}
	c.totalPassed.Add(1)
	return -1
}

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
