// FILE: src/internal/filter/filter.go
package filter

import (
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"

	"logwisp/src/internal/config"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Filter applies regex-based filtering to log entries
type Filter struct {
	config   config.FilterConfig
	patterns []*regexp.Regexp
	mu       sync.RWMutex
	logger   *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	totalMatched   atomic.Uint64
	totalDropped   atomic.Uint64
}

// New creates a new filter from configuration
func New(cfg config.FilterConfig, logger *log.Logger) (*Filter, error) {
	// Set defaults
	if cfg.Type == "" {
		cfg.Type = config.FilterTypeInclude
	}
	if cfg.Logic == "" {
		cfg.Logic = config.FilterLogicOr
	}

	f := &Filter{
		config:   cfg,
		patterns: make([]*regexp.Regexp, 0, len(cfg.Patterns)),
		logger:   logger,
	}

	// Compile patterns
	for i, pattern := range cfg.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern[%d] '%s': %w", i, pattern, err)
		}
		f.patterns = append(f.patterns, re)
	}

	logger.Debug("msg", "Filter created",
		"component", "filter",
		"type", cfg.Type,
		"logic", cfg.Logic,
		"pattern_count", len(cfg.Patterns))

	return f, nil
}

// Apply checks if a log entry should be passed through
func (f *Filter) Apply(entry source.LogEntry) bool {
	f.totalProcessed.Add(1)

	// No patterns means pass everything
	if len(f.patterns) == 0 {
		return true
	}

	// Check against all fields that might contain the log content
	text := entry.Message
	if entry.Level != "" {
		text = entry.Level + " " + text
	}
	if entry.Source != "" {
		text = entry.Source + " " + text
	}

	matched := f.matches(text)
	if matched {
		f.totalMatched.Add(1)
	}

	// Determine if we should pass or drop
	shouldPass := false
	switch f.config.Type {
	case config.FilterTypeInclude:
		shouldPass = matched
	case config.FilterTypeExclude:
		shouldPass = !matched
	}

	if !shouldPass {
		f.totalDropped.Add(1)
	}

	return shouldPass
}

// matches checks if text matches the patterns according to the logic
func (f *Filter) matches(text string) bool {
	switch f.config.Logic {
	case config.FilterLogicOr:
		// Match any pattern
		for _, re := range f.patterns {
			if re.MatchString(text) {
				return true
			}
		}
		return false

	case config.FilterLogicAnd:
		// Must match all patterns
		for _, re := range f.patterns {
			if !re.MatchString(text) {
				return false
			}
		}
		return true

	default:
		// Shouldn't happen after validation
		f.logger.Warn("msg", "Unknown filter logic",
			"component", "filter",
			"logic", f.config.Logic)
		return false
	}
}

// GetStats returns filter statistics
func (f *Filter) GetStats() map[string]any {
	return map[string]any{
		"type":            f.config.Type,
		"logic":           f.config.Logic,
		"pattern_count":   len(f.patterns),
		"total_processed": f.totalProcessed.Load(),
		"total_matched":   f.totalMatched.Load(),
		"total_dropped":   f.totalDropped.Load(),
	}
}

// UpdatePatterns allows dynamic pattern updates
func (f *Filter) UpdatePatterns(patterns []string) error {
	compiled := make([]*regexp.Regexp, 0, len(patterns))

	// Compile all patterns first
	for i, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern[%d] '%s': %w", i, pattern, err)
		}
		compiled = append(compiled, re)
	}

	// Update atomically
	f.mu.Lock()
	f.patterns = compiled
	f.config.Patterns = patterns
	f.mu.Unlock()

	f.logger.Info("msg", "Filter patterns updated",
		"component", "filter",
		"pattern_count", len(patterns))
	return nil
}