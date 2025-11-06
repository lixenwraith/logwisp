// FILE: logwisp/src/internal/filter/filter.go
package filter

import (
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Filter applies regex-based filtering to log entries.
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

// NewFilter creates a new filter from a configuration.
func NewFilter(cfg config.FilterConfig, logger *log.Logger) (*Filter, error) {
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

// Apply determines if a log entry should be passed through based on the filter's rules.
func (f *Filter) Apply(entry core.LogEntry) bool {
	f.totalProcessed.Add(1)

	// No patterns means pass everything
	if len(f.patterns) == 0 {
		f.logger.Debug("msg", "No patterns configured, passing entry",
			"component", "filter",
			"type", f.config.Type)
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

	f.logger.Debug("msg", "Filter checking entry",
		"component", "filter",
		"type", f.config.Type,
		"logic", f.config.Logic,
		"entry_level", entry.Level,
		"entry_source", entry.Source,
		"entry_message", entry.Message[:min(100, len(entry.Message))], // First 100 chars
		"text_to_match", text[:min(150, len(text))], // First 150 chars
		"patterns", f.config.Patterns)

	for i, pattern := range f.config.Patterns {
		isMatch := f.patterns[i].MatchString(text)
		f.logger.Debug("msg", "Pattern match result",
			"component", "filter",
			"pattern_index", i,
			"pattern", pattern,
			"matched", isMatch)
	}

	matched := f.matches(text)
	if matched {
		f.totalMatched.Add(1)
	}
	f.logger.Debug("msg", "Filter final match result",
		"component", "filter",
		"matched", matched)

	// Determine if we should pass or drop
	shouldPass := false
	switch f.config.Type {
	case config.FilterTypeInclude:
		shouldPass = matched
	case config.FilterTypeExclude:
		shouldPass = !matched
	}

	f.logger.Debug("msg", "Filter decision",
		"component", "filter",
		"type", f.config.Type,
		"matched", matched,
		"should_pass", shouldPass)

	if !shouldPass {
		f.totalDropped.Add(1)
	}

	return shouldPass
}

// GetStats returns the filter's current statistics.
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

// UpdatePatterns allows for dynamic, thread-safe updates to the filter's regex patterns.
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

// matches checks if the given text matches the filter's patterns according to its logic.
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