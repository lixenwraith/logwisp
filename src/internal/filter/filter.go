// FILE: src/internal/filter/filter.go
package filter

import (
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"

	"logwisp/src/internal/monitor"
)

// Type represents the filter type
type Type string

const (
	TypeInclude Type = "include" // Whitelist - only matching logs pass
	TypeExclude Type = "exclude" // Blacklist - matching logs are dropped
)

// Logic represents how multiple patterns are combined
type Logic string

const (
	LogicOr  Logic = "or"  // Match any pattern
	LogicAnd Logic = "and" // Match all patterns
)

// Config represents filter configuration
type Config struct {
	Type     Type     `toml:"type"`
	Logic    Logic    `toml:"logic"`
	Patterns []string `toml:"patterns"`
}

// Filter applies regex-based filtering to log entries
type Filter struct {
	config   Config
	patterns []*regexp.Regexp
	mu       sync.RWMutex

	// Statistics
	totalProcessed atomic.Uint64
	totalMatched   atomic.Uint64
	totalDropped   atomic.Uint64
}

// New creates a new filter from configuration
func New(cfg Config) (*Filter, error) {
	// Set defaults
	if cfg.Type == "" {
		cfg.Type = TypeInclude
	}
	if cfg.Logic == "" {
		cfg.Logic = LogicOr
	}

	f := &Filter{
		config:   cfg,
		patterns: make([]*regexp.Regexp, 0, len(cfg.Patterns)),
	}

	// Compile patterns
	for i, pattern := range cfg.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern[%d] '%s': %w", i, pattern, err)
		}
		f.patterns = append(f.patterns, re)
	}

	return f, nil
}

// Apply checks if a log entry should be passed through
func (f *Filter) Apply(entry monitor.LogEntry) bool {
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
	case TypeInclude:
		shouldPass = matched
	case TypeExclude:
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
	case LogicOr:
		// Match any pattern
		for _, re := range f.patterns {
			if re.MatchString(text) {
				return true
			}
		}
		return false

	case LogicAnd:
		// Must match all patterns
		for _, re := range f.patterns {
			if !re.MatchString(text) {
				return false
			}
		}
		return true

	default:
		// Shouldn't happen after validation
		return false
	}
}

// GetStats returns filter statistics
func (f *Filter) GetStats() map[string]interface{} {
	return map[string]interface{}{
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

	return nil
}