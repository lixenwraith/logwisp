package filter

import (
	"fmt"
	"regexp"
	"sync/atomic"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/log"
)

// Filter applies regex-based filtering to log entries. It does not change
// once built: a pipeline swaps its whole flow to edit one.
type Filter struct {
	config   config.FilterConfig
	patterns []*regexp.Regexp
	logger   *log.Logger

	// Statistics
	totalProcessed atomic.Uint64
	totalMatched   atomic.Uint64
	totalDropped   atomic.Uint64
}

// NewFilter creates a new filter from a configuration
func NewFilter(cfg config.FilterConfig, logger *log.Logger) (*Filter, error) {
	if err := config.Settle(&cfg); err != nil {
		return nil, err
	}

	f := &Filter{
		config:   cfg,
		patterns: make([]*regexp.Regexp, 0, len(cfg.Patterns)),
		logger:   logger,
	}

	for i, pattern := range cfg.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern[%d] '%s': %w", i, pattern, err)
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

// matchText is what the patterns match: the entry's source and level, each
// followed by a space when set, then its message. A chain builds it once.
func matchText(entry core.LogEntry) string {
	switch {
	case entry.Source != "" && entry.Level != "":
		return entry.Source + " " + entry.Level + " " + entry.Message
	case entry.Source != "":
		return entry.Source + " " + entry.Message
	case entry.Level != "":
		return entry.Level + " " + entry.Message
	}
	return entry.Message
}

// apply reports whether the entry, whose match text is text, passes
func (f *Filter) apply(entry core.LogEntry, text string) bool {
	f.totalProcessed.Add(1)

	// The report matches every pattern on its own and builds its arguments
	// before Debug could drop them, so it runs only at DEBUG; otherwise
	// matches alone runs the patterns, stopping where the logic allows
	debug := f.logger.Enabled(log.LevelDebug)
	if debug {
		f.logger.Debug("msg", "Filter checking entry",
			"component", "filter",
			"type", f.config.Type,
			"logic", f.config.Logic,
			"entry_level", entry.Level,
			"entry_source", entry.Source,
			"entry_message", entry.Message[:min(100, len(entry.Message))],
			"text_to_match", text[:min(150, len(text))],
			"patterns", f.config.Patterns)

		for i, pattern := range f.config.Patterns {
			isMatch := f.patterns[i].MatchString(text)
			f.logger.Debug("msg", "Pattern match result",
				"component", "filter",
				"pattern_index", i,
				"pattern", pattern,
				"matched", isMatch)
		}
	}

	matched := f.matches(text)
	if matched {
		f.totalMatched.Add(1)
	}
	if debug {
		f.logger.Debug("msg", "Filter final match result",
			"component", "filter",
			"matched", matched)
	}

	shouldPass := false
	switch f.config.Type {
	case config.FilterTypeInclude:
		shouldPass = matched
	case config.FilterTypeExclude:
		shouldPass = !matched
	}

	if debug {
		f.logger.Debug("msg", "Filter decision",
			"component", "filter",
			"type", f.config.Type,
			"matched", matched,
			"should_pass", shouldPass)
	}

	if !shouldPass {
		f.totalDropped.Add(1)
	}

	return shouldPass
}

// GetStats returns the filter's current statistics
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

// matches checks if the given text matches the filter's patterns according to its logic
func (f *Filter) matches(text string) bool {
	switch f.config.Logic {
	case config.FilterLogicOr:
		for _, re := range f.patterns {
			if re.MatchString(text) {
				return true
			}
		}
		return false

	case config.FilterLogicAnd:
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
