// FILE: src/internal/config/filter.go
package config

import (
	"fmt"
	"regexp"
)

// FilterType represents the filter type
type FilterType string

const (
	FilterTypeInclude FilterType = "include" // Whitelist - only matching logs pass
	FilterTypeExclude FilterType = "exclude" // Blacklist - matching logs are dropped
)

// FilterLogic represents how multiple patterns are combined
type FilterLogic string

const (
	FilterLogicOr  FilterLogic = "or"  // Match any pattern
	FilterLogicAnd FilterLogic = "and" // Match all patterns
)

// FilterConfig represents filter configuration
type FilterConfig struct {
	Type     FilterType  `toml:"type"`
	Logic    FilterLogic `toml:"logic"`
	Patterns []string    `toml:"patterns"`
}

func validateFilter(pipelineName string, filterIndex int, cfg *FilterConfig) error {
	// Validate filter type
	switch cfg.Type {
	case FilterTypeInclude, FilterTypeExclude, "":
		// Valid types
	default:
		return fmt.Errorf("pipeline '%s' filter[%d]: invalid type '%s' (must be 'include' or 'exclude')",
			pipelineName, filterIndex, cfg.Type)
	}

	// Validate filter logic
	switch cfg.Logic {
	case FilterLogicOr, FilterLogicAnd, "":
		// Valid logic
	default:
		return fmt.Errorf("pipeline '%s' filter[%d]: invalid logic '%s' (must be 'or' or 'and')",
			pipelineName, filterIndex, cfg.Logic)
	}

	// Empty patterns is valid - passes everything
	if len(cfg.Patterns) == 0 {
		return nil
	}

	// Validate regex patterns
	for i, pattern := range cfg.Patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("pipeline '%s' filter[%d] pattern[%d] '%s': invalid regex: %w",
				pipelineName, filterIndex, i, pattern, err)
		}
	}

	return nil
}