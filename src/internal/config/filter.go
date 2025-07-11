// FILE: src/internal/config/filter.go
package config

import (
	"fmt"
	"regexp"

	"logwisp/src/internal/filter"
)

func validateFilter(pipelineName string, filterIndex int, cfg *filter.Config) error {
	// Validate filter type
	switch cfg.Type {
	case filter.TypeInclude, filter.TypeExclude, "":
		// Valid types
	default:
		return fmt.Errorf("pipeline '%s' filter[%d]: invalid type '%s' (must be 'include' or 'exclude')",
			pipelineName, filterIndex, cfg.Type)
	}

	// Validate filter logic
	switch cfg.Logic {
	case filter.LogicOr, filter.LogicAnd, "":
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