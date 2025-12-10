package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

// ValidateConfig is the centralized validator for the entire configuration structure
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if len(cfg.Pipelines) == 0 {
		return fmt.Errorf("no pipelines configured")
	}

	if err := validateLogConfig(cfg.Logging); err != nil {
		return fmt.Errorf("logging config: %w", err)
	}

	// // Track used ports across all pipelines
	// allPorts := make(map[int64]string)
	// pipelineNames := make(map[string]bool)

	// for i, pipeline := range cfg.Pipelines {
	// 	if err := validatePipeline(i, &pipeline, pipelineNames, allPorts); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

// validateLogConfig validates the application's own logging settings
func validateLogConfig(cfg *LogConfig) error {
	validOutputs := map[string]bool{
		"file": true, "stdout": true, "stderr": true,
		"split": true, "all": true, "none": true,
	}
	if !validOutputs[cfg.Output] {
		return fmt.Errorf("invalid log output mode: %s", cfg.Output)
	}

	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLevels[cfg.Level] {
		return fmt.Errorf("invalid log level: %s", cfg.Level)
	}

	if cfg.Console != nil {
		validTargets := map[string]bool{
			"stdout": true, "stderr": true, "split": true,
		}
		if !validTargets[cfg.Console.Target] {
			return fmt.Errorf("invalid console target: %s", cfg.Console.Target)
		}
	}

	return nil
}

// validateRateLimit validates the pipeline-level rate limit settings
func validateRateLimit(pipelineName string, cfg *RateLimitConfig) error {
	if cfg == nil {
		return nil
	}

	if cfg.Rate < 0 {
		return fmt.Errorf("pipeline '%s': rate limit rate cannot be negative", pipelineName)
	}

	if cfg.Burst < 0 {
		return fmt.Errorf("pipeline '%s': rate limit burst cannot be negative", pipelineName)
	}

	if cfg.MaxEntrySizeBytes < 0 {
		return fmt.Errorf("pipeline '%s': max entry size bytes cannot be negative", pipelineName)
	}

	// Validate policy
	switch strings.ToLower(cfg.Policy) {
	case "", "pass", "drop":
		// Valid policies
	default:
		return fmt.Errorf("pipeline '%s': invalid rate limit policy '%s' (must be 'pass' or 'drop')",
			pipelineName, cfg.Policy)
	}

	return nil
}

// validateFilter validates a single filter's configuration
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

// validateFileSource validates the settings for a directory source
func validateFileSource(pipelineName string, index int, opts *FileSourceOptions) error {
	if err := lconfig.NonEmpty(opts.Directory); err != nil {
		return fmt.Errorf("pipeline '%s' source[%d]: directory requires 'path'", pipelineName, index)
	} else {
		absPath, err := filepath.Abs(opts.Directory)
		if err != nil {
			return fmt.Errorf("invalid path %s: %w", opts.Directory, err)
		}
		opts.Directory = absPath
	}

	// Check for directory traversal
	if strings.Contains(opts.Directory, "..") {
		return fmt.Errorf("pipeline '%s' source[%d]: path contains directory traversal", pipelineName, index)
	}

	// Validate pattern if provided
	if opts.Pattern != "" {
		if strings.Count(opts.Pattern, "*") == 0 && strings.Count(opts.Pattern, "?") == 0 {
			// If no wildcards, ensure valid filename
			if filepath.Base(opts.Pattern) != opts.Pattern {
				return fmt.Errorf("pipeline '%s' source[%d]: pattern contains path separators", pipelineName, index)
			}
		}
	} else {
		opts.Pattern = "*"
	}

	// Validate check interval
	if opts.CheckIntervalMS < 10 {
		return fmt.Errorf("pipeline '%s' source[%d]: check_interval_ms must be at least 10ms", pipelineName, index)
	}

	return nil
}

// validateConsoleSource validates the settings for a console source
func validateConsoleSource(pipelineName string, index int, opts *ConsoleSourceOptions) error {
	if opts.BufferSize < 0 {
		return fmt.Errorf("pipeline '%s' source[%d]: buffer_size must be positive", pipelineName, index)
	} else if opts.BufferSize == 0 {
		opts.BufferSize = 1000
	}
	return nil
}

// validateConsoleSink validates the settings for a console sink
func validateConsoleSink(pipelineName string, index int, opts *ConsoleSinkOptions) error {
	if opts.BufferSize < 1 {
		return fmt.Errorf("pipeline '%s' sink[%d]: buffer_size must be positive", pipelineName, index)
	}
	return nil
}

// validateFileSink validates the settings for a file sink
func validateFileSink(pipelineName string, index int, opts *FileSinkOptions) error {
	if err := lconfig.NonEmpty(opts.Directory); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: file requires 'directory'", pipelineName, index)
	}

	if err := lconfig.NonEmpty(opts.Name); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: file requires 'name'", pipelineName, index)
	}

	if opts.BufferSize <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: max_size_mb must be positive", pipelineName, index)
	}

	// Validate sizes
	if opts.MaxSizeMB < 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: max_size_mb must be positive", pipelineName, index)
	}

	if opts.MaxTotalSizeMB <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: max_total_size_mb cannot be negative", pipelineName, index)
	}

	if opts.MinDiskFreeMB < 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: min_disk_free_mb must be positive", pipelineName, index)
	}

	if opts.RetentionHours <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: retention_hours cannot be negative", pipelineName, index)
	}

	return nil
}

// validateHeartbeat validates nested HeartbeatConfig settings
func validateHeartbeat(pipelineName, location string, hb *HeartbeatConfig) error {
	if !hb.Enabled {
		return nil // Skip validation if disabled
	}

	if hb.IntervalMS < 1000 { // At least 1 second
		return fmt.Errorf("pipeline '%s' %s: heartbeat interval must be at least 1000ms", pipelineName, location)
	}

	return nil
}