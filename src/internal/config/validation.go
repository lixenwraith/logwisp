// FILE: logwisp/src/internal/config/validation.go
package config

import (
	"fmt"
)

func (c *Config) validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	if c.Logging == nil {
		c.Logging = DefaultLogConfig()
	}

	if len(c.Pipelines) == 0 {
		return fmt.Errorf("no pipelines configured")
	}

	if err := validateLogConfig(c.Logging); err != nil {
		return fmt.Errorf("logging config: %w", err)
	}

	// Track used ports across all pipelines
	allPorts := make(map[int64]string)
	pipelineNames := make(map[string]bool)

	for i, pipeline := range c.Pipelines {
		if pipeline.Name == "" {
			return fmt.Errorf("pipeline %d: missing name", i)
		}

		if pipelineNames[pipeline.Name] {
			return fmt.Errorf("pipeline %d: duplicate name '%s'", i, pipeline.Name)
		}
		pipelineNames[pipeline.Name] = true

		// Pipeline must have at least one source
		if len(pipeline.Sources) == 0 {
			return fmt.Errorf("pipeline '%s': no sources specified", pipeline.Name)
		}

		// Validate sources
		for j, source := range pipeline.Sources {
			if err := validateSource(pipeline.Name, j, &source); err != nil {
				return err
			}
		}

		// Validate rate limit if present
		if err := validateRateLimit(pipeline.Name, pipeline.RateLimit); err != nil {
			return err
		}

		// Validate filters
		for j, filterCfg := range pipeline.Filters {
			if err := validateFilter(pipeline.Name, j, &filterCfg); err != nil {
				return err
			}
		}

		// Pipeline must have at least one sink
		if len(pipeline.Sinks) == 0 {
			return fmt.Errorf("pipeline '%s': no sinks specified", pipeline.Name)
		}

		// Validate sinks and check for port conflicts
		for j, sink := range pipeline.Sinks {
			if err := validateSink(pipeline.Name, j, &sink, allPorts); err != nil {
				return err
			}
		}

		// Validate auth if present
		if err := validateAuth(pipeline.Name, pipeline.Auth); err != nil {
			return err
		}
	}

	return nil
}