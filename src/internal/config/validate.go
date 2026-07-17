package config

import (
	"fmt"

	lconfig "github.com/lixenwraith/config"
)

// ValidateConfig validates top-level structure only
// Value range validation is delegated to component constructors
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if len(cfg.Pipelines) == 0 {
		return fmt.Errorf("no pipelines configured")
	}

	// Reject duplicate pipeline names (service map is keyed by name)
	names := make(map[string]struct{}, len(cfg.Pipelines))
	for i, p := range cfg.Pipelines {
		if _, dup := names[p.Name]; dup {
			return fmt.Errorf("pipeline[%d]: duplicate name %q", i, p.Name)
		}
		names[p.Name] = struct{}{}
	}

	if err := validateLogConfig(cfg.Logging); err != nil {
		return fmt.Errorf("logging: %w", err)
	}

	for i, p := range cfg.Pipelines {
		if err := lconfig.NonEmpty(p.Name); err != nil {
			return fmt.Errorf("pipeline[%d].name: %w", i, err)
		}
		if len(p.PluginSources) == 0 {
			return fmt.Errorf("pipeline[%d]: no sources defined", i)
		}
		if len(p.PluginSinks) == 0 {
			return fmt.Errorf("pipeline[%d]: no sinks defined", i)
		}
	}

	return nil
}

// validateLogConfig validates application logging settings
func validateLogConfig(cfg *LogConfig) error {
	if cfg == nil {
		return nil
	}

	validateOutput := lconfig.OneOf("file", "stdout", "stderr", "split", "all", "none")
	if err := validateOutput(cfg.Output); err != nil {
		return fmt.Errorf("output: %w", err)
	}

	validateLevel := lconfig.OneOf("debug", "info", "warn", "error")
	if err := validateLevel(cfg.Level); err != nil {
		return fmt.Errorf("level: %w", err)
	}

	if cfg.Format != "" {
		if err := lconfig.OneOf("raw", "txt", "json")(cfg.Format); err != nil {
			return fmt.Errorf("format: %w", err)
		}
	}
	if cfg.Sanitization != "" {
		if err := lconfig.OneOf("raw", "json", "txt", "shell")(cfg.Sanitization); err != nil {
			return fmt.Errorf("sanitization: %w", err)
		}
	}

	if cfg.Console != nil {
		validateTarget := lconfig.OneOf("stdout", "stderr", "split")
		if err := validateTarget(cfg.Console.Target); err != nil {
			return fmt.Errorf("console.target: %w", err)
		}
	}

	return nil
}
