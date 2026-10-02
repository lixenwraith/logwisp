package config

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

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

// Scan decodes a plugin's config map into target, rejecting keys target does
// not declare: a misspelled tls or auth key must fail, not silently disable
// the protection it was meant to configure.
func Scan(configMap map[string]any, target any) error {
	if err := unknownKeys(configMap, reflect.TypeOf(target), ""); err != nil {
		return err
	}
	return lconfig.ScanMap(configMap, target)
}

// unknownKeys walks nested tables against the toml tags of t. Map-typed fields
// hold free-form keys and are not descended into.
func unknownKeys(m map[string]any, t reflect.Type, prefix string) error {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	fields := make(map[string]reflect.Type, t.NumField())
	for f := range t.Fields() {
		if name, _, _ := strings.Cut(f.Tag.Get("toml"), ","); name != "" && name != "-" {
			fields[name] = f.Type
		}
	}
	for _, key := range slices.Sorted(maps.Keys(m)) {
		ft, ok := fields[key]
		if !ok {
			return fmt.Errorf("unknown key %q", prefix+key)
		}
		var tables []map[string]any
		switch v := m[key].(type) {
		case map[string]any:
			tables = []map[string]any{v}
		case []map[string]any:
			tables = v
		case []any:
			for _, e := range v {
				if table, ok := e.(map[string]any); ok {
					tables = append(tables, table)
				}
			}
		}
		for _, table := range tables {
			if err := unknownKeys(table, ft, prefix+key+"."); err != nil {
				return err
			}
		}
	}
	return nil
}
