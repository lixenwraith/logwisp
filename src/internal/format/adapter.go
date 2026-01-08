package format

import (
	"encoding/json"
	"fmt"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log/formatter"
	"github.com/lixenwraith/log/sanitizer"
)

const (
	DefaultFormatType = "raw"
)

// FormatterAdapter wraps log/formatter for logwisp compatibility
type FormatterAdapter struct {
	formatter *formatter.Formatter
	format    string
	flags     int64
}

// NewFormatterAdapter creates adapter from config
func NewFormatterAdapter(cfg *config.FormatConfig) (*FormatterAdapter, error) {
	// Validate
	if cfg.Type != "" {
		validateType := lconfig.OneOf("json", "txt", "text", "raw")
		if err := validateType(cfg.Type); err != nil {
			return nil, fmt.Errorf("type: %w", err)
		}
	}

	if cfg.SanitizerPolicy != "" {
		validatePolicy := lconfig.OneOf("raw", "json", "txt", "shell")
		if err := validatePolicy(cfg.SanitizerPolicy); err != nil {
			return nil, fmt.Errorf("sanitizer_policy: %w", err)
		}
	}

	// Defaults
	if cfg.Type == "" {
		cfg.Type = DefaultFormatType
	}

	// Create sanitizer based on policy
	var s *sanitizer.Sanitizer
	if cfg.SanitizerPolicy != "" {
		s = sanitizer.New().Policy(sanitizer.PolicyPreset(cfg.SanitizerPolicy))
	} else {
		// Default sanitizer policy based on format type
		switch cfg.Type {
		case "json":
			s = sanitizer.New().Policy(sanitizer.PolicyJSON)
		case "txt", "text":
			s = sanitizer.New().Policy(sanitizer.PolicyTxt)
		default:
			s = sanitizer.New().Policy(sanitizer.PolicyRaw)
		}
	}

	// Create formatter with sanitizer
	f := formatter.New(s).Type(cfg.Type)

	if cfg.TimestampFormat != "" {
		f.TimestampFormat(cfg.TimestampFormat)
	}

	// Build flags from config
	flags := cfg.Flags
	if flags == 0 {
		if cfg.Type == "raw" {
			flags = formatter.FlagRaw
		} else {
			flags = formatter.FlagDefault
		}
	}

	return &FormatterAdapter{
		formatter: f,
		format:    cfg.Type,
		flags:     flags,
	}, nil
}

// Format implements Formatter interface
func (a *FormatterAdapter) Format(entry core.LogEntry) ([]byte, error) {
	// Map logwisp LogEntry to formatter args
	level := mapLevel(entry.Level)

	// Build args based on whether we have structured fields
	var args []any

	if len(entry.Fields) > 0 {
		// Parse fields JSON
		var fields map[string]any
		if err := json.Unmarshal(entry.Fields, &fields); err == nil && len(fields) > 0 {
			// Use structured JSON format for fields
			args = []any{entry.Message, fields}
			// Add structured flag to properly format fields as JSON object
			effectiveFlags := a.flags | formatter.FlagStructuredJSON
			return a.formatter.Format(effectiveFlags, entry.Time, level, entry.Source, args), nil
		}
	}

	// Simple message without fields
	args = []any{entry.Message}
	return a.formatter.Format(a.flags, entry.Time, level, entry.Source, args), nil
}

// FormatWithFlags allows custom flags for specific formatting needs
func (a *FormatterAdapter) FormatWithFlags(entry core.LogEntry, customFlags int64) ([]byte, error) {
	level := mapLevel(entry.Level)

	var args []any
	if len(entry.Fields) > 0 {
		var fields map[string]any
		if err := json.Unmarshal(entry.Fields, &fields); err == nil && len(fields) > 0 {
			args = []any{entry.Message, fields}
			customFlags |= formatter.FlagStructuredJSON
		} else {
			args = []any{entry.Message}
		}
	} else {
		args = []any{entry.Message}
	}

	return a.formatter.Format(customFlags, entry.Time, level, entry.Source, args), nil
}

// Name returns formatter type
func (a *FormatterAdapter) Name() string {
	return a.format
}

// mapLevel maps string level to int64
func mapLevel(level string) int64 {
	switch level {
	case "DEBUG", "debug":
		return -4
	case "INFO", "info":
		return 0
	case "WARN", "warn", "WARNING", "warning":
		return 4
	case "ERROR", "error":
		return 8
	default:
		return 0
	}
}