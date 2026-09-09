package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"logwisp/internal/config"
	"logwisp/internal/core"

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
	mu        sync.Mutex // formatter reuses internal buffer, not goroutine-safe
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
	return a.serialize(entry, a.flags), nil
}

// FormatWithFlags allows custom flags for specific formatting needs
func (a *FormatterAdapter) FormatWithFlags(entry core.LogEntry, customFlags int64) ([]byte, error) {
	return a.serialize(entry, customFlags), nil
}

// serialize renders an entry under the given flags. The returned slice is a
// copy: the underlying formatter reuses one buffer and sinks retain payloads.
func (a *FormatterAdapter) serialize(entry core.LogEntry, flags int64) []byte {
	args, flags := formatArgs(entry, flags)

	a.mu.Lock()
	out := bytes.Clone(a.formatter.Format(flags, entry.Time, mapLevel(entry.Level), sourceLabel(entry), args))
	a.mu.Unlock()
	return out
}

// formatArgs pairs the entry with its flags. FlagRaw keeps the fields JSON
// verbatim beside the message rather than silently overriding the caller's
// choice of passthrough; every other mode renders it as a JSON object.
func formatArgs(entry core.LogEntry, flags int64) ([]any, int64) {
	if len(entry.Fields) == 0 {
		return []any{entry.Message}, flags
	}
	if flags&formatter.FlagRaw != 0 {
		if entry.Message == "" {
			return []any{[]byte(entry.Fields)}, flags
		}
		return []any{entry.Message, []byte(entry.Fields)}, flags
	}

	var fields map[string]any
	if err := json.Unmarshal(entry.Fields, &fields); err != nil || len(fields) == 0 {
		return []any{entry.Message}, flags
	}
	return []any{entry.Message, fields}, flags | formatter.FlagStructuredJSON
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

// sourceLabel prefixes origin node onto source (syslog HOSTNAME + TAG convention)
func sourceLabel(entry core.LogEntry) string {
	if entry.Node == "" {
		return entry.Source
	}
	return entry.Node + "/" + entry.Source
}
