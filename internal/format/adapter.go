package format

import (
	"bytes"
	"encoding/json"
	"sync"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/log/formatter"
	"github.com/lixenwraith/log/sanitizer"
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
	if err := config.Settle(cfg); err != nil {
		return nil, err
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
		case "txt":
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

// serialize renders an entry under the given flags as one record ending in
// one newline, which raw output lacks unless the message carried it. The
// result is a copy: the formatter reuses one buffer and sinks keep payloads.
func (a *FormatterAdapter) serialize(entry core.LogEntry, flags int64) []byte {
	args, flags := formatArgs(entry, flags)

	a.mu.Lock()
	out := a.formatter.Format(flags, entry.Time, mapLevel(entry.Level), sourceLabel(entry), args)
	record := make([]byte, len(out), len(out)+1)
	copy(record, out)
	a.mu.Unlock()
	if !bytes.HasSuffix(record, []byte{'\n'}) {
		record = append(record, '\n')
	}
	return record
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
