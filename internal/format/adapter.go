package format

import (
	"bytes"
	"encoding/json"
	"strings"
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
}

// NewFormatterAdapter creates adapter from config
func NewFormatterAdapter(cfg *config.FormatConfig) (*FormatterAdapter, error) {
	cfg = new(*cfg) // settled as a copy: the configuration keeps the keys set
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
// one newline, which raw output lacks unless the message carried it. Sources
// format at once (AppendFormat keeps no state) into pooled scratch, and the
// record is a copy of its size: sinks keep payloads.
func (a *FormatterAdapter) serialize(entry core.LogEntry, flags int64) []byte {
	var argv [2]any
	args, flags := formatArgs(&argv, entry, flags)
	buf := scratch.Get().(*[]byte)
	out := a.formatter.AppendFormat((*buf)[:0], flags, entry.Time, mapLevel(entry.Level), entry.Label(), args)
	record := make([]byte, len(out), len(out)+1)
	copy(record, out)
	if cap(out) <= maxScratch {
		*buf = out
		scratch.Put(buf)
	}
	if !bytes.HasSuffix(record, []byte{'\n'}) {
		record = append(record, '\n')
	}
	return record
}

// scratch holds records while they are formatted; one longer than maxScratch
// is not kept, so a rare large entry pins no memory
var scratch = sync.Pool{New: func() any { return new([]byte) }}

const maxScratch = 64 << 10

// formatArgs puts the entry's arguments in argv and pairs them with its flags.
// FlagRaw keeps the fields JSON verbatim beside the message rather than
// silently overriding the caller's choice of passthrough; every other mode
// renders it as a JSON object.
func formatArgs(argv *[2]any, entry core.LogEntry, flags int64) ([]any, int64) {
	argv[0] = entry.Message
	if len(entry.Fields) == 0 {
		return argv[:1], flags
	}
	if flags&formatter.FlagRaw != 0 {
		if entry.Message == "" {
			argv[0] = []byte(entry.Fields)
			return argv[:1], flags
		}
		argv[1] = []byte(entry.Fields)
		return argv[:2], flags
	}

	var fields map[string]any
	if err := json.Unmarshal(entry.Fields, &fields); err != nil || len(fields) == 0 {
		return argv[:1], flags
	}
	argv[1] = fields
	return argv[:2], flags | formatter.FlagStructuredJSON
}

// Name returns formatter type
func (a *FormatterAdapter) Name() string {
	return a.format
}

// mapLevel is the log library's number for the level an entry's word names
// in core.Levels, TRACE -8 to ERROR 8 by rank; no level, or another word, is
// INFO's 0
func mapLevel(level string) int64 {
	if level == "" {
		return 0
	}
	for i, l := range core.Levels {
		if level == l.Level {
			return int64(i-2) * 4
		}
	}
	for i, l := range core.Levels {
		for _, names := range [2][]string{l.Names, l.Keyed} {
			for _, name := range names {
				if strings.EqualFold(level, name) {
					return int64(i-2) * 4
				}
			}
		}
	}
	return 0
}
