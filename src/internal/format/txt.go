// FILE: logwisp/src/internal/format/txt.go
package format

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Produces human-readable text logs using templates
type TxtFormatter struct {
	config   *config.TxtFormatterOptions
	template *template.Template
	logger   *log.Logger
}

// Creates a new text formatter
func NewTxtFormatter(opts *config.TxtFormatterOptions, logger *log.Logger) (*TxtFormatter, error) {
	f := &TxtFormatter{
		config: opts,
		logger: logger,
	}

	// Create template with helper functions
	funcMap := template.FuncMap{
		"FmtTime": func(t time.Time) string {
			return t.Format(f.config.TimestampFormat)
		},
		"ToUpper":   strings.ToUpper,
		"ToLower":   strings.ToLower,
		"TrimSpace": strings.TrimSpace,
	}

	tmpl, err := template.New("log").Funcs(funcMap).Parse(f.config.Template)
	if err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}

	f.template = tmpl
	return f, nil
}

// Formats the log entry using the template
func (f *TxtFormatter) Format(entry core.LogEntry) ([]byte, error) {
	// Prepare data for template
	data := map[string]any{
		"Timestamp": entry.Time,
		"Level":     entry.Level,
		"Source":    entry.Source,
		"Message":   entry.Message,
	}

	// Set default level if empty
	if data["Level"] == "" {
		data["Level"] = "INFO"
	}

	// Add fields if present
	if len(entry.Fields) > 0 {
		data["Fields"] = string(entry.Fields)
	}

	var buf bytes.Buffer
	if err := f.template.Execute(&buf, data); err != nil {
		// Fallback: return a basic formatted message
		f.logger.Debug("msg", "Template execution failed, using fallback",
			"component", "txt_formatter",
			"error", err)

		fallback := fmt.Sprintf("[%s] [%s] %s - %s\n",
			entry.Time.Format(f.config.TimestampFormat),
			strings.ToUpper(entry.Level),
			entry.Source,
			entry.Message)
		return []byte(fallback), nil
	}

	// Ensure newline at end
	result := buf.Bytes()
	if len(result) == 0 || result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}

	return result, nil
}

// Returns the formatter name
func (f *TxtFormatter) Name() string {
	return "txt"
}