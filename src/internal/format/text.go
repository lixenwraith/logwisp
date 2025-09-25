// FILE: logwisp/src/internal/format/text.go
package format

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// Produces human-readable text logs using templates
type TextFormatter struct {
	template        *template.Template
	timestampFormat string
	logger          *log.Logger
}

// Creates a new text formatter
func NewTextFormatter(options map[string]any, logger *log.Logger) (*TextFormatter, error) {
	// Default template
	templateStr := "[{{.Timestamp | FmtTime}}] [{{.Level | ToUpper}}] {{.Source}} - {{.Message}}{{ if .Fields }} {{.Fields}}{{ end }}"
	if tmpl, ok := options["template"].(string); ok && tmpl != "" {
		templateStr = tmpl
	}

	// Default timestamp format
	timestampFormat := time.RFC3339
	if tsFormat, ok := options["timestamp_format"].(string); ok && tsFormat != "" {
		timestampFormat = tsFormat
	}

	f := &TextFormatter{
		timestampFormat: timestampFormat,
		logger:          logger,
	}

	// Create template with helper functions
	funcMap := template.FuncMap{
		"FmtTime": func(t time.Time) string {
			return t.Format(f.timestampFormat)
		},
		"ToUpper":   strings.ToUpper,
		"ToLower":   strings.ToLower,
		"TrimSpace": strings.TrimSpace,
	}

	tmpl, err := template.New("log").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}

	f.template = tmpl
	return f, nil
}

// Formats the log entry using the template
func (f *TextFormatter) Format(entry core.LogEntry) ([]byte, error) {
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
			"component", "text_formatter",
			"error", err)

		fallback := fmt.Sprintf("[%s] [%s] %s - %s\n",
			entry.Time.Format(f.timestampFormat),
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
func (f *TextFormatter) Name() string {
	return "text"
}