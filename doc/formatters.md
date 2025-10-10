# Formatters

LogWisp formatters transform log entries before output to sinks.

## Formatter Types

### Raw Formatter

Outputs the log message as-is with optional newline.

```toml
[pipelines.format]
type = "raw"

[pipelines.format.raw]
add_new_line = true
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `add_new_line` | bool | true | Append newline to messages |

### JSON Formatter

Produces structured JSON output.

```toml
[pipelines.format]
type = "json"

[pipelines.format.json]
pretty = false
timestamp_field = "timestamp"
level_field = "level"
message_field = "message"
source_field = "source"
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pretty` | bool | false | Pretty print JSON |
| `timestamp_field` | string | "timestamp" | Field name for timestamp |
| `level_field` | string | "level" | Field name for log level |
| `message_field` | string | "message" | Field name for message |
| `source_field` | string | "source" | Field name for source |

**Output Structure:**
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "ERROR",
  "source": "app",
  "message": "Connection failed"
}
```

### Text Formatter

Template-based text formatting.

```toml
[pipelines.format]
type = "txt"

[pipelines.format.txt]
template = "[{{.Timestamp | FmtTime}}] [{{.Level | ToUpper}}] {{.Source}} - {{.Message}}"
timestamp_format = "2006-01-02T15:04:05.000Z07:00"
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `template` | string | See below | Go template string |
| `timestamp_format` | string | RFC3339 | Go time format string |

**Default Template:**
```
[{{.Timestamp | FmtTime}}] [{{.Level | ToUpper}}] {{.Source}} - {{.Message}}{{ if .Fields }} {{.Fields}}{{ end }}
```

## Template Functions

Available functions in text templates:

| Function | Description | Example |
|----------|-------------|---------|
| `FmtTime` | Format timestamp | `{{.Timestamp \| FmtTime}}` |
| `ToUpper` | Convert to uppercase | `{{.Level \| ToUpper}}` |
| `ToLower` | Convert to lowercase | `{{.Source \| ToLower}}` |
| `TrimSpace` | Remove whitespace | `{{.Message \| TrimSpace}}` |

## Template Variables

Available variables in templates:

| Variable | Type | Description |
|----------|------|-------------|
| `.Timestamp` | time.Time | Entry timestamp |
| `.Level` | string | Log level |
| `.Source` | string | Source identifier |
| `.Message` | string | Log message |
| `.Fields` | string | Additional fields (JSON) |

## Time Format Strings

Common Go time format patterns:

| Pattern | Example Output |
|---------|---------------|
| `2006-01-02T15:04:05Z07:00` | 2024-01-02T15:04:05Z |
| `2006-01-02 15:04:05` | 2024-01-02 15:04:05 |
| `Jan 2 15:04:05` | Jan 2 15:04:05 |
| `15:04:05.000` | 15:04:05.123 |
| `2006/01/02` | 2024/01/02 |

## Format Selection

### Default Behavior

If no formatter specified:
- **HTTP/TCP sinks**: JSON format
- **Console/File sinks**: Raw format
- **Client sinks**: JSON format

### Per-Pipeline Configuration

Each pipeline can have its own formatter:

```toml
[[pipelines]]
name = "json-pipeline"
[pipelines.format]
type = "json"

[[pipelines]]
name = "text-pipeline"
[pipelines.format]
type = "txt"
```

## Message Processing

### JSON Message Handling

When using JSON formatter with JSON log messages:
1. Attempts to parse message as JSON
2. Merges fields with LogWisp metadata
3. LogWisp fields take precedence
4. Falls back to string if parsing fails

### Field Preservation

LogWisp metadata always includes:
- Timestamp (from source or current time)
- Level (detected or default)
- Source (origin identifier)
- Message (original content)

## Performance Characteristics

### Formatter Performance

Relative performance (fastest to slowest):
1. **Raw**: Direct passthrough
2. **Text**: Template execution
3. **JSON**: Serialization
4. **JSON (pretty)**: Formatted serialization

### Optimization Tips

- Use raw format for high throughput
- Cache template compilation (automatic)
- Minimize template complexity
- Avoid pretty JSON in production

## Common Configurations

### Structured Logging
```toml
[pipelines.format]
type = "json"
[pipelines.format.json]
pretty = false
```

### Human-Readable Logs
```toml
[pipelines.format]
type = "txt"
[pipelines.format.txt]
template = "{{.Timestamp | FmtTime}} [{{.Level}}] {{.Message}}"
timestamp_format = "15:04:05"
```

### Syslog Format
```toml
[pipelines.format]
type = "txt"
[pipelines.format.txt]
template = "{{.Timestamp | FmtTime}} {{.Source}} {{.Level}}: {{.Message}}"
timestamp_format = "Jan 2 15:04:05"
```

### Minimal Output
```toml
[pipelines.format]
type = "txt"
[pipelines.format.txt]
template = "{{.Message}}"
```