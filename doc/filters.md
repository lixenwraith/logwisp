# Filters

LogWisp filters control which log entries pass through the pipeline using pattern matching.

## Filter Types

### Include Filter

Only entries matching patterns pass through.

```toml
[[pipelines.filters]]
type = "include"
logic = "or"  # or|and
patterns = [
    "ERROR",
    "WARN",
    "CRITICAL"
]
```

### Exclude Filter

Entries matching patterns are dropped.

```toml
[[pipelines.filters]]
type = "exclude"
patterns = [
    "DEBUG",
    "TRACE",
    "health-check"
]
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | Required | Filter type (include/exclude) |
| `logic` | string | "or" | Pattern matching logic (or/and) |
| `patterns` | []string | Required | Pattern list |

## Pattern Syntax

Patterns support regular expression syntax:

### Basic Patterns
- **Literal match**: `"ERROR"` - matches "ERROR" anywhere
- **Case-insensitive**: `"(?i)error"` - matches "error", "ERROR", "Error"
- **Word boundary**: `"\\berror\\b"` - matches whole word only

### Advanced Patterns
- **Alternation**: `"ERROR|WARN|FATAL"`
- **Character classes**: `"[0-9]{3}"`
- **Wildcards**: `".*exception.*"`
- **Line anchors**: `"^ERROR"` (start), `"ERROR$"` (end)

### Special Characters
Escape special regex characters with backslash:
- `.` → `\\.`
- `*` → `\\*`
- `[` → `\\[`
- `(` → `\\(`

## Filter Logic

### OR Logic (default)
Entry passes if ANY pattern matches:
```toml
logic = "or"
patterns = ["ERROR", "WARN"]
# Passes: "ERROR in module", "WARN: low memory"
# Blocks: "INFO: started"
```

### AND Logic
Entry passes only if ALL patterns match:
```toml
logic = "and"  
patterns = ["database", "ERROR"]
# Passes: "ERROR: database connection failed"
# Blocks: "ERROR: file not found"
```

## Filter Chain

Multiple filters execute sequentially:

```toml
# First filter: Include errors and warnings
[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "WARN"]

# Second filter: Exclude test environments
[[pipelines.filters]]
type = "exclude"
patterns = ["test-env", "staging"]
```

Processing order:
1. Entry arrives from source
2. Include filter evaluates
3. If passed, exclude filter evaluates
4. If passed all filters, entry continues to sink

## Performance Considerations

### Pattern Compilation
- Patterns compile once at startup
- Invalid patterns cause startup failure
- Complex patterns may impact performance

### Optimization Tips
- Place most selective filters first
- Use simple patterns when possible
- Combine related patterns with alternation
- Avoid excessive wildcards (`.*`)

## Filter Statistics

Filters track:
- Total entries evaluated
- Entries passed
- Entries blocked
- Processing time per pattern

## Common Use Cases

### Log Level Filtering
```toml
[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "WARN", "FATAL", "CRITICAL"]
```

### Application Filtering
```toml
[[pipelines.filters]]
type = "include"
patterns = ["app1", "app2", "app3"]
```

### Noise Reduction
```toml
[[pipelines.filters]]
type = "exclude"
patterns = [
    "health-check",
    "ping",
    "/metrics",
    "heartbeat"
]
```

### Security Filtering
```toml
[[pipelines.filters]]
type = "exclude"
patterns = [
    "password",
    "token",
    "api[_-]key",
    "secret"
]
```

### Multi-stage Filtering
```toml
# Include production logs
[[pipelines.filters]]
type = "include"
patterns = ["prod-", "production"]

# Include only errors
[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "EXCEPTION", "FATAL"]

# Exclude known issues
[[pipelines.filters]]
type = "exclude"
patterns = ["ECONNRESET", "broken pipe"]
```