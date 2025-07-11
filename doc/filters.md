# Filter Guide

LogWisp filters control which log entries pass through pipelines using regular expressions.

## How Filters Work

- **Include**: Only matching logs pass (whitelist)
- **Exclude**: Matching logs are dropped (blacklist)
- Multiple filters apply sequentially - all must pass

## Configuration

```toml
[[pipelines.filters]]
type = "include"    # or "exclude"
logic = "or"        # or "and"
patterns = [
    "pattern1",
    "pattern2"
]
```

### Filter Types

#### Include Filter
```toml
[[pipelines.filters]]
type = "include"
logic = "or"
patterns = ["ERROR", "WARN", "CRITICAL"]
# Only ERROR, WARN, or CRITICAL logs pass
```

#### Exclude Filter
```toml
[[pipelines.filters]]
type = "exclude"
patterns = ["DEBUG", "TRACE", "/health"]
# DEBUG, TRACE, and health checks are dropped
```

### Logic Operators

- **OR**: Match ANY pattern (default)
- **AND**: Match ALL patterns

```toml
# OR Logic
logic = "or"
patterns = ["ERROR", "FAIL"]
# Matches: "ERROR: disk full" OR "FAIL: timeout"

# AND Logic
logic = "and"
patterns = ["database", "timeout", "ERROR"]
# Matches: "ERROR: database connection timeout"
# Not: "ERROR: file not found"
```

## Pattern Syntax

Go regular expressions (RE2):

```toml
"ERROR"              # Substring match
"(?i)error"          # Case-insensitive
"\\berror\\b"        # Word boundaries
"^ERROR"             # Start of line
"ERROR$"             # End of line
"error|fail|warn"    # Alternatives
```

## Common Patterns

### Log Levels
```toml
patterns = [
    "\\[(ERROR|WARN|INFO)\\]",      # [ERROR] format
    "(?i)\\b(error|warning)\\b",    # Word boundaries
    "level=(error|warn)",           # key=value format
]
```

### Application Errors
```toml
# Java
patterns = [
    "Exception",
    "at .+\\.java:[0-9]+",
    "NullPointerException"
]

# Python
patterns = [
    "Traceback",
    "File \".+\\.py\", line [0-9]+",
    "ValueError|TypeError"
]

# Go
patterns = [
    "panic:",
    "goroutine [0-9]+",
    "runtime error:"
]
```

### Performance Issues
```toml
patterns = [
    "took [0-9]{4,}ms",           # >999ms operations
    "timeout|timed out",
    "slow query",
    "high cpu|cpu usage: [8-9][0-9]%"
]
```

### HTTP Patterns
```toml
patterns = [
    "status[=:][4-5][0-9]{2}",    # 4xx/5xx codes
    "HTTP/[0-9.]+ [4-5][0-9]{2}",
    "\"/api/v[0-9]+/",            # API paths
]
```

## Filter Chains

### Error Monitoring
```toml
# Include errors
[[pipelines.filters]]
type = "include"
patterns = ["(?i)\\b(error|fail|critical)\\b"]

# Exclude known non-issues
[[pipelines.filters]]
type = "exclude"
patterns = ["Error: Expected", "/health"]
```

### API Monitoring
```toml
# Include API calls
[[pipelines.filters]]
type = "include"
patterns = ["/api/", "/v[0-9]+/"]

# Exclude successful
[[pipelines.filters]]
type = "exclude"
patterns = ["\" 2[0-9]{2} "]
```

## Performance Tips

1. **Use anchors**: `^ERROR` faster than `ERROR`
2. **Avoid nested quantifiers**: `((a+)+)+`
3. **Non-capturing groups**: `(?:error|warn)`
4. **Order by frequency**: Most common first
5. **Simple patterns**: Faster than complex regex

## Testing Filters

```bash
# Test configuration
echo "[ERROR] Test" >> test.log
echo "[INFO] Test" >> test.log

# Run with debug
logwisp --log-level debug

# Check output
curl -N http://localhost:8080/stream
```