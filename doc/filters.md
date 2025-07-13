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

## Regex Pattern Guide

LogWisp uses Go's standard regex engine (RE2). It includes most common features but omits backtracking-heavy syntax.

For complex logic, chain multiple filters (e.g., an `include` followed by an `exclude`) rather than writing one complex regex.

### Basic Matching

| Pattern | Description | Example |
| :--- | :--- | :--- |
| `literal` | Matches the exact text. | `"ERROR"` matches any log with "ERROR". |
| `.` | Matches any single character (except newline). | `"user."` matches "userA", "userB", etc. |
| `a\|b` | Matches expression `a` OR expression `b`. | `"error\|fail"` matches lines with "error" or "fail". |

### Anchors and Boundaries

Anchors tie your pattern to a specific position in the line.

| Pattern | Description | Example |
| :--- | :--- | :--- |
| `^` | Matches the beginning of the line. | `"^ERROR"` matches lines *starting* with "ERROR". |
| `$` | Matches the end of the line. | `"crashed$"` matches lines *ending* with "crashed". |
| `\b` | Matches a word boundary. | `"\berror\b"` matches "error" but not "terrorist". |

### Character Classes

| Pattern | Description | Example |
| :--- | :--- | :--- |
| `[abc]` | Matches `a`, `b`, or `c`. | `"[aeiou]"` matches any vowel. |
| `[^abc]` | Matches any character *except* `a`, `b`, or `c`. | `"[^0-9]"` matches any non-digit. |
| `[a-z]` | Matches any character in the range `a` to `z`. | `"[a-zA-Z]"` matches any letter. |
| `\d` | Matches any digit (`[0-9]`). | `\d{3}` matches three digits, like "123". |
| `\w` | Matches any word character (`[a-zA-Z0-9_]`). | `\w+` matches one or more word characters. |
| `\s` | Matches any whitespace character. | `\s+` matches one or more spaces or tabs. |

### Quantifiers

Quantifiers specify how many times a character or group must appear.

| Pattern | Description | Example |
| :--- | :--- | :--- |
| `*` | Zero or more times. | `"a*"` matches "", "a", "aa". |
| `+` | One or more times. | `"a+"` matches "a", "aa", but not "". |
| `?` | Zero or one time. | `"colou?r"` matches "color" and "colour". |
| `{n}` | Exactly `n` times. | `\d{4}` matches a 4-digit number. |
| `{n,}` | `n` or more times. | `\d{2,}` matches numbers with 2 or more digits. |
| `{n,m}` | Between `n` and `m` times. | `\d{1,3}` matches numbers with 1 to 3 digits. |

### Grouping

| Pattern | Description | Example |
| :--- | :--- | :--- |
| `(...)` | Groups an expression and captures the match. | `(ERROR|WARN)` captures "ERROR" or "WARN". |
| `(?:...)`| Groups an expression *without* capturing. Faster. | `(?:ERROR|WARN)` is more efficient if you just need to group. |

### Flags and Modifiers

Flags are placed at the beginning of a pattern to change its behavior.

| Pattern | Description |
| :--- | :--- |
| `(?i)` | Case-insensitive matching. |
| `(?m)` | Multi-line mode (`^` and `$` match start/end of lines). |

**Example:** `"(?i)error"` matches "error", "ERROR", and "Error".

### Practical Examples for Logging

*   **Match an IP Address:**
    ```
    \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
    ```

*   **Match HTTP 4xx or 5xx Status Codes:**
    ```
    "status[= ](4|5)\d{2}"
    ```

*   **Match a slow database query (>100ms):**
    ```
    "Query took [1-9]\d{2,}ms"
    ```

*   **Match key-value pairs:**
    ```
    "user=(admin|guest)"
    ```

*   **Match Java exceptions:**
    ```
    "Exception:|at .+\.java:\d+"
    ```