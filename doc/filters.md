# Filter Guide

LogWisp's filtering system allows you to control which log entries are streamed to clients, reducing noise and focusing on what matters.

## How Filters Work

Filters use regular expressions to match log entries. Each filter can either:
- **Include**: Only matching logs pass through (whitelist)
- **Exclude**: Matching logs are dropped (blacklist)

Multiple filters are applied sequentially - a log entry must pass ALL filters to be streamed.

## Filter Configuration

### Basic Structure

```toml
[[streams.filters]]
type = "include"    # or "exclude"
logic = "or"        # or "and"
patterns = [
    "pattern1",
    "pattern2"
]
```

### Filter Types

#### Include Filter (Whitelist)
Only logs matching the patterns are streamed:

```toml
[[streams.filters]]
type = "include"
logic = "or"
patterns = [
    "ERROR",
    "WARN",
    "CRITICAL"
]
# Result: Only ERROR, WARN, or CRITICAL logs are streamed
```

#### Exclude Filter (Blacklist)
Logs matching the patterns are dropped:

```toml
[[streams.filters]]
type = "exclude"
patterns = [
    "DEBUG",
    "TRACE",
    "/health"
]
# Result: DEBUG, TRACE, and health check logs are filtered out
```

### Logic Operators

#### OR Logic (Default)
Log matches if ANY pattern matches:

```toml
[[streams.filters]]
type = "include"
logic = "or"
patterns = ["ERROR", "FAIL", "EXCEPTION"]
# Matches: "ERROR: disk full" OR "FAIL: connection timeout" OR "NullPointerException"
```

#### AND Logic
Log matches only if ALL patterns match:

```toml
[[streams.filters]]
type = "include"
logic = "and"
patterns = ["database", "timeout", "ERROR"]
# Matches: "ERROR: database connection timeout"
# Doesn't match: "ERROR: file not found" (missing "database" and "timeout")
```

## Pattern Syntax

LogWisp uses Go's regular expression syntax (RE2):

### Basic Patterns

```toml
patterns = [
    "ERROR",                    # Exact substring match
    "(?i)error",               # Case-insensitive
    "\\berror\\b",             # Word boundaries
    "^ERROR",                  # Start of line
    "ERROR$",                  # End of line
    "ERR(OR)?",                # Optional group
    "error|fail|exception"     # Alternatives
]
```

### Common Pattern Examples

#### Log Levels
```toml
# Standard log levels
patterns = [
    "\\[(ERROR|WARN|INFO|DEBUG)\\]",     # [ERROR] format
    "(?i)\\b(error|warning|info|debug)\\b", # Word boundaries
    "level=(error|warn|info|debug)",      # key=value format
    "<(Error|Warning|Info|Debug)>"        # XML-style
]

# Severity patterns
patterns = [
    "(?i)(fatal|critical|severe)",
    "(?i)(error|fail|exception)",
    "(?i)(warn|warning|caution)",
    "panic:",                             # Go panics
    "Traceback",                          # Python errors
]
```

#### Application Errors
```toml
# Java/JVM
patterns = [
    "Exception",
    "\\.java:[0-9]+",                    # Stack trace lines
    "at com\\.mycompany\\.",             # Company packages
    "NullPointerException|ClassNotFoundException"
]

# Python
patterns = [
    "Traceback \\(most recent call last\\)",
    "File \".+\\.py\", line [0-9]+",
    "(ValueError|TypeError|KeyError)"
]

# Go
patterns = [
    "panic:",
    "goroutine [0-9]+",
    "runtime error:"
]

# Node.js
patterns = [
    "Error:",
    "at .+ \\(.+\\.js:[0-9]+:[0-9]+\\)",
    "UnhandledPromiseRejection"
]
```

#### Performance Issues
```toml
patterns = [
    "took [0-9]{4,}ms",                  # Operations over 999ms
    "duration>[0-9]{3,}s",               # Long durations
    "timeout|timed out",                 # Timeouts
    "slow query",                        # Database
    "memory pressure",                   # Memory issues
    "high cpu|cpu usage: [8-9][0-9]%"   # CPU issues
]
```

#### Security Patterns
```toml
patterns = [
    "(?i)(unauthorized|forbidden|denied)",
    "(?i)(auth|authentication) fail",
    "invalid (token|session|credentials)",
    "SQL injection|XSS|CSRF",
    "brute force|rate limit",
    "suspicious activity"
]
```

#### HTTP Patterns
```toml
# Error status codes
patterns = [
    "status[=:][4-5][0-9]{2}",          # status=404, status:500
    "HTTP/[0-9.]+ [4-5][0-9]{2}",       # HTTP/1.1 404
    "\"status\":\\s*[4-5][0-9]{2}"      # JSON "status": 500
]

# Specific endpoints
patterns = [
    "\"(GET|POST|PUT|DELETE) /api/",
    "/api/v[0-9]+/users",
    "path=\"/admin"
]
```

## Filter Chains

Multiple filters create a processing chain. Each filter must pass for the log to be streamed.

### Example: Error Monitoring
```toml
# Step 1: Include only errors and warnings
[[streams.filters]]
type = "include"
logic = "or"
patterns = [
    "(?i)\\b(error|fail|exception)\\b",
    "(?i)\\b(warn|warning)\\b",
    "(?i)\\b(critical|fatal|severe)\\b"
]

# Step 2: Exclude known non-issues
[[streams.filters]]
type = "exclude"
patterns = [
    "Error: Expected behavior",
    "Warning: Deprecated API",
    "INFO.*error in message"          # INFO logs talking about errors
]

# Step 3: Exclude noisy sources
[[streams.filters]]
type = "exclude"
patterns = [
    "/health",
    "/metrics",
    "ELB-HealthChecker",
    "Googlebot"
]
```

### Example: API Monitoring
```toml
# Include only API calls
[[streams.filters]]
type = "include"
patterns = [
    "/api/",
    "/v[0-9]+/"
]

# Exclude successful requests
[[streams.filters]]
type = "exclude"
patterns = [
    "\" 200 ",                        # HTTP 200 OK
    "\" 201 ",                        # HTTP 201 Created
    "\" 204 ",                        # HTTP 204 No Content
    "\" 304 "                         # HTTP 304 Not Modified
]

# Exclude OPTIONS requests (CORS)
[[streams.filters]]
type = "exclude"
patterns = [
    "OPTIONS "
]
```

### Example: Security Audit
```toml
# Include security-relevant events
[[streams.filters]]
type = "include"
logic = "or"
patterns = [
    "(?i)auth",
    "(?i)login|logout",
    "(?i)sudo|root",
    "(?i)ssh|sftp|ftp",
    "(?i)firewall|iptables",
    "COMMAND=",                       # sudo commands
    "USER=",                          # user actions
    "SELINUX"
]

# Must also contain failure/success indicators
[[streams.filters]]
type = "include"
logic = "or"
patterns = [
    "(?i)(fail|denied|error)",
    "(?i)(success|accepted|granted)",
    "(?i)(invalid|unauthorized)"
]
```

## Performance Considerations

### Pattern Complexity

Simple patterns are fast (~1μs per check):
```toml
patterns = ["ERROR", "WARN", "FATAL"]
```

Complex patterns are slower (~10-100μs per check):
```toml
patterns = [
    "^\\[\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\]\\s+\\[(ERROR|WARN)\\]\\s+\\[([^\\]]+)\\]\\s+(.+)$"
]
```

### Optimization Tips

1. **Use anchors when possible**:
   ```toml
   "^ERROR" # Faster than "ERROR"
   ```

2. **Avoid nested quantifiers**:
   ```toml
   # BAD: Can cause exponential backtracking
   "((a+)+)+"
   
   # GOOD: Linear time
   "a+"
   ```

3. **Use non-capturing groups**:
   ```toml
   "(?:error|warn)" # Instead of "(error|warn)"
   ```

4. **Order patterns by frequency**:
   ```toml
   # Most common first
   patterns = ["ERROR", "WARN", "INFO", "DEBUG"]
   ```

5. **Prefer character classes**:
   ```toml
   "[0-9]" # Instead of "\\d"
   "[a-zA-Z]" # Instead of "\\w"
   ```

## Testing Filters

### Test Configuration
Create a test configuration with sample logs:

```toml
[[streams]]
name = "test"
[streams.monitor]
targets = [{ path = "./test-logs", pattern = "*.log" }]

[[streams.filters]]
type = "include"
patterns = ["YOUR_PATTERN_HERE"]

[streams.httpserver]
enabled = true
port = 8888
```

### Generate Test Logs
```bash
# Create test log entries
echo "[ERROR] Database connection failed" >> test-logs/app.log
echo "[INFO] User logged in" >> test-logs/app.log
echo "[WARN] High memory usage: 85%" >> test-logs/app.log

# Run LogWisp with debug logging
logwisp --config test.toml --log-level debug

# Check what passes through
curl -N http://localhost:8888/stream
```

### Debug Filter Behavior
Enable debug logging to see filter decisions:

```bash
logwisp --log-level debug --log-output stderr
```

Look for messages like:
```
Entry filtered out component=filter_chain filter_index=0 filter_type=include
Entry passed all filters component=filter_chain
```

## Common Pitfalls

### Case Sensitivity
By default, patterns are case-sensitive:
```toml
# Won't match "error" or "Error"
patterns = ["ERROR"]

# Use case-insensitive flag
patterns = ["(?i)error"]
```

### Partial Matches
Patterns match substrings by default:
```toml
# Matches "ERROR", "ERRORS", "TERROR"
patterns = ["ERROR"]

# Use word boundaries for exact words
patterns = ["\\bERROR\\b"]
```

### Special Characters
Remember to escape regex special characters:
```toml
# Won't work as expected
patterns = ["[ERROR]"]

# Correct: escape brackets
patterns = ["\\[ERROR\\]"]
```

### Performance Impact
Too many complex patterns can impact performance:
```toml
# Consider splitting into multiple streams instead
[[streams.filters]]
patterns = [
    # 50+ complex patterns...
]
```

## Best Practices

1. **Start Simple**: Begin with basic patterns and refine as needed
2. **Test Thoroughly**: Use test logs to verify filter behavior
3. **Monitor Performance**: Check filter statistics in `/status`
4. **Document Patterns**: Comment complex patterns for maintenance
5. **Use Multiple Streams**: Instead of complex filters, consider separate streams
6. **Regular Review**: Periodically review and optimize filter rules

## See Also

- [Configuration Guide](configuration.md) - Complete configuration reference
- [Performance Tuning](performance.md) - Optimization guidelines
- [Examples](examples/) - Real-world filter configurations