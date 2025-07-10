# Configuration Guide

LogWisp uses TOML format for configuration with sensible defaults for all settings.

## Configuration File Location

Default search order:
1. Command line: `--config /path/to/config.toml`
2. Environment: `$LOGWISP_CONFIG_FILE`
3. User config: `~/.config/logwisp.toml`
4. Current directory: `./logwisp.toml`

## Configuration Structure

```toml
# Optional: LogWisp's own logging configuration
[logging]
output = "stderr"  # file, stdout, stderr, both, none
level = "info"     # debug, info, warn, error

# Required: At least one stream
[[streams]]
name = "default"   # Unique identifier

[streams.monitor]  # Required: What to monitor
# ... monitor settings ...

[streams.httpserver]  # Optional: HTTP/SSE server
# ... HTTP settings ...

[streams.tcpserver]   # Optional: TCP server
# ... TCP settings ...

[[streams.filters]]   # Optional: Log filtering
# ... filter settings ...
```

## Logging Configuration

Controls LogWisp's operational logging (not the logs being monitored).

```toml
[logging]
output = "stderr"  # Where to write LogWisp's logs
level = "info"     # Minimum log level

# File output settings (when output includes "file")
[logging.file]
directory = "./logs"          # Log directory
name = "logwisp"             # Base filename
max_size_mb = 100            # Rotate at this size
max_total_size_mb = 1000     # Total size limit
retention_hours = 168        # Keep for 7 days

# Console output settings
[logging.console]
target = "stderr"  # stdout, stderr, split
format = "txt"     # txt or json
```

## Stream Configuration

Each `[[streams]]` section defines an independent log monitoring pipeline.

### Monitor Settings

What files or directories to watch:

```toml
[streams.monitor]
check_interval_ms = 100  # How often to check for new entries

# Monitor targets (at least one required)
targets = [
    # Watch all .log files in a directory
    { path = "/var/log/myapp", pattern = "*.log", is_file = false },
    
    # Watch a specific file
    { path = "/var/log/app.log", is_file = true },
    
    # Multiple patterns
    { path = "/logs", pattern = "app-*.log", is_file = false },
    { path = "/logs", pattern = "error-*.txt", is_file = false }
]
```

### HTTP Server (SSE)

Server-Sent Events streaming over HTTP:

```toml
[streams.httpserver]
enabled = true
port = 8080
buffer_size = 1000      # Per-client event buffer
stream_path = "/stream" # SSE endpoint
status_path = "/status" # Statistics endpoint

# Keep-alive heartbeat
[streams.httpserver.heartbeat]
enabled = true
interval_seconds = 30
format = "comment"        # "comment" or "json"
include_timestamp = true
include_stats = false

# Rate limiting (optional)
[streams.httpserver.rate_limit]
enabled = false
requests_per_second = 10.0
burst_size = 20
limit_by = "ip"           # "ip" or "global"
response_code = 429
response_message = "Rate limit exceeded"
max_connections_per_ip = 5
max_total_connections = 100
```

### TCP Server

Raw TCP streaming for high performance:

```toml
[streams.tcpserver]
enabled = true
port = 9090
buffer_size = 5000  # Larger buffer for TCP

# Heartbeat (always JSON format for TCP)
[streams.tcpserver.heartbeat]
enabled = true
interval_seconds = 60
include_timestamp = true
include_stats = false

# Rate limiting
[streams.tcpserver.rate_limit]
enabled = false
requests_per_second = 5.0
burst_size = 10
limit_by = "ip"
```

### Filters

Control which log entries are streamed:

```toml
# Include filter - only matching logs pass
[[streams.filters]]
type = "include"
logic = "or"      # "or" = match any, "and" = match all
patterns = [
    "ERROR",
    "WARN",
    "CRITICAL"
]

# Exclude filter - matching logs are dropped
[[streams.filters]]
type = "exclude"
patterns = [
    "DEBUG",
    "health check"
]
```

## Complete Examples

### Minimal Configuration

```toml
[[streams]]
name = "simple"
[streams.monitor]
targets = [{ path = "./logs", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080
```

### Production Web Application

```toml
[logging]
output = "file"
level = "info"
[logging.file]
directory = "/var/log/logwisp"
max_size_mb = 500
retention_hours = 336  # 14 days

[[streams]]
name = "webapp"

[streams.monitor]
check_interval_ms = 50
targets = [
    { path = "/var/log/nginx", pattern = "access.log*" },
    { path = "/var/log/nginx", pattern = "error.log*" },
    { path = "/var/log/myapp", pattern = "*.log" }
]

# Only errors and warnings
[[streams.filters]]
type = "include"
logic = "or"
patterns = [
    "\\b(ERROR|error|Error)\\b",
    "\\b(WARN|WARNING|warn|warning)\\b",
    "\\b(CRITICAL|FATAL|critical|fatal)\\b",
    "status=[4-5][0-9][0-9]"  # HTTP errors
]

# Exclude noise
[[streams.filters]]
type = "exclude"
patterns = [
    "/health",
    "/metrics",
    "ELB-HealthChecker"
]

[streams.httpserver]
enabled = true
port = 8080
buffer_size = 2000

[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 25.0
burst_size = 50
max_connections_per_ip = 10
```

### Multi-Service with Router

```toml
# Run with: logwisp --router

# Service 1: API
[[streams]]
name = "api"
[streams.monitor]
targets = [{ path = "/var/log/api", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080  # All streams can use same port in router mode

# Service 2: Database
[[streams]]
name = "database"
[streams.monitor]
targets = [{ path = "/var/log/postgresql", pattern = "*.log" }]
[[streams.filters]]
type = "include"
patterns = ["ERROR", "FATAL", "deadlock", "timeout"]
[streams.httpserver]
enabled = true
port = 8080

# Service 3: System
[[streams]]
name = "system"
[streams.monitor]
targets = [
    { path = "/var/log/syslog", is_file = true },
    { path = "/var/log/auth.log", is_file = true }
]
[streams.tcpserver]
enabled = true
port = 9090
```

### High-Security Configuration

```toml
[logging]
output = "file"
level = "warn"  # Less verbose

[[streams]]
name = "secure"

[streams.monitor]
targets = [{ path = "/var/log/secure", pattern = "*.log" }]

# Only security events
[[streams.filters]]
type = "include"
patterns = [
    "auth",
    "sudo",
    "ssh",
    "login",
    "failed",
    "denied"
]

[streams.httpserver]
enabled = true
port = 8443

# Strict rate limiting
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 2.0
burst_size = 3
limit_by = "ip"
max_connections_per_ip = 1
response_code = 403  # Forbidden instead of 429

# Future: Authentication
# [streams.auth]
# type = "basic"
# [streams.auth.basic_auth]
# users_file = "/etc/logwisp/users.htpasswd"
```

## Configuration Tips

### Performance Tuning

- **check_interval_ms**: Higher values reduce CPU usage
- **buffer_size**: Larger buffers handle bursts better
- **rate_limit**: Essential for public-facing streams

### Filter Patterns

- Use word boundaries: `\\berror\\b` (won't match "errorCode")
- Case-insensitive: `(?i)error`
- Anchors for speed: `^ERROR` faster than `ERROR`
- Test complex patterns before deployment

### Resource Limits

- Each stream uses ~10-50MB RAM (depending on buffers)
- CPU usage scales with check_interval and file activity
- Network bandwidth depends on log volume and client count

## Validation

LogWisp validates configuration on startup:
- Required fields (name, monitor targets)
- Port conflicts between streams
- Pattern syntax for filters
- Path accessibility

## See Also

- [Environment Variables](environment.md) - Override via environment
- [CLI Options](cli.md) - Override via command line
- [Filter Guide](filters.md) - Advanced filtering patterns
- [Examples](examples/) - Ready-to-use configurations