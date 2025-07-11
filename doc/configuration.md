# Configuration Guide

LogWisp uses TOML format with a flexible **source → filter → sink** pipeline architecture.

## Configuration File Location

1. Command line: `--config /path/to/config.toml`
2. Environment: `$LOGWISP_CONFIG_FILE`
3. User config: `~/.config/logwisp.toml`
4. Current directory: `./logwisp.toml`

## Configuration Structure

```toml
# Optional: LogWisp's own logging
[logging]
output = "stderr"
level = "info"

# Required: At least one pipeline
[[pipelines]]
name = "default"

# Sources (required)
[[pipelines.sources]]
type = "directory"
options = { ... }

# Filters (optional)
[[pipelines.filters]]
type = "include"
patterns = [...]

# Sinks (required)
[[pipelines.sinks]]
type = "http"
options = { ... }
```

## Logging Configuration

Controls LogWisp's operational logging:

```toml
[logging]
output = "stderr"  # file, stdout, stderr, both, none
level = "info"     # debug, info, warn, error

[logging.file]
directory = "./logs"
name = "logwisp"
max_size_mb = 100
max_total_size_mb = 1000
retention_hours = 168

[logging.console]
target = "stderr"  # stdout, stderr, split
format = "txt"     # txt or json
```

## Pipeline Configuration

Each `[[pipelines]]` section defines an independent processing pipeline.

### Sources

Input data sources:

#### Directory Source
```toml
[[pipelines.sources]]
type = "directory"
options = {
    path = "/var/log/myapp",      # Directory to monitor
    pattern = "*.log",            # File pattern (glob)
    check_interval_ms = 100       # Check interval (10-60000)
}
```

#### File Source
```toml
[[pipelines.sources]]
type = "file"
options = {
    path = "/var/log/app.log"     # Specific file
}
```

#### Stdin Source
```toml
[[pipelines.sources]]
type = "stdin"
options = {}
```

### Filters

Control which log entries pass through:

```toml
# Include filter - only matching logs pass
[[pipelines.filters]]
type = "include"
logic = "or"      # or: match any, and: match all
patterns = [
    "ERROR",
    "(?i)warn",   # Case-insensitive
    "\\bfatal\\b" # Word boundary
]

# Exclude filter - matching logs are dropped
[[pipelines.filters]]
type = "exclude"
patterns = ["DEBUG", "health-check"]
```

### Sinks

Output destinations:

#### HTTP Sink (SSE)
```toml
[[pipelines.sinks]]
type = "http"
options = {
    port = 8080,
    buffer_size = 1000,
    stream_path = "/stream",
    status_path = "/status",
    
    # Heartbeat
    heartbeat = {
        enabled = true,
        interval_seconds = 30,
        format = "comment",  # comment or json
        include_timestamp = true
    },
    
    # Rate limiting
    rate_limit = {
        enabled = true,
        requests_per_second = 10.0,
        burst_size = 20,
        limit_by = "ip",  # ip or global
        max_connections_per_ip = 5
    }
}
```

#### TCP Sink
```toml
[[pipelines.sinks]]
type = "tcp"
options = {
    port = 9090,
    buffer_size = 5000,
    heartbeat = { enabled = true, interval_seconds = 60 },
    rate_limit = { enabled = true, requests_per_second = 5.0 }
}
```

#### File Sink
```toml
[[pipelines.sinks]]
type = "file"
options = {
    directory = "/var/log/logwisp",
    name = "app",
    max_size_mb = 100,
    retention_hours = 168.0,
    buffer_size = 2000
}
```

#### Console Sinks
```toml
[[pipelines.sinks]]
type = "stdout"  # or "stderr"
options = { buffer_size = 500 }
```

## Complete Examples

### Basic Application Monitoring

```toml
[[pipelines]]
name = "app"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log" }

[[pipelines.sinks]]
type = "http"
options = { port = 8080 }
```

### Production with Filtering

```toml
[logging]
output = "file"
level = "info"

[[pipelines]]
name = "production"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log", check_interval_ms = 50 }

[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "WARN", "CRITICAL"]

[[pipelines.filters]]
type = "exclude"
patterns = ["/health", "/metrics"]

[[pipelines.sinks]]
type = "http"
options = {
    port = 8080,
    rate_limit = { enabled = true, requests_per_second = 25.0 }
}

[[pipelines.sinks]]
type = "file"
options = { directory = "/var/log/archive", name = "errors" }
```

### Multi-Source Aggregation

```toml
[[pipelines]]
name = "aggregated"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/nginx", pattern = "*.log" }

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log" }

[[pipelines.sources]]
type = "stdin"
options = {}

[[pipelines.sinks]]
type = "tcp"
options = { port = 9090 }
```

### Router Mode

```toml
# Run with: logwisp --router

[[pipelines]]
name = "api"
[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/api", pattern = "*.log" }
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }  # Same port OK in router mode

[[pipelines]]
name = "web"
[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/nginx", pattern = "*.log" }
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }  # Shared port

# Access:
# http://localhost:8080/api/stream
# http://localhost:8080/web/stream
# http://localhost:8080/status
```

## Validation

LogWisp validates on startup:
- Required fields (name, sources, sinks)
- Port conflicts between pipelines
- Pattern syntax
- Path accessibility
- Rate limit values