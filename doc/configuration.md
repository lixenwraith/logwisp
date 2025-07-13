# Configuration Guide

LogWisp uses TOML format with a flexible **source → filter → sink** pipeline architecture.

## Configuration Methods

LogWisp supports three configuration methods with the following precedence:

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration file** (lowest priority)

### Complete Configuration Reference

| Category | CLI Flag | Environment Variable | TOML File |
|----------|----------|---------------------|-----------|
| **Top-level** |
| Router mode | `--router` | `LOGWISP_ROUTER` | `router = true` |
| Background mode | `--background` | `LOGWISP_BACKGROUND` | `background = true` |
| Show version | `--version` | `LOGWISP_VERSION` | `version = true` |
| Quiet mode | `--quiet` | `LOGWISP_QUIET` | `quiet = true` |
| Disable status reporter | `--disable-status-reporter` | `LOGWISP_DISABLE_STATUS_REPORTER` | `disable_status_reporter = true` |
| Config file | `--config <path>` | `LOGWISP_CONFIG_FILE` | N/A |
| Config directory | N/A | `LOGWISP_CONFIG_DIR` | N/A |
| **Logging** |
| Output mode | `--logging.output <mode>` | `LOGWISP_LOGGING_OUTPUT` | `[logging]`<br>`output = "stderr"` |
| Log level | `--logging.level <level>` | `LOGWISP_LOGGING_LEVEL` | `[logging]`<br>`level = "info"` |
| File directory | `--logging.file.directory <path>` | `LOGWISP_LOGGING_FILE_DIRECTORY` | `[logging.file]`<br>`directory = "./logs"` |
| File name | `--logging.file.name <name>` | `LOGWISP_LOGGING_FILE_NAME` | `[logging.file]`<br>`name = "logwisp"` |
| Max file size | `--logging.file.max_size_mb <size>` | `LOGWISP_LOGGING_FILE_MAX_SIZE_MB` | `[logging.file]`<br>`max_size_mb = 100` |
| Max total size | `--logging.file.max_total_size_mb <size>` | `LOGWISP_LOGGING_FILE_MAX_TOTAL_SIZE_MB` | `[logging.file]`<br>`max_total_size_mb = 1000` |
| Retention hours | `--logging.file.retention_hours <hours>` | `LOGWISP_LOGGING_FILE_RETENTION_HOURS` | `[logging.file]`<br>`retention_hours = 168` |
| Console target | `--logging.console.target <target>` | `LOGWISP_LOGGING_CONSOLE_TARGET` | `[logging.console]`<br>`target = "stderr"` |
| Console format | `--logging.console.format <format>` | `LOGWISP_LOGGING_CONSOLE_FORMAT` | `[logging.console]`<br>`format = "txt"` |
| **Pipelines** |
| Pipeline name | `--pipelines.N.name <name>` | `LOGWISP_PIPELINES_N_NAME` | `[[pipelines]]`<br>`name = "default"` |
| Source type | `--pipelines.N.sources.N.type <type>` | `LOGWISP_PIPELINES_N_SOURCES_N_TYPE` | `[[pipelines.sources]]`<br>`type = "directory"` |
| Source options | `--pipelines.N.sources.N.options.<key> <value>` | `LOGWISP_PIPELINES_N_SOURCES_N_OPTIONS_<KEY>` | `[[pipelines.sources]]`<br>`options = { ... }` |
| Filter type | `--pipelines.N.filters.N.type <type>` | `LOGWISP_PIPELINES_N_FILTERS_N_TYPE` | `[[pipelines.filters]]`<br>`type = "include"` |
| Filter logic | `--pipelines.N.filters.N.logic <logic>` | `LOGWISP_PIPELINES_N_FILTERS_N_LOGIC` | `[[pipelines.filters]]`<br>`logic = "or"` |
| Filter patterns | `--pipelines.N.filters.N.patterns <json>` | `LOGWISP_PIPELINES_N_FILTERS_N_PATTERNS` | `[[pipelines.filters]]`<br>`patterns = [...]` |
| Sink type | `--pipelines.N.sinks.N.type <type>` | `LOGWISP_PIPELINES_N_SINKS_N_TYPE` | `[[pipelines.sinks]]`<br>`type = "http"` |
| Sink options | `--pipelines.N.sinks.N.options.<key> <value>` | `LOGWISP_PIPELINES_N_SINKS_N_OPTIONS_<KEY>` | `[[pipelines.sinks]]`<br>`options = { ... }` |
| Auth type | `--pipelines.N.auth.type <type>` | `LOGWISP_PIPELINES_N_AUTH_TYPE` | `[pipelines.auth]`<br>`type = "none"` |

Note: `N` represents array indices (0-based).

## Configuration File Location

1. Command line: `--config /path/to/config.toml`
2. Environment: `$LOGWISP_CONFIG_FILE` and `$LOGWISP_CONFIG_DIR`
3. User config: `~/.config/logwisp/logwisp.toml`
4. Current directory: `./logwisp.toml`

## Configuration Structure

```toml
# Optional: Enable router mode
router = false

# Optional: Background mode
background = false

# Optional: Quiet mode
quiet = false

# Optional: Disable status reporter
disable_status_reporter = false

# Optional: LogWisp's own logging
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

#### HTTP Source
```toml
[[pipelines.sources]]
type = "http"
options = {
    port = 8081,                  # Port to listen on
    ingest_path = "/ingest",      # Path for POST requests
    buffer_size = 1000,           # Input buffer size
    rate_limit = {                # Optional rate limiting
        enabled = true,
        requests_per_second = 10.0,
        burst_size = 20,
        limit_by = "ip"
    }
}
```

#### TCP Source
```toml
[[pipelines.sources]]
type = "tcp"
options = {
    port = 9091,                  # Port to listen on
    buffer_size = 1000,           # Input buffer size
    rate_limit = {                # Optional rate limiting
        enabled = true,
        requests_per_second = 5.0,
        burst_size = 10,
        limit_by = "ip"
    }
}
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
        include_timestamp = true,
        include_stats = false
    },
    
    # Rate limiting
    rate_limit = {
        enabled = true,
        requests_per_second = 10.0,
        burst_size = 20,
        limit_by = "ip",  # ip or global
        max_connections_per_ip = 5,
        max_total_connections = 100,
        response_code = 429,
        response_message = "Rate limit exceeded"
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
    heartbeat = { enabled = true, interval_seconds = 60, format = "json" },
    rate_limit = { enabled = true, requests_per_second = 5.0, burst_size = 10 }
}
```

#### HTTP Client Sink
```toml
[[pipelines.sinks]]
type = "http_client"
options = {
    url = "https://remote-log-server.com/ingest",
    buffer_size = 1000,
    batch_size = 100,
    batch_delay_ms = 1000,
    timeout_seconds = 30,
    max_retries = 3,
    retry_delay_ms = 1000,
    retry_backoff = 2.0,
    headers = {
        "Authorization" = "Bearer <API_KEY_HERE>",
        "X-Custom-Header" = "value"
    },
    insecure_skip_verify = false
}
```

#### TCP Client Sink
```toml
[[pipelines.sinks]]
type = "tcp_client"
options = {
    address = "remote-server.com:9090",
    buffer_size = 1000,
    dial_timeout_seconds = 10,
    write_timeout_seconds = 30,
    keep_alive_seconds = 30,
    reconnect_delay_ms = 1000,
    max_reconnect_delay_seconds = 30,
    reconnect_backoff = 1.5
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
    max_total_size_mb = 1000,
    retention_hours = 168.0,
    min_disk_free_mb = 1000,
    buffer_size = 2000
}
```

#### Console Sinks
```toml
[[pipelines.sinks]]
type = "stdout"  # or "stderr"
options = { 
    buffer_size = 500,
    target = "stdout"  # stdout, stderr, or split
}
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

### Filtering

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

[[pipelines.sources]]
type = "http"
options = { port = 8081, ingest_path = "/logs" }

[[pipelines.sinks]]
type = "tcp"
options = { port = 9090 }
```

### Router Mode

```toml
# Run with: logwisp --router
router = true

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

### Remote Log Forwarding

```toml
[[pipelines]]
name = "forwarder"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log" }

[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "WARN"]

[[pipelines.sinks]]
type = "http_client"
options = {
    url = "https://log-aggregator.example.com/ingest",
    batch_size = 100,
    batch_delay_ms = 5000,
    headers = { "Authorization" = "Bearer <API_KEY_HERE>" }
}

[[pipelines.sinks]]
type = "tcp_client"
options = {
    address = "backup-logger.example.com:9090",
    reconnect_delay_ms = 5000
}
```