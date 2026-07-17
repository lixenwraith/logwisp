# Output Sinks

LogWisp sinks deliver processed log entries to various destinations.

## Sink Types

### Console Sink

Output to stdout/stderr.

```toml
[[pipelines.plugin_sinks]]
id = "console_out"
type = "console"
[pipelines.plugin_sinks.config]
target = "stdout"  # stdout|stderr|split
buffer_size = 1000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | "stdout" | Output target (stdout/stderr/split) |
| `buffer_size` | int | 1000 | Internal buffer size |

**Target Modes:**
- **stdout**: All output to standard output
- **stderr**: All output to standard error
- **split**: INFO/DEBUG to stdout, WARN/ERROR to stderr

### File Sink

Write logs to rotating files.

```toml
[[pipelines.plugin_sinks]]
id = "file_out"
type = "file"
[pipelines.plugin_sinks.config]
directory = "./logs"
name = "output"
max_size_mb = 100
max_total_size_mb = 1000
min_disk_free_mb = 500
retention_hours = 168.0
buffer_size = 1000
flush_interval_ms = 1000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `directory` | string | Required | Output directory |
| `name` | string | Required | Base filename |
| `max_size_mb` | int | 100 | Rotation threshold |
| `max_total_size_mb` | int | 1000 | Total size limit |
| `min_disk_free_mb` | int | 500 | Minimum free disk space |
| `retention_hours` | float | 168 | Delete files older than |
| `buffer_size` | int | 1000 | Internal buffer size |
| `flush_interval_ms` | int | 1000 | Force flush interval |

**Features:**
- Automatic rotation on size
- Retention management
- Disk space monitoring
- Periodic flushing

### HTTP Sink

SSE (Server-Sent Events) streaming server.

```toml
[[pipelines.plugin_sinks]]
id = "http_out"
type = "http"
[pipelines.plugin_sinks.config]
host = "0.0.0.0"
port = 8080
stream_path = "/stream"
status_path = "/status"
buffer_size = 1000
write_timeout_ms = 10000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Bind address |
| `port` | int | Required | Listen port |
| `stream_path` | string | "/stream" | SSE stream endpoint |
| `status_path` | string | "/status" | Status endpoint |
| `buffer_size` | int | 1000 | Internal buffer size |
| `write_timeout_ms` | int | 10000 | Write timeout |

### TCP Sink

TCP streaming server for debugging.

```toml
[[pipelines.plugin_sinks]]
id = "tcp_out"
type = "tcp"
[pipelines.plugin_sinks.config]
host = "0.0.0.0"
port = 9090
buffer_size = 1000
keep_alive = true
keep_alive_period_ms = 30000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Bind address |
| `port` | int | Required | Listen port |
| `buffer_size` | int | 1000 | Internal buffer size |
| `keep_alive` | bool | true | Enable TCP keep-alive |
| `keep_alive_period_ms` | int | 30000 | Keep-alive interval |
| `write_timeout_ms` | int | 10000 | Write timeout |

### Null Sink

```toml
[[pipelines.plugin_sinks]]
id = "null_out"
type = "null"
```

## Buffer Management

- Full input buffer: entry dropped for that sink only (counted per pipeline as `total_dropped_by_sink`)"

## Sink Statistics

All sinks track:
- Total entries processed
- Active connections
- Failed sends
- Retry attempts
- Last processed timestamp
