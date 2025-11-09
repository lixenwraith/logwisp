# Output Sinks

LogWisp sinks deliver processed log entries to various destinations.

## Sink Types

### Console Sink

Output to stdout/stderr.

```toml
[[pipelines.sinks]]
type = "console"

[pipelines.sinks.console]
target = "stdout"  # stdout|stderr|split
colorize = false
buffer_size = 100
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | "stdout" | Output target (stdout/stderr/split) |
| `colorize` | bool | false | Enable colored output |
| `buffer_size` | int | 100 | Internal buffer size |

**Target Modes:**
- **stdout**: All output to standard output
- **stderr**: All output to standard error
- **split**: INFO/DEBUG to stdout, WARN/ERROR to stderr

### File Sink

Write logs to rotating files.

```toml
[[pipelines.sinks]]
type = "file"

[pipelines.sinks.file]
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
[[pipelines.sinks]]
type = "http"

[pipelines.sinks.http]
host = "0.0.0.0"
port = 8080
stream_path = "/stream"
status_path = "/status"
buffer_size = 1000
max_connections = 100
read_timeout_ms = 10000
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
| `max_connections` | int | 100 | Maximum concurrent clients |
| `read_timeout_ms` | int | 10000 | Read timeout |
| `write_timeout_ms` | int | 10000 | Write timeout |

**Heartbeat Configuration:**

```toml
[pipelines.sinks.http.heartbeat]
enabled = true
interval_ms = 30000
include_timestamp = true
include_stats = false
format = "comment"  # comment|event|json
```

### TCP Sink

TCP streaming server for debugging.

```toml
[[pipelines.sinks]]
type = "tcp"

[pipelines.sinks.tcp]
host = "0.0.0.0"
port = 9090
buffer_size = 1000
max_connections = 100
keep_alive = true
keep_alive_period_ms = 30000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Bind address |
| `port` | int | Required | Listen port |
| `buffer_size` | int | 1000 | Internal buffer size |
| `max_connections` | int | 100 | Maximum concurrent clients |
| `keep_alive` | bool | true | Enable TCP keep-alive |
| `keep_alive_period_ms` | int | 30000 | Keep-alive interval |

**Note:** TCP Sink has no authentication support (debugging only).

### HTTP Client Sink

Forward logs to remote HTTP endpoints.

```toml
[[pipelines.sinks]]
type = "http_client"

[pipelines.sinks.http_client]
url = "https://logs.example.com/ingest"
buffer_size = 1000
batch_size = 100
batch_delay_ms = 1000
timeout_seconds = 30
max_retries = 3
retry_delay_ms = 1000
retry_backoff = 2.0
insecure_skip_verify = false
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | string | Required | Target URL |
| `buffer_size` | int | 1000 | Internal buffer size |
| `batch_size` | int | 100 | Logs per request |
| `batch_delay_ms` | int | 1000 | Max wait before sending |
| `timeout_seconds` | int | 30 | Request timeout |
| `max_retries` | int | 3 | Retry attempts |
| `retry_delay_ms` | int | 1000 | Initial retry delay |
| `retry_backoff` | float | 2.0 | Exponential backoff multiplier |
| `insecure_skip_verify` | bool | false | Skip TLS verification |

### TCP Client Sink

Forward logs to remote TCP servers.

```toml
[[pipelines.sinks]]
type = "tcp_client"

[pipelines.sinks.tcp_client]
host = "logs.example.com"
port = 9090
buffer_size = 1000
dial_timeout = 10
write_timeout = 30
read_timeout = 10
keep_alive = 30
reconnect_delay_ms = 1000
max_reconnect_delay_ms = 30000
reconnect_backoff = 1.5
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | Required | Target host |
| `port` | int | Required | Target port |
| `buffer_size` | int | 1000 | Internal buffer size |
| `dial_timeout` | int | 10 | Connection timeout (seconds) |
| `write_timeout` | int | 30 | Write timeout (seconds) |
| `read_timeout` | int | 10 | Read timeout (seconds) |
| `keep_alive` | int | 30 | TCP keep-alive (seconds) |
| `reconnect_delay_ms` | int | 1000 | Initial reconnect delay |
| `max_reconnect_delay_ms` | int | 30000 | Maximum reconnect delay |
| `reconnect_backoff` | float | 1.5 | Backoff multiplier |

## Network Sink Features

### Network Rate Limiting

Available for HTTP and TCP sinks:

```toml
[pipelines.sinks.http.net_limit]
enabled = true
max_connections_per_ip = 10
max_connections_total = 100
ip_whitelist = ["192.168.1.0/24"]
ip_blacklist = ["10.0.0.0/8"]
```

### TLS Configuration (HTTP Only)

```toml
[pipelines.sinks.http.tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
ca_file = "/path/to/ca.pem"
min_version = "TLS1.2"
client_auth = false
```

HTTP Client TLS:

```toml
[pipelines.sinks.http_client.tls]
enabled = true
server_ca_file = "/path/to/ca.pem"  # For server verification
server_name = "logs.example.com"
insecure_skip_verify = false
client_cert_file = "/path/to/client.pem"  # For mTLS
client_key_file = "/path/to/client.key"   # For mTLS
```

## Sink Chaining

Designed connection patterns:

### Log Aggregation
- **HTTP Client Sink → HTTP Source**: HTTP/HTTPS (optional mTLS for HTTPS)
- **TCP Client Sink → TCP Source**: Raw TCP

### Live Monitoring
- **HTTP Sink**: Browser-based SSE streaming
- **TCP Sink**: Debug interface (telnet/netcat)

## Sink Statistics

All sinks track:
- Total entries processed
- Active connections
- Failed sends
- Retry attempts
- Last processed timestamp