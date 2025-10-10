# Input Sources

LogWisp sources monitor various inputs and generate log entries for pipeline processing.

## Source Types

### Directory Source

Monitors a directory for log files matching a pattern.

```toml
[[pipelines.sources]]
type = "directory"

[pipelines.sources.directory]
path = "/var/log/myapp"
pattern = "*.log"          # Glob pattern
check_interval_ms = 100    # Poll interval
recursive = false           # Scan subdirectories
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `path` | string | Required | Directory to monitor |
| `pattern` | string | "*" | File pattern (glob) |
| `check_interval_ms` | int | 100 | File check interval in milliseconds |
| `recursive` | bool | false | Include subdirectories |

**Features:**
- Automatic file rotation detection
- Position tracking (resume after restart)
- Concurrent file monitoring
- Pattern-based file selection

### Stdin Source

Reads log entries from standard input.

```toml
[[pipelines.sources]]
type = "stdin"

[pipelines.sources.stdin]
buffer_size = 1000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `buffer_size` | int | 1000 | Internal buffer size |

**Features:**
- Line-based processing
- Automatic level detection
- Non-blocking reads

### HTTP Source

REST endpoint for log ingestion.

```toml
[[pipelines.sources]]
type = "http"

[pipelines.sources.http]
host = "0.0.0.0"
port = 8081
ingest_path = "/ingest"
buffer_size = 1000
max_body_size = 1048576  # 1MB
read_timeout_ms = 10000
write_timeout_ms = 10000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Bind address |
| `port` | int | Required | Listen port |
| `ingest_path` | string | "/ingest" | Ingestion endpoint path |
| `buffer_size` | int | 1000 | Internal buffer size |
| `max_body_size` | int | 1048576 | Maximum request body size |
| `read_timeout_ms` | int | 10000 | Read timeout |
| `write_timeout_ms` | int | 10000 | Write timeout |

**Input Formats:**
- Single JSON object
- JSON array
- Newline-delimited JSON (NDJSON)
- Plain text (one entry per line)

### TCP Source

Raw TCP socket listener for log ingestion.

```toml
[[pipelines.sources]]
type = "tcp"

[pipelines.sources.tcp]
host = "0.0.0.0"
port = 9091
buffer_size = 1000
read_timeout_ms = 10000
keep_alive = true
keep_alive_period_ms = 30000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Bind address |
| `port` | int | Required | Listen port |
| `buffer_size` | int | 1000 | Internal buffer size |
| `read_timeout_ms` | int | 10000 | Read timeout |
| `keep_alive` | bool | true | Enable TCP keep-alive |
| `keep_alive_period_ms` | int | 30000 | Keep-alive interval |

**Protocol:**
- Newline-delimited JSON
- One log entry per line
- UTF-8 encoding

## Network Source Features

### Network Rate Limiting

Available for HTTP and TCP sources:

```toml
[pipelines.sources.http.net_limit]
enabled = true
max_connections_per_ip = 10
max_connections_total = 100
requests_per_second = 100.0
burst_size = 200
response_code = 429
response_message = "Rate limit exceeded"
ip_whitelist = ["192.168.1.0/24"]
ip_blacklist = ["10.0.0.0/8"]
```

### TLS Configuration (HTTP Only)

```toml
[pipelines.sources.http.tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
ca_file = "/path/to/ca.pem"
min_version = "TLS1.2"
client_auth = true
client_ca_file = "/path/to/client-ca.pem"
verify_client_cert = true
```

### Authentication

HTTP Source authentication options:

```toml
[pipelines.sources.http.auth]
type = "basic"  # none|basic|token|mtls
realm = "LogWisp"

# Basic auth
[[pipelines.sources.http.auth.basic.users]]
username = "admin"
password_hash = "$argon2..."

# Token auth
[pipelines.sources.http.auth.token]
tokens = ["token1", "token2"]
```

TCP Source authentication:

```toml
[pipelines.sources.tcp.auth]
type = "scram"  # none|scram

# SCRAM users
[[pipelines.sources.tcp.auth.scram.users]]
username = "user1"
stored_key = "base64..."
server_key = "base64..."
salt = "base64..."
argon_time = 3
argon_memory = 65536
argon_threads = 4
```

## Source Statistics

All sources track:
- Total entries received
- Dropped entries (buffer full)
- Invalid entries
- Last entry timestamp
- Active connections (network sources)
- Source-specific metrics

## Buffer Management

Each source maintains internal buffers:
- Default size: 1000 entries
- Drop policy when full
- Configurable per source
- Non-blocking writes