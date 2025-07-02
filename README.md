<p align="center">
  <img src="assets/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
</p>

# LogWisp - Dual-Stack Log Streaming

A high-performance log streaming service with dual-stack architecture: raw TCP streaming via gnet and HTTP/SSE streaming via fasthttp.

## Features

- **Dual streaming modes**: TCP (gnet) and HTTP/SSE (fasthttp)
- **Fan-out architecture**: Multiple independent consumers
- **Real-time updates**: File monitoring with rotation detection
- **Zero dependencies**: Only gnet and fasthttp beyond stdlib
- **High performance**: Non-blocking I/O throughout

## Quick Start

```bash
# Build
go build -o logwisp ./src/cmd/logwisp

# Run with HTTP only (default)
./logwisp

# Enable both TCP and HTTP
./logwisp --enable-tcp --tcp-port 9090

# Monitor specific paths
./logwisp /var/log:*.log /app/logs:error*.log
```

## Architecture

```
Monitor (Publisher) → [Subscriber Channels] → TCP Server (default port 9090)
                                           ↘ HTTP Server (default port 8080)
```

## Command Line Options

```bash
logwisp [OPTIONS] [TARGET...]

OPTIONS:
  --config FILE             Config file path
  --check-interval MS       File check interval (default: 100)
  
  # TCP Server
  --enable-tcp              Enable TCP server
  --tcp-port PORT          TCP port (default: 9090)
  --tcp-buffer-size SIZE   TCP buffer size (default: 1000)
  
  # HTTP Server  
  --enable-http            Enable HTTP server (default: true)
  --http-port PORT         HTTP port (default: 8080)
  --http-buffer-size SIZE  HTTP buffer size (default: 1000)

TARGET:
  path[:pattern[:isfile]]  Path to monitor
                          pattern: glob pattern for directories
                          isfile: true/false (auto-detected if omitted)
```

## Configuration

Config file location: `~/.config/logwisp.toml`

```toml
[monitor]
check_interval_ms = 100

[[monitor.targets]]
path = "./"
pattern = "*.log"
is_file = false

[tcpserver]
enabled = false
port = 9090
buffer_size = 1000

[httpserver]
enabled = true
port = 8080
buffer_size = 1000
```

## Clients

### TCP Stream
```bash
# Simple TCP client
nc localhost 9090

# Using telnet
telnet localhost 9090

# Using socat
socat - TCP:localhost:9090
```

### HTTP/SSE Stream
```bash
# Stream logs
curl -N http://localhost:8080/stream

# Check status
curl http://localhost:8080/status
```

## Environment Variables

All config values can be set via environment:
- `LOGWISP_MONITOR_CHECK_INTERVAL_MS`
- `LOGWISP_MONITOR_TARGETS` (format: "path:pattern:isfile,...")
- `LOGWISP_TCPSERVER_ENABLED`
- `LOGWISP_TCPSERVER_PORT`
- `LOGWISP_HTTPSERVER_ENABLED`
- `LOGWISP_HTTPSERVER_PORT`

## Log Entry Format

```json
{
  "time": "2024-01-01T12:00:00.123456Z",
  "source": "app.log",
  "level": "error",
  "message": "Something went wrong",
  "fields": {"key": "value"}
}
```

## API Endpoints

### TCP Protocol
- Raw JSON lines, one entry per line
- No headers or authentication
- Instant connection, streaming starts immediately

### HTTP Endpoints
- `GET /stream` - SSE stream of log entries
- `GET /status` - Service status JSON

### SSE Events
- `connected` - Initial connection with client_id
- `data` - Log entry JSON
- `:` - Heartbeat comment (30s interval)

## Heartbeat Configuration

LogWisp supports configurable heartbeat messages for both HTTP/SSE and TCP streams to detect stale connections and provide server statistics.

**HTTP/SSE Heartbeat:**
- **Format Options:**
    - `comment`: SSE comment format (`: heartbeat ...`)
    - `json`: Standard data message with JSON payload
- **Content Options:**
    - `include_timestamp`: Add current UTC timestamp
    - `include_stats`: Add active clients count and server uptime

**TCP Heartbeat:**
- Always uses JSON format
- Same content options as HTTP
- Useful for detecting disconnected clients

**⚠️ SECURITY:** Heartbeat statistics expose minimal server state (connection count, uptime). If this is sensitive in your environment, disable `include_stats`.

**Example Heartbeat Messages:**

HTTP Comment format:
```
: heartbeat 2024-01-01T12:00:00Z clients=5 uptime=3600s
```

JSON format:
```json
{"type":"heartbeat","timestamp":"2024-01-01T12:00:00Z","active_clients":5,"uptime_seconds":3600}
```

**Configuration:**
```toml
[httpserver.heartbeat]
enabled = true
interval_seconds = 30
include_timestamp = true
include_stats = true
format = "json"
```

**Environment Variables:**
- `LOGWISP_HTTPSERVER_HEARTBEAT_ENABLED`
- `LOGWISP_HTTPSERVER_HEARTBEAT_INTERVAL_SECONDS`
- `LOGWISP_TCPSERVER_HEARTBEAT_ENABLED`
- `LOGWISP_TCPSERVER_HEARTBEAT_INTERVAL_SECONDS`

## Deployment

### Systemd Service
```ini
[Unit]
Description=LogWisp Log Streaming
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/logwisp --enable-tcp --enable-http
Restart=always
Environment="LOGWISP_TCPSERVER_PORT=9090"
Environment="LOGWISP_HTTPSERVER_PORT=8080"

[Install]
WantedBy=multi-user.target
```

### Docker
```dockerfile
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go build -o logwisp ./src/cmd/logwisp

FROM debian:bookworm-slim
COPY --from=builder /app/logwisp /usr/local/bin/
EXPOSE 8080 9090
CMD ["logwisp", "--enable-tcp", "--enable-http"]
```

## Performance Tuning

- **Buffer Size**: Increase for burst traffic (5000+)
- **Check Interval**: Decrease for lower latency (10-50ms)
- **TCP**: Best for high-volume system consumers
- **HTTP**: Best for web browsers and REST clients

### Message Dropping and Client Behavior

LogWisp uses non-blocking message delivery to maintain system stability. When a client cannot keep up with the log stream, messages are dropped rather than blocking other clients or the monitor.

**Common causes of dropped messages:**
- **Browser throttling**: Browsers may throttle background tabs, reducing JavaScript execution frequency
- **Network congestion**: Slow connections or high latency can cause client buffers to fill
- **Client processing**: Heavy client-side processing (parsing, rendering) can create backpressure
- **System resources**: CPU/memory constraints on client machines affect consumption rate

**TCP vs HTTP behavior:**
- **TCP**: Raw stream with kernel-level buffering. Drops occur when TCP send buffer fills
- **HTTP/SSE**: Application-level buffering. Each client has a dedicated channel (default: 1000 entries)

**Mitigation strategies:**
1. Increase buffer sizes for burst tolerance: `--tcp-buffer-size 5000` or `--http-buffer-size 5000`
2. Implement client-side flow control (pause/resume based on queue depth)
3. Use TCP for high-volume consumers that need guaranteed delivery
4. Keep browser tabs in foreground for real-time monitoring
5. Consider log aggregation/filtering at source for high-volume scenarios

**Monitoring drops:**
- HTTP: Check `/status` endpoint for drop statistics
- TCP: Monitor connection count and system TCP metrics
- Both: Watch for "channel full" indicators in client implementations

## Building from Source

```bash
git clone https://github.com/yourusername/logwisp
cd logwisp
go mod init logwisp
go get github.com/panjf2000/gnet/v2
go get github.com/valyala/fasthttp
go get github.com/lixenwraith/config
go build -o logwisp ./src/cmd/logwisp
```

## License

BSD-3-Clause