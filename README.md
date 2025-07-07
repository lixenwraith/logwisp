# LogWisp - Multi-Stream Log Monitoring Service

<p align="center">
  <img src="assets/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
</p>

A high-performance log streaming service with multi-stream architecture, supporting both TCP and HTTP/SSE protocols with real-time file monitoring and rotation detection.

## Features

- **Multi-Stream Architecture**: Run multiple independent log streams, each with its own configuration
- **Dual Protocol Support**: TCP (raw streaming) and HTTP/SSE (browser-friendly)
- **Real-time Monitoring**: Instant updates with configurable check intervals
- **File Rotation Detection**: Automatic detection and handling of log rotation
- **Path-based Routing**: Optional HTTP router for consolidated access
- **Per-Stream Configuration**: Independent settings for each log stream
- **Connection Statistics**: Real-time monitoring of active connections
- **Flexible Targets**: Monitor individual files or entire directories
- **Zero Dependencies**: Only gnet and fasthttp beyond stdlib

## Quick Start

```bash
# Build
go build -o logwisp ./src/cmd/logwisp

# Run with default configuration
./logwisp

# Run with custom config
./logwisp --config /etc/logwisp/production.toml

# Run with HTTP router (path-based routing)
./logwisp --router
```

## Architecture

LogWisp uses a service-oriented architecture where each stream is an independent pipeline:

```
LogStream Service
├── Stream["app-logs"]
│   ├── Monitor (watches files)
│   ├── TCP Server (optional)
│   └── HTTP Server (optional)
├── Stream["system-logs"]
│   ├── Monitor
│   └── HTTP Server
└── HTTP Router (optional, for path-based routing)
```

## Configuration

Configuration file location: `~/.config/logwisp.toml`

### Basic Multi-Stream Configuration

```toml
# Global defaults
[monitor]
check_interval_ms = 100

# Application logs stream
[[streams]]
name = "app"

[streams.monitor]
targets = [
    { path = "/var/log/myapp", pattern = "*.log", is_file = false },
    { path = "/var/log/myapp/app.log", is_file = true }
]

[streams.httpserver]
enabled = true
port = 8080
buffer_size = 2000
stream_path = "/stream"
status_path = "/status"

# System logs stream
[[streams]]
name = "system"

[streams.monitor]
check_interval_ms = 50  # Override global default
targets = [
    { path = "/var/log/syslog", is_file = true },
    { path = "/var/log/auth.log", is_file = true }
]

[streams.tcpserver]
enabled = true
port = 9090
buffer_size = 5000

[streams.httpserver]
enabled = true
port = 8443
stream_path = "/logs"
status_path = "/health"
```

### Target Configuration

Monitor targets support both files and directories:

```toml
# Directory monitoring with pattern
{ path = "/var/log", pattern = "*.log", is_file = false }

# Specific file monitoring
{ path = "/var/log/app.log", is_file = true }

# All .log files in a directory
{ path = "./logs", pattern = "*.log", is_file = false }
```

## Usage Modes

### 1. Standalone Mode (Default)

Each stream runs on its configured ports:

```bash
./logwisp
# Stream endpoints:
# - app: http://localhost:8080/stream
# - system: tcp://localhost:9090 and https://localhost:8443/logs
```

### 2. Router Mode

All HTTP streams share ports with path-based routing:

```bash
./logwisp --router
# Routed endpoints:
# - app: http://localhost:8080/app/stream
# - system: http://localhost:8080/system/logs
# - global: http://localhost:8080/status
```

## Client Examples

### HTTP/SSE Stream

```bash
# Connect to a stream
curl -N http://localhost:8080/stream

# Check stream status
curl http://localhost:8080/status

# With authentication (when implemented)
curl -u admin:password -N https://localhost:8443/logs
```

### TCP Stream

```bash
# Using netcat
nc localhost 9090

# Using telnet
telnet localhost 9090

# With TLS (when implemented)
openssl s_client -connect localhost:9443
```

### JavaScript Client

```javascript
const eventSource = new EventSource('http://localhost:8080/stream');

eventSource.addEventListener('connected', (e) => {
    const data = JSON.parse(e.data);
    console.log('Connected with ID:', data.client_id);
});

eventSource.addEventListener('message', (e) => {
    const logEntry = JSON.parse(e.data);
    console.log(`[${logEntry.time}] ${logEntry.level}: ${logEntry.message}`);
});
```

## Log Entry Format

All log entries are streamed as JSON:

```json
{
  "time": "2024-01-01T12:00:00.123456Z",
  "source": "app.log",
  "level": "ERROR",
  "message": "Connection timeout",
  "fields": {
    "user_id": "12345",
    "request_id": "abc-def-ghi"
  }
}
```

## API Endpoints

### Stream Endpoints (per stream)

- `GET {stream_path}` - SSE log stream
- `GET {status_path}` - Stream statistics and configuration

### Global Endpoints (router mode)

- `GET /status` - Aggregated status for all streams
- `GET /{stream_name}/{path}` - Stream-specific endpoints

### Status Response

```json
{
  "service": "LogWisp",
  "version": "3.0.0",
  "server": {
    "type": "http",
    "port": 8080,
    "active_clients": 5,
    "uptime_seconds": 3600
  },
  "monitor": {
    "active_watchers": 3,
    "total_entries": 15420,
    "dropped_entries": 0
  }
}
```

## Real-time Statistics

LogWisp provides comprehensive statistics at multiple levels:

- **Per-Stream Stats**: Monitor performance, connection counts, data throughput
- **Per-Watcher Stats**: File size, position, entries read, rotation count
- **Global Stats**: Aggregated view of all streams (in router mode)

Access statistics via status endpoints or watch the console output:

```
[15:04:05] Active streams: 2
  app: watchers=3 entries=1542 tcp_conns=2 http_conns=5
  system: watchers=2 entries=8901 tcp_conns=0 http_conns=3
```

## Advanced Features

### File Rotation Detection

LogWisp automatically detects log rotation through multiple methods:
- Inode change detection
- File size decrease
- Modification time anomalies
- Position beyond file size

When rotation is detected, a special log entry is generated:
```json
{
  "level": "INFO",
  "message": "Log rotation detected (#1): inode change"
}
```

### Buffer Management

- **Non-blocking delivery**: Messages are dropped rather than blocking when buffers fill
- **Per-client buffers**: Each client has independent buffer space
- **Configurable sizes**: Adjust buffer sizes based on expected load

### Heartbeat Messages

Keep connections alive and detect stale clients:

```toml
[streams.httpserver.heartbeat]
enabled = true
interval_seconds = 30
include_timestamp = true
include_stats = true
format = "json"  # or "comment" for SSE comments
```

## Performance Tuning

### Monitor Settings
- `check_interval_ms`: Lower values = faster detection, higher CPU usage
- `buffer_size`: Larger buffers handle bursts better but use more memory

### File Watcher Optimization
- Use specific file paths when possible (more efficient than directory scanning)
- Adjust patterns to minimize unnecessary file checks
- Consider separate streams for different update frequencies

### Network Optimization
- TCP: Best for high-volume, low-latency requirements
- HTTP/SSE: Best for browser compatibility and firewall traversal
- Router mode: Reduces port usage but adds slight routing overhead

## Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/logwisp
cd logwisp

# Install dependencies
go mod init logwisp
go get github.com/panjf2000/gnet/v2
go get github.com/valyala/fasthttp
go get github.com/lixenwraith/config

# Build
go build -o logwisp ./src/cmd/logwisp

# Run tests
go test ./...
```

## Deployment

### Systemd Service

```ini
[Unit]
Description=LogWisp Multi-Stream Log Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/logwisp --config /etc/logwisp/production.toml
Restart=always
User=logwisp
Group=logwisp

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/var/log

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
RUN useradd -r -s /bin/false logwisp
COPY --from=builder /app/logwisp /usr/local/bin/
USER logwisp
EXPOSE 8080 9090
CMD ["logwisp"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  logwisp:
    build: .
    volumes:
      - /var/log:/var/log:ro
      - ./config.toml:/etc/logwisp/config.toml:ro
    ports:
      - "8080:8080"
      - "9090:9090"
    restart: unless-stopped
    command: ["logwisp", "--config", "/etc/logwisp/config.toml"]
```

## Security Considerations

### Current Implementation
- Read-only file access
- No authentication (placeholder configuration only)
- No TLS/SSL support (placeholder configuration only)

### Planned Security Features
- **Authentication**: Basic, Bearer/JWT, mTLS
- **TLS/SSL**: For both HTTP and TCP streams
- **Rate Limiting**: Per-client request limits
- **IP Filtering**: Whitelist/blacklist support
- **Audit Logging**: Access and authentication events

### Best Practices
1. Run with minimal privileges (read-only access to log files)
2. Use network-level security until authentication is implemented
3. Place behind a reverse proxy for production HTTPS
4. Monitor access logs for unusual patterns
5. Regularly update dependencies

## Troubleshooting

### No Log Entries Appearing
1. Check file permissions (LogWisp needs read access)
2. Verify file paths in configuration
3. Ensure files match the specified patterns
4. Check monitor statistics in status endpoint

### High Memory Usage
1. Reduce buffer sizes in configuration
2. Lower the number of concurrent watchers
3. Increase check interval for less critical logs
4. Use TCP instead of HTTP for high-volume streams

### Connection Drops
1. Check heartbeat configuration
2. Verify network stability
3. Monitor client-side errors
4. Review dropped entry statistics

## License

BSD-3-Clause

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## Roadmap

- [x] Multi-stream architecture
- [x] File and directory monitoring
- [x] TCP and HTTP/SSE streaming
- [x] Path-based HTTP routing
- [ ] Authentication (Basic, JWT, mTLS)
- [ ] TLS/SSL support
- [ ] Rate limiting
- [ ] Prometheus metrics export
- [ ] WebSocket support
- [ ] Log filtering and transformation