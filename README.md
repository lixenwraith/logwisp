# LogWisp - Multi-Stream Log Monitoring Service

<p align="center">
  <img src="assets/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
</p>

A high-performance log streaming service with multi-stream architecture, supporting both TCP and HTTP/SSE protocols with real-time file monitoring, rotation detection, regex-based filtering, and rate limiting.

## Features

- **Multi-Stream Architecture**: Run multiple independent log streams, each with its own configuration
- **Dual Protocol Support**: TCP (raw streaming) and HTTP/SSE (browser-friendly)
- **Real-time Monitoring**: Instant updates with per-stream configurable check intervals
- **File Rotation Detection**: Automatic detection and handling of log rotation
- **Regex-based Filtering**: Include/exclude patterns with AND/OR logic per stream
- **Path-based Routing**: Optional HTTP router for consolidated access
- **Rate Limiting**: Per-IP or global rate limiting with token bucket algorithm
- **Connection Limiting**: Configurable concurrent connection limits per IP
- **Per-Stream Configuration**: Independent settings including check intervals, filters, and rate limits
- **Connection Statistics**: Real-time monitoring of active connections, filter, and rate limit metrics
- **Flexible Targets**: Monitor individual files or entire directories
- **Version Management**: Git tag-based versioning with build information
- **Configurable Heartbeats**: Keep connections alive with customizable formats
- **Minimal Direct Dependencies**: panjf2000/gnet/v2, valyala/fasthttp, lixenwraith/config, and stdlib

## Quick Start

```bash
# Build with version information
make build

# Run with default configuration if ~/.config/logwisp.toml doesn't exists
./logwisp

# Run with custom config
./logwisp --config /etc/logwisp/production.toml

# Run with HTTP router (path-based routing)
./logwisp --router

# Show version information
./logwisp --version
```

## Architecture

LogWisp uses a service-oriented architecture where each stream is an independent pipeline:

```
LogStream Service
├── Stream["app-logs"]
│   ├── Monitor (watches files)
│   ├── Filter Chain (optional)
│   ├── Rate Limiter (optional)
│   ├── TCP Server (optional)
│   └── HTTP Server (optional)
├── Stream["system-logs"]
│   ├── Monitor
│   ├── Filter Chain (optional)
│   ├── Rate Limiter (optional)
│   └── HTTP Server
└── HTTP Router (optional, for path-based routing)
```

## Configuration

Configuration file location: `~/.config/logwisp.toml`

### Basic Multi-Stream Configuration

```toml
# Application logs stream
[[streams]]
name = "app"

[streams.monitor]
# Per-stream check interval in milliseconds
check_interval_ms = 100
targets = [
    { path = "/var/log/myapp", pattern = "*.log", is_file = false },
    { path = "/var/log/myapp/app.log", is_file = true }
]

# Filter configuration (optional)
[[streams.filters]]
type = "include"         # Only show matching logs
logic = "or"            # Match any pattern
patterns = [
    "(?i)error",        # Case-insensitive error
    "(?i)warn",         # Case-insensitive warning
    "(?i)fatal"         # Fatal errors
]

[streams.httpserver]
enabled = true
port = 8080
buffer_size = 2000
stream_path = "/stream"
status_path = "/status"

# Heartbeat configuration
[streams.httpserver.heartbeat]
enabled = true
interval_seconds = 30
format = "comment"  # or "json" for structured events
include_timestamp = true
include_stats = false

# Rate limiting configuration
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 10.0
burst_size = 20
limit_by = "ip"
response_code = 429
response_message = "Rate limit exceeded"
max_connections_per_ip = 5

# System logs stream with slower check interval
[[streams]]
name = "system"

[streams.monitor]
# Check every 60 seconds for slowly updating logs
check_interval_ms = 60000
targets = [
    { path = "/var/log/syslog", is_file = true },
    { path = "/var/log/auth.log", is_file = true }
]

# Exclude debug logs
[[streams.filters]]
type = "exclude"
patterns = ["DEBUG", "TRACE"]

[streams.tcpserver]
enabled = true
port = 9090
buffer_size = 5000

# TCP heartbeat (always JSON format)
[streams.tcpserver.heartbeat]
enabled = true
interval_seconds = 300  # 5 minutes
include_timestamp = true
include_stats = true

# TCP rate limiting
[streams.tcpserver.rate_limit]
enabled = true
requests_per_second = 5.0
burst_size = 10
limit_by = "ip"
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

### Filter Configuration

Control which logs are streamed using regex patterns:

```toml
# Include filter - only matching logs pass
[[streams.filters]]
type = "include"
logic = "or"         # Match ANY pattern
patterns = [
    "ERROR",
    "WARN",
    "CRITICAL"
]

# Exclude filter - matching logs are dropped
[[streams.filters]]
type = "exclude"
logic = "or"         # Drop if ANY pattern matches
patterns = [
    "DEBUG",
    "healthcheck",
    "/metrics"
]

# Complex filter with AND logic
[[streams.filters]]
type = "include"
logic = "and"        # Must match ALL patterns
patterns = [
    "database",      # Must contain "database"
    "error",         # AND must contain "error"
    "connection"     # AND must contain "connection"
]
```

Multiple filters are applied sequentially - all must pass for a log to be streamed.

### Check Interval Configuration

Each stream can have its own check interval based on log update frequency:

- **High-frequency logs**: 50-100ms (e.g., application debug logs)
- **Normal logs**: 100-1000ms (e.g., application logs)
- **Low-frequency logs**: 10000-60000ms (e.g., system logs, archives)

### Rate Limiting Configuration

Control request rates and connection limits per stream:

```toml
[streams.httpserver.rate_limit]
enabled = true                    # Enable/disable rate limiting
requests_per_second = 10.0       # Token refill rate
burst_size = 20                  # Maximum burst capacity
limit_by = "ip"                  # "ip" or "global"
response_code = 429              # HTTP response code when limited
response_message = "Too many requests"
max_connections_per_ip = 5       # Max concurrent connections per IP
max_total_connections = 100      # Max total connections (global)
```

### Heartbeat Configuration

Keep connections alive and detect stale clients with configurable heartbeats:

```toml
[streams.httpserver.heartbeat]
enabled = true
interval_seconds = 30
format = "comment"        # "comment" for SSE comments, "json" for events
include_timestamp = true  # Add timestamp to heartbeat
include_stats = true      # Include connection count and uptime
```

**Heartbeat Formats**:

Comment format (SSE):
```
: heartbeat 2025-01-07T10:30:00Z clients=5 uptime=3600s
```

JSON format (SSE):
```
event: heartbeat
data: {"type":"heartbeat","timestamp":"2025-01-07T10:30:00Z","active_clients":5,"uptime_seconds":3600}
```

TCP always uses JSON format with newline delimiter.

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

# Check stream status (includes filter and rate limit stats)
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

eventSource.addEventListener('heartbeat', (e) => {
    const heartbeat = JSON.parse(e.data);
    console.log('Heartbeat:', heartbeat);
});

eventSource.addEventListener('error', (e) => {
    if (e.status === 429) {
        console.error('Rate limited - backing off');
        // Implement exponential backoff
    }
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
  "version": "v1.0.0",
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
  },
  "filters": {
    "filter_count": 2,
    "total_processed": 15420,
    "total_passed": 1234,
    "filters": [
      {
        "type": "include",
        "logic": "or",
        "pattern_count": 3,
        "total_processed": 15420,
        "total_matched": 1234,
        "total_dropped": 0
      }
    ]
  },
  "features": {
    "rate_limit": {
      "enabled": true,
      "total_requests": 45678,
      "blocked_requests": 234,
      "active_ips": 23,
      "total_connections": 5,
      "config": {
        "requests_per_second": 10,
        "burst_size": 20,
        "limit_by": "ip"
      }
    }
  }
}
```

## Real-time Statistics

LogWisp provides comprehensive statistics at multiple levels:

- **Per-Stream Stats**: Monitor performance, connection counts, data throughput
- **Per-Watcher Stats**: File size, position, entries read, rotation count
- **Filter Stats**: Processed entries, matched patterns, dropped logs
- **Rate Limit Stats**: Total requests, blocked requests, active IPs
- **Global Stats**: Aggregated view of all streams (in router mode)

Access statistics via status endpoints or watch the console output:

```
[15:04:05] Active streams: 2
  app: watchers=3 entries=1542 tcp_conns=2 http_conns=5
  system: watchers=2 entries=8901 tcp_conns=0 http_conns=3
```

## Advanced Features

### Log Filtering

LogWisp implements powerful regex-based filtering:
- **Include Filters**: Whitelist patterns - only matching logs pass
- **Exclude Filters**: Blacklist patterns - matching logs are dropped
- **Logic Options**: OR (match any) or AND (match all) for pattern combinations
- **Filter Chains**: Multiple filters applied sequentially
- **Performance**: Patterns compiled once at startup for efficiency

Filter statistics help monitor effectiveness:
```bash
# Watch filter statistics
watch -n 1 'curl -s http://localhost:8080/status | jq .filters'
```

### Rate Limiting

LogWisp implements token bucket rate limiting with:
- **Per-IP limiting**: Each IP gets its own token bucket
- **Global limiting**: All clients share a single token bucket
- **Connection limits**: Restrict concurrent connections per IP
- **Automatic cleanup**: Stale IP entries removed after 5 minutes
- **Non-blocking**: Excess requests are immediately rejected with 429 status

Monitor rate limiting effectiveness:
```bash
# Watch rate limit statistics
watch -n 1 'curl -s http://localhost:8080/status | jq .features.rate_limit'
```

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

### Per-Stream Check Intervals

Optimize resource usage by configuring check intervals based on log update frequency:

```toml
# High-frequency application logs
[streams.monitor]
check_interval_ms = 50  # Check every 50ms

# Low-frequency system logs
[streams.monitor]
check_interval_ms = 60000  # Check every minute
```

## Performance Tuning

### Monitor Settings
- `check_interval_ms`: Lower values = faster detection, higher CPU usage
- Configure per-stream based on expected update frequency
- Use 10000ms+ for archival or slowly updating logs

### Filter Optimization
- Place most selective filters first
- Use simple patterns when possible
- Consider combining patterns: `"ERROR|WARN"` vs separate patterns
- Monitor filter statistics to identify bottlenecks

### Rate Limiting
- `requests_per_second`: Balance between protection and availability
- `burst_size`: Set to 2-3x the per-second rate for traffic spikes
- `max_connections_per_ip`: Prevent resource exhaustion from single IPs

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
git clone https://github.com/lixenwraith/logwisp
cd logwisp

# Install dependencies
go mod init logwisp
go get github.com/panjf2000/gnet/v2
go get github.com/valyala/fasthttp
go get github.com/lixenwraith/config

# Build with version information
make build

# Run tests
make test

# Test rate limiting
./test_ratelimit.sh

# Test router functionality
./test_router.sh

# Create a release
make release TAG=v1.0.0
```

### Makefile Targets

- `make build` - Build binary with version information
- `make install` - Install to /usr/local/bin
- `make clean` - Remove built binary
- `make test` - Run test suite
- `make release TAG=vX.Y.Z` - Create and push git tag

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

# Rate limiting at system level
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN make build

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
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
```

## Security Considerations

### Current Implementation
- Read-only file access
- Regex pattern validation at startup
- Rate limiting for DDoS protection
- Connection limits to prevent resource exhaustion
- No authentication (placeholder configuration only)
- No TLS/SSL support (placeholder configuration only)

### Filter Security
⚠️ **SECURITY**: Be aware of potential ReDoS (Regular Expression Denial of Service) attacks:
- Complex nested patterns can cause CPU spikes
- Patterns are validated at startup but not for complexity
- Monitor filter processing time in production
- Consider pattern complexity limits for public-facing streams

### Planned Security Features
- **Authentication**: Basic, Bearer/JWT, mTLS
- **TLS/SSL**: For both HTTP and TCP streams
- **IP Filtering**: Whitelist/blacklist support
- **Audit Logging**: Access and authentication events
- **RBAC**: Role-based access control per stream

### Best Practices
1. Run with minimal privileges (read-only access to log files)
2. Configure appropriate rate limits based on expected traffic
3. Use network-level security until authentication is implemented
4. Place behind a reverse proxy for production HTTPS
5. Monitor rate limit statistics for potential attacks
6. Regularly update dependencies
7. Test filter patterns for performance impact
8. Limit regex complexity in production environments

### Rate Limiting Best Practices
- Start with conservative limits and adjust based on monitoring
- Use per-IP limiting for public endpoints
- Use global limiting for resource protection
- Set connection limits to prevent memory exhaustion
- Monitor blocked request statistics for anomalies

## Troubleshooting

### Filter Issues
1. Check filter statistics to see matched/dropped counts
2. Test patterns with sample log entries
3. Verify filter type (include vs exclude)
4. Check filter logic (or vs and)
5. Monitor CPU usage for complex patterns

### Rate Limit Issues
1. Check rate limit statistics in status endpoint
2. Verify appropriate `requests_per_second` for your use case
3. Ensure `burst_size` accommodates normal traffic spikes
4. Monitor for distributed attacks if per-IP limiting isn't effective

### No Log Entries Appearing
1. Check file permissions (LogWisp needs read access)
2. Verify file paths in configuration
3. Ensure files match the specified patterns
4. Check monitor statistics in status endpoint
5. Verify check_interval_ms is appropriate for log update frequency
6. Review filter configuration - logs might be filtered out

### High Memory Usage
1. Reduce buffer sizes in configuration
2. Lower the number of concurrent watchers
3. Enable rate limiting to prevent connection floods
4. Increase check interval for less critical logs
5. Use TCP instead of HTTP for high-volume streams
6. Check for complex regex patterns causing backtracking

### Connection Drops
1. Check heartbeat configuration
2. Verify network stability
3. Monitor client-side errors
4. Review dropped entry statistics
5. Check if rate limits are too restrictive

### Version Information
Use `./logwisp --version` to see:
- Version tag (from git tags)
- Git commit hash
- Build timestamp

## License

BSD-3-Clause

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## Roadmap

- [x] Multi-stream architecture
- [x] File and directory monitoring
- [x] TCP and HTTP/SSE streaming
- [x] Path-based HTTP routing
- [x] Per-stream check intervals
- [x] Version management
- [x] Configurable heartbeats
- [x] Rate and connection limiting
- [x] Regex-based log filtering
- [ ] Log transformation (field extraction, formatting)
- [ ] Configurable logging/stdout support
- [ ] Authentication (Basic, JWT, mTLS)
- [ ] TLS/SSL support
- [ ] Prometheus metrics export
- [ ] WebSocket support