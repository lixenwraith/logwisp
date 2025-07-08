# LogWisp Architecture and Project Structure

## Directory Structure

```
logwisp/
├── Makefile                      # Build automation with version injection
├── go.mod                        # Go module definition
├── go.sum                        # Go module checksums
├── README.md                     # Project documentation
├── config/
│   ├── logwisp.toml.defaults     # Default configuration and guide
│   ├── logwisp.toml.example      # Example configuration
│   └── logwisp.toml.minimal      # Minimal configuration template
├── doc/
│   └── architecture.md           # This file - architecture documentation
├── test_router.sh                # Router functionality test suite
├── test_ratelimit.sh             # Rate limiting test suite
└── src/
    ├── cmd/
    │   └── logwisp/
    │       └── main.go           # Application entry point, CLI handling
    └── internal/
        ├── config/
        │   ├── auth.go           # Authentication configuration structures
        │   ├── config.go         # Main configuration structures
        │   ├── loader.go         # Configuration loading with lixenwraith/config
        │   ├── server.go         # TCP/HTTP server configurations with rate limiting
        │   ├── ssl.go            # SSL/TLS configuration structures
        │   ├── stream.go         # Stream-specific configurations
        │   └── validation.go     # Configuration validation including rate limits
        ├── logstream/
        │   ├── httprouter.go     # HTTP router for path-based routing
        │   ├── logstream.go      # Stream lifecycle management
        │   ├── routerserver.go   # Router server implementation
        │   └── service.go        # Multi-stream service orchestration
        ├── monitor/
        │   ├── file_watcher.go   # File watching and rotation detection
        │   └── monitor.go        # Log monitoring interface and implementation
        ├── ratelimit/
        │   ├── ratelimit.go      # Token bucket algorithm implementation
        │   └── limiter.go        # Per-stream rate limiter with IP tracking
        ├── stream/
        │   ├── httpstreamer.go   # HTTP/SSE streaming with rate limiting
        │   ├── noop_logger.go    # Silent logger for gnet
        │   ├── tcpserver.go      # TCP server with rate limiting (gnet)
        │   └── tcpstreamer.go    # TCP streaming implementation
        └── version/
            └── version.go        # Version information management
```

## Configuration System

### Configuration Hierarchy (Highest to Lowest Priority)

1. **CLI Arguments**: Direct command-line flags
2. **Environment Variables**: `LOGWISP_` prefixed variables
3. **Configuration File**: TOML format configuration
4. **Built-in Defaults**: Hardcoded default values

### Configuration Locations

```bash
# Default configuration file location
~/.config/logwisp.toml

# Override via environment variable
export LOGWISP_CONFIG_FILE=/etc/logwisp/production.toml

# Override config directory
export LOGWISP_CONFIG_DIR=/etc/logwisp
export LOGWISP_CONFIG_FILE=production.toml  # Relative to CONFIG_DIR

# Direct CLI override
./logwisp --config /path/to/config.toml
```

### Environment Variable Mapping

Environment variables follow a structured naming pattern:
- Prefix: `LOGWISP_`
- Path separator: `_` (underscore)
- Array index: Numeric suffix (0-based)

Examples:
```bash
# Stream-specific settings
LOGWISP_STREAMS_0_NAME=app
LOGWISP_STREAMS_0_MONITOR_CHECK_INTERVAL_MS=50
LOGWISP_STREAMS_0_HTTPSERVER_PORT=8080
LOGWISP_STREAMS_0_HTTPSERVER_BUFFER_SIZE=2000
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_ENABLED=true
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_FORMAT=json

# Rate limiting configuration
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_ENABLED=true
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_REQUESTS_PER_SECOND=10.0
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_BURST_SIZE=20
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_LIMIT_BY=ip

# Multiple streams
LOGWISP_STREAMS_1_NAME=system
LOGWISP_STREAMS_1_MONITOR_CHECK_INTERVAL_MS=1000
LOGWISP_STREAMS_1_TCPSERVER_PORT=9090
```

## Component Architecture

### Core Components

1. **Service (`logstream.Service`)**
   - Manages multiple log streams
   - Handles lifecycle (creation, shutdown)
   - Provides global statistics
   - Thread-safe stream registry

2. **LogStream (`logstream.LogStream`)**
   - Represents a single log monitoring pipeline
   - Contains: Monitor + Rate Limiter + Servers (TCP/HTTP)
   - Independent configuration
   - Per-stream statistics with rate limit metrics

3. **Monitor (`monitor.Monitor`)**
   - Watches files and directories
   - Detects log rotation
   - Publishes log entries to subscribers
   - Configurable check intervals

4. **Rate Limiter (`ratelimit.Limiter`)**
   - Token bucket algorithm for smooth rate limiting
   - Per-IP or global limiting strategies
   - Connection tracking and limits
   - Automatic cleanup of stale entries
   - Non-blocking rejection of excess requests

5. **Streamers**
   - **HTTPStreamer**: SSE-based streaming over HTTP
      - Rate limit enforcement before request handling
      - Connection tracking for per-IP limits
      - Configurable 429 responses
   - **TCPStreamer**: Raw JSON streaming over TCP
      - Silent connection drops when rate limited
      - Per-IP connection tracking
   - Both support configurable heartbeats
   - Non-blocking client management

6. **HTTPRouter (`logstream.HTTPRouter`)**
   - Optional component for path-based routing
   - Consolidates multiple HTTP streams on shared ports
   - Provides global status endpoint
   - Longest-prefix path matching
   - Dynamic stream registration/deregistration

### Data Flow

```
File System → Monitor → LogEntry Channel → [Rate Limiter] → Streamer → Network Client
     ↑            ↓                              ↓
     └── Rotation Detection              Rate Limit Check
                                               ↓
                                         Accept/Reject
```

### Rate Limiting Architecture

```
Client Request → Rate Limiter → Token Bucket Check → Allow/Deny
                      ↓                    ↓
                 IP Tracking         Refill Rate
                      ↓
                Cleanup Timer
```

### Configuration Structure

```toml
[[streams]]
name = "stream-name"

[streams.monitor]
check_interval_ms = 100  # Per-stream check interval
targets = [
    { path = "/path/to/logs", pattern = "*.log", is_file = false },
    { path = "/path/to/file.log", is_file = true }
]

[streams.httpserver]
enabled = true
port = 8080
buffer_size = 1000
stream_path = "/stream"
status_path = "/status"

[streams.httpserver.heartbeat]
enabled = true
interval_seconds = 30
format = "comment"  # or "json"
include_timestamp = true
include_stats = false

[streams.httpserver.rate_limit]
enabled = false                  # Disabled by default
requests_per_second = 10.0       # Token refill rate
burst_size = 20                  # Token bucket capacity
limit_by = "ip"                  # "ip" or "global"
response_code = 429              # HTTP response code
response_message = "Rate limit exceeded"
max_connections_per_ip = 5       # Concurrent connection limit
max_total_connections = 100      # Global connection limit

[streams.tcpserver]
enabled = true
port = 9090
buffer_size = 5000

[streams.tcpserver.heartbeat]
enabled = true
interval_seconds = 60
include_timestamp = true
include_stats = true

[streams.tcpserver.rate_limit]
enabled = false
requests_per_second = 5.0
burst_size = 10
limit_by = "ip"
```

## Rate Limiting Implementation

### Token Bucket Algorithm
- Each IP (or global limiter) gets a bucket with configurable capacity
- Tokens refill at `requests_per_second` rate
- Each request/connection consumes one token
- Smooth rate limiting without hard cutoffs

### Limiting Strategies
1. **Per-IP**: Each client IP gets its own token bucket
2. **Global**: All clients share a single token bucket

### Connection Limits
- Per-IP connection limits prevent single client resource exhaustion
- Global connection limits protect overall system resources
- Checked before rate limits to prevent connection hanging

### Cleanup
- IP entries older than 5 minutes are automatically removed
- Prevents unbounded memory growth
- Runs every minute in background

## Build System

### Makefile Targets

```bash
make build          # Build with version information
make install        # Install to /usr/local/bin
make clean          # Remove built binary
make test           # Run test suite
make release TAG=v1.0.0  # Create and push git tag
```

### Version Management

Version information is injected at compile time:
```bash
# Automatic version detection from git
VERSION := $(shell git describe --tags --always --dirty)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Manual build with version
go build -ldflags "-X 'logwisp/src/internal/version.Version=v1.0.0'" \
    -o logwisp ./src/cmd/logwisp
```

## Operating Modes

### 1. Standalone Mode (Default)
- Each stream runs its own HTTP/TCP servers
- Direct port access per stream
- Simple configuration
- Best for single-stream or distinct-port setups

### 2. Router Mode (`--router`)
- HTTP streams share ports via path-based routing
- Consolidated access through URL paths
- Global status endpoint with aggregated statistics
- Best for multi-stream setups with limited ports
- Streams accessible at `/{stream_name}/{path}`

## Testing

### Test Suites

1. **Router Testing** (`test_router.sh`)
   - Path routing verification
   - Client isolation between streams
   - Statistics aggregation
   - Graceful shutdown
   - Port conflict handling

2. **Rate Limiting Testing** (`test_ratelimit.sh`)
   - Per-IP rate limiting
   - Global rate limiting
   - Connection limits
   - Rate limit recovery
   - Statistics accuracy
   - Stress testing

### Running Tests

```bash
# Test router functionality
./test_router.sh

# Test rate limiting
./test_ratelimit.sh

# Run all tests
make test
```

## Performance Considerations

### Rate Limiting Overhead
- Token bucket checks: O(1) time complexity
- Memory: ~100 bytes per tracked IP
- Cleanup: Runs asynchronously every minute
- Minimal impact when disabled

### Optimization Guidelines
- Use per-IP limiting for fairness
- Use global limiting for resource protection
- Set burst size to 2-3x requests_per_second
- Monitor rate limit statistics for tuning
- Higher check_interval_ms for low-activity logs

## Security Architecture

### Current Security Features
- Read-only file access
- Rate limiting for DDoS protection
- Connection limits for resource protection
- Non-blocking request rejection

### Future Security Roadmap
- Authentication (Basic, JWT, mTLS)
- TLS/SSL support
- IP whitelisting/blacklisting
- Audit logging
- RBAC per stream

### Security Best Practices
- Run with minimal privileges
- Enable rate limiting on public endpoints
- Use connection limits to prevent exhaustion
- Deploy behind reverse proxy for HTTPS
- Monitor rate limit statistics for attacks