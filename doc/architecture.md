# LogWisp Architecture and Project Structure

## Directory Structure

```
logwisp/
├── Makefile                      # Build automation with version injection
├── go.mod                        # Go module definition
├── go.sum                        # Go module checksums
├── README.md                     # Project documentation
├── config/
│   └── logwisp.toml              # Example configuration template
├── doc/
│   └── architecture.md           # This file - architecture documentation
└── src/
    ├── cmd/
    │   └── logwisp/
    │       └── main.go           # Application entry point, CLI handling
    └── internal/
        ├── config/
        │   ├── auth.go           # Authentication configuration structures
        │   ├── config.go         # Main configuration structures
        │   ├── loader.go         # Configuration loading with lixenwraith/config
        │   ├── server.go         # TCP/HTTP server configurations
        │   ├── ssl.go            # SSL/TLS configuration structures
        │   ├── stream.go         # Stream-specific configurations
        │   └── validation.go     # Configuration validation logic
        ├── logstream/
        │   ├── httprouter.go     # HTTP router for path-based routing
        │   ├── logstream.go      # Stream lifecycle management
        │   ├── routerserver.go   # Router server implementation
        │   └── service.go        # Multi-stream service orchestration
        ├── monitor/
        │   ├── file_watcher.go   # File watching and rotation detection
        │   └── monitor.go        # Log monitoring interface and implementation
        ├── stream/
        │   ├── httpstreamer.go   # HTTP/SSE streaming server
        │   ├── noop_logger.go    # Silent logger for gnet
        │   ├── tcpserver.go      # TCP server using gnet
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
    - Contains: Monitor + Servers (TCP/HTTP)
    - Independent configuration
    - Per-stream statistics

3. **Monitor (`monitor.Monitor`)**
    - Watches files and directories
    - Detects log rotation
    - Publishes log entries to subscribers
    - Configurable check intervals

4. **Streamers**
    - **HTTPStreamer**: SSE-based streaming over HTTP
    - **TCPStreamer**: Raw JSON streaming over TCP
    - Both support configurable heartbeats
    - Non-blocking client management

5. **HTTPRouter (`logstream.HTTPRouter`)**
    - Optional component for path-based routing
    - Consolidates multiple HTTP streams on shared ports
    - Provides global status endpoint

### Data Flow

```
File System → Monitor → LogEntry Channel → Streamer → Network Client
     ↑            ↓
     └── Rotation Detection
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

[streams.tcpserver]
enabled = true
port = 9090
buffer_size = 5000

[streams.tcpserver.heartbeat]
enabled = true
interval_seconds = 60
include_timestamp = true
include_stats = true
```

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
- Global status endpoint
- Best for multi-stream setups with limited ports