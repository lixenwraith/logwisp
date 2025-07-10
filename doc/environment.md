# Environment Variables

LogWisp supports comprehensive configuration through environment variables, allowing deployment without configuration files or dynamic overrides in containerized environments.

## Naming Convention

Environment variables follow a structured pattern:
- **Prefix**: `LOGWISP_`
- **Path separator**: `_` (underscore)
- **Array indices**: Numeric suffix (0-based)
- **Case**: UPPERCASE

### Examples:
- Config file setting: `logging.level = "debug"`
- Environment variable: `LOGWISP_LOGGING_LEVEL=debug`

- Array element: `streams[0].name = "app"`
- Environment variable: `LOGWISP_STREAMS_0_NAME=app`

## General Variables

### `LOGWISP_CONFIG_FILE`
Path to the configuration file.
- **Default**: `~/.config/logwisp.toml`
- **Example**: `LOGWISP_CONFIG_FILE=/etc/logwisp/config.toml`

### `LOGWISP_CONFIG_DIR`
Directory containing configuration files.
- **Usage**: Combined with `LOGWISP_CONFIG_FILE` for relative paths
- **Example**:
  ```bash
  export LOGWISP_CONFIG_DIR=/etc/logwisp
  export LOGWISP_CONFIG_FILE=production.toml
  # Loads: /etc/logwisp/production.toml
  ```

### `LOGWISP_DISABLE_STATUS_REPORTER`
Disable the periodic status reporter.
- **Values**: `1` (disable), `0` or unset (enable)
- **Default**: `0` (enabled)
- **Example**: `LOGWISP_DISABLE_STATUS_REPORTER=1`

### `LOGWISP_BACKGROUND`
Internal marker for background process detection.
- **Note**: Set automatically by `--background` flag
- **Values**: `1` (background), unset (foreground)

## Logging Variables

### `LOGWISP_LOGGING_OUTPUT`
LogWisp's operational log output mode.
- **Values**: `file`, `stdout`, `stderr`, `both`, `none`
- **Example**: `LOGWISP_LOGGING_OUTPUT=both`

### `LOGWISP_LOGGING_LEVEL`
Minimum log level for operational logs.
- **Values**: `debug`, `info`, `warn`, `error`
- **Example**: `LOGWISP_LOGGING_LEVEL=debug`

### File Logging
```bash
LOGWISP_LOGGING_FILE_DIRECTORY=/var/log/logwisp
LOGWISP_LOGGING_FILE_NAME=logwisp
LOGWISP_LOGGING_FILE_MAX_SIZE_MB=100
LOGWISP_LOGGING_FILE_MAX_TOTAL_SIZE_MB=1000
LOGWISP_LOGGING_FILE_RETENTION_HOURS=168  # 7 days
```

### Console Logging
```bash
LOGWISP_LOGGING_CONSOLE_TARGET=stderr     # stdout, stderr, split
LOGWISP_LOGGING_CONSOLE_FORMAT=txt        # txt, json
```

## Stream Configuration

Streams are configured using array indices (0-based).

### Basic Stream Settings
```bash
# First stream (index 0)
LOGWISP_STREAMS_0_NAME=app
LOGWISP_STREAMS_0_MONITOR_CHECK_INTERVAL_MS=100

# Second stream (index 1)
LOGWISP_STREAMS_1_NAME=system
LOGWISP_STREAMS_1_MONITOR_CHECK_INTERVAL_MS=1000
```

### Monitor Targets
```bash
# Single file target
LOGWISP_STREAMS_0_MONITOR_TARGETS_0_PATH=/var/log/app.log
LOGWISP_STREAMS_0_MONITOR_TARGETS_0_IS_FILE=true

# Directory with pattern
LOGWISP_STREAMS_0_MONITOR_TARGETS_1_PATH=/var/log/myapp
LOGWISP_STREAMS_0_MONITOR_TARGETS_1_PATTERN="*.log"
LOGWISP_STREAMS_0_MONITOR_TARGETS_1_IS_FILE=false
```

### Filters
```bash
# Include filter
LOGWISP_STREAMS_0_FILTERS_0_TYPE=include
LOGWISP_STREAMS_0_FILTERS_0_LOGIC=or
LOGWISP_STREAMS_0_FILTERS_0_PATTERNS='["ERROR","WARN","CRITICAL"]'

# Exclude filter
LOGWISP_STREAMS_0_FILTERS_1_TYPE=exclude
LOGWISP_STREAMS_0_FILTERS_1_PATTERNS='["DEBUG","TRACE"]'
```

### HTTP Server
```bash
LOGWISP_STREAMS_0_HTTPSERVER_ENABLED=true
LOGWISP_STREAMS_0_HTTPSERVER_PORT=8080
LOGWISP_STREAMS_0_HTTPSERVER_BUFFER_SIZE=1000
LOGWISP_STREAMS_0_HTTPSERVER_STREAM_PATH=/stream
LOGWISP_STREAMS_0_HTTPSERVER_STATUS_PATH=/status

# Heartbeat
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_ENABLED=true
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_INTERVAL_SECONDS=30
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_FORMAT=comment
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_INCLUDE_TIMESTAMP=true
LOGWISP_STREAMS_0_HTTPSERVER_HEARTBEAT_INCLUDE_STATS=false

# Rate Limiting
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_ENABLED=true
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_REQUESTS_PER_SECOND=10.0
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_BURST_SIZE=20
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_LIMIT_BY=ip
LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_MAX_CONNECTIONS_PER_IP=5
```

### TCP Server
```bash
LOGWISP_STREAMS_0_TCPSERVER_ENABLED=true
LOGWISP_STREAMS_0_TCPSERVER_PORT=9090
LOGWISP_STREAMS_0_TCPSERVER_BUFFER_SIZE=5000

# Rate Limiting
LOGWISP_STREAMS_0_TCPSERVER_RATE_LIMIT_ENABLED=true
LOGWISP_STREAMS_0_TCPSERVER_RATE_LIMIT_REQUESTS_PER_SECOND=5.0
LOGWISP_STREAMS_0_TCPSERVER_RATE_LIMIT_BURST_SIZE=10
```

## Complete Example

Here's a complete example configuring two streams via environment variables:

```bash
#!/bin/bash

# Logging configuration
export LOGWISP_LOGGING_OUTPUT=both
export LOGWISP_LOGGING_LEVEL=info
export LOGWISP_LOGGING_FILE_DIRECTORY=/var/log/logwisp
export LOGWISP_LOGGING_FILE_MAX_SIZE_MB=100

# Stream 0: Application logs
export LOGWISP_STREAMS_0_NAME=app
export LOGWISP_STREAMS_0_MONITOR_CHECK_INTERVAL_MS=50
export LOGWISP_STREAMS_0_MONITOR_TARGETS_0_PATH=/var/log/myapp
export LOGWISP_STREAMS_0_MONITOR_TARGETS_0_PATTERN="*.log"
export LOGWISP_STREAMS_0_MONITOR_TARGETS_0_IS_FILE=false

# Stream 0: Filters
export LOGWISP_STREAMS_0_FILTERS_0_TYPE=include
export LOGWISP_STREAMS_0_FILTERS_0_PATTERNS='["ERROR","WARN"]'

# Stream 0: HTTP server
export LOGWISP_STREAMS_0_HTTPSERVER_ENABLED=true
export LOGWISP_STREAMS_0_HTTPSERVER_PORT=8080
export LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_ENABLED=true
export LOGWISP_STREAMS_0_HTTPSERVER_RATE_LIMIT_REQUESTS_PER_SECOND=25.0

# Stream 1: System logs
export LOGWISP_STREAMS_1_NAME=system
export LOGWISP_STREAMS_1_MONITOR_CHECK_INTERVAL_MS=1000
export LOGWISP_STREAMS_1_MONITOR_TARGETS_0_PATH=/var/log/syslog
export LOGWISP_STREAMS_1_MONITOR_TARGETS_0_IS_FILE=true

# Stream 1: TCP server
export LOGWISP_STREAMS_1_TCPSERVER_ENABLED=true
export LOGWISP_STREAMS_1_TCPSERVER_PORT=9090

# Start LogWisp
logwisp
```

## Docker/Kubernetes Usage

Environment variables are ideal for containerized deployments:

### Docker
```dockerfile
FROM logwisp:latest
ENV LOGWISP_LOGGING_OUTPUT=stdout
ENV LOGWISP_STREAMS_0_NAME=container
ENV LOGWISP_STREAMS_0_MONITOR_TARGETS_0_PATH=/var/log/app
ENV LOGWISP_STREAMS_0_HTTPSERVER_PORT=8080
```

### Docker Compose
```yaml
version: '3'
services:
  logwisp:
    image: logwisp:latest
    environment:
      - LOGWISP_LOGGING_OUTPUT=stdout
      - LOGWISP_STREAMS_0_NAME=webapp
      - LOGWISP_STREAMS_0_MONITOR_TARGETS_0_PATH=/logs
      - LOGWISP_STREAMS_0_HTTPSERVER_PORT=8080
    volumes:
      - ./logs:/logs:ro
    ports:
      - "8080:8080"
```

### Kubernetes ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: logwisp-config
data:
  LOGWISP_LOGGING_LEVEL: "info"
  LOGWISP_STREAMS_0_NAME: "k8s-app"
  LOGWISP_STREAMS_0_HTTPSERVER_PORT: "8080"
```

## Precedence Rules

When the same setting is configured multiple ways, this precedence applies:

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Default values** (lowest priority)

Example:
```bash
# Config file has: logging.level = "info"
export LOGWISP_LOGGING_LEVEL=warn
logwisp --log-level debug

# Result: log level will be "debug" (CLI flag wins)
```

## Debugging

To see which environment variables LogWisp recognizes:
```bash
# List all LOGWISP variables
env | grep ^LOGWISP_

# Test configuration parsing
LOGWISP_LOGGING_LEVEL=debug logwisp --version
```

## Security Considerations

- **Sensitive Values**: Avoid putting passwords or tokens in environment variables
- **Process Visibility**: Environment variables may be visible to other processes
- **Container Security**: Use secrets management for sensitive configuration
- **Logging**: Be careful not to log environment variable values

## See Also

- [Configuration Guide](configuration.md) - Complete configuration reference
- [CLI Options](cli.md) - Command-line interface
- [Docker Deployment](integrations.md#docker) - Container-specific guidance