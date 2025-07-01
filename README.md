# LogWisp - Simple Log Streaming

A lightweight log streaming service that monitors files and streams updates via Server-Sent Events (SSE).

## Philosophy

LogWisp follows the Unix philosophy: do one thing and do it well. It monitors log files and streams them over HTTP/SSE. That's it.

## Features

- Monitors multiple files and directories simultaneously
- Streams log updates in real-time via SSE
- Supports both plain text and JSON formatted logs
- Automatic file rotation detection
- Configurable rate limiting
- Environment variable support
- Simple TOML configuration
- Atomic configuration management

## Quick Start

1. Build:
```bash
./build.sh
```

2. Run with defaults (monitors current directory):
```bash
./logwisp
```

3. View logs:
```bash
curl -N http://localhost:8080/stream
```

## Configuration

LogWisp uses a three-level configuration hierarchy:

1. **Environment variables** (highest priority)
2. **Configuration file** (~/.config/logwisp.toml)
3. **Default values** (lowest priority)

### Configuration File Location

Default: `~/.config/logwisp.toml`

Override with environment variables:
- `LOGWISP_CONFIG_DIR` - Directory containing config file
- `LOGWISP_CONFIG_FILE` - Config filename (absolute or relative)

Examples:
```bash
# Use config from current directory
LOGWISP_CONFIG_DIR=. ./logwisp

# Use specific config file
LOGWISP_CONFIG_FILE=/etc/logwisp/prod.toml ./logwisp

# Use custom directory and filename
LOGWISP_CONFIG_DIR=/opt/configs LOGWISP_CONFIG_FILE=myapp.toml ./logwisp
```

### Environment Variables

All configuration values can be overridden via environment variables:

| Environment Variable | Config Path | Description |
|---------------------|-------------|-------------|
| `LOGWISP_PORT` | `port` | HTTP listen port |
| `LOGWISP_MONITOR_CHECK_INTERVAL_MS` | `monitor.check_interval_ms` | File check interval |
| `LOGWISP_MONITOR_TARGETS` | `monitor.targets` | Comma-separated targets |
| `LOGWISP_STREAM_BUFFER_SIZE` | `stream.buffer_size` | Client buffer size |
| `LOGWISP_STREAM_RATE_LIMIT_ENABLED` | `stream.rate_limit.enabled` | Enable rate limiting |
| `LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SEC` | `stream.rate_limit.requests_per_second` | Rate limit |
| `LOGWISP_STREAM_RATE_LIMIT_BURST_SIZE` | `stream.rate_limit.burst_size` | Burst size |
| `LOGWISP_STREAM_RATE_LIMIT_CLEANUP_INTERVAL` | `stream.rate_limit.cleanup_interval_s` | Cleanup interval |

### Monitor Targets Format

The `LOGWISP_MONITOR_TARGETS` environment variable uses a special format:
```
path:pattern:isfile,path2:pattern2:isfile
```

Examples:
```bash
# Monitor directory and specific file
LOGWISP_MONITOR_TARGETS="/var/log:*.log:false,/app/app.log::true" ./logwisp

# Multiple directories
LOGWISP_MONITOR_TARGETS="/var/log:*.log:false,/opt/app/logs:app-*.log:false" ./logwisp
```

### Example Configuration

```toml
port = 8080

[monitor]
check_interval_ms = 100

# Monitor directory (all .log files)
[[monitor.targets]]
path = "/var/log"
pattern = "*.log"
is_file = false

# Monitor specific file
[[monitor.targets]]
path = "/app/logs/app.log"
pattern = ""  # Ignored for files
is_file = true

# Monitor with specific pattern
[[monitor.targets]]
path = "/var/log/nginx"
pattern = "access*.log"
is_file = false

[stream]
buffer_size = 1000

[stream.rate_limit]
enabled = true
requests_per_second = 10
burst_size = 20
cleanup_interval_s = 60
```

## Color Support

LogWisp can pass through ANSI color escape codes from monitored logs to SSE clients using the `-c` flag.

```bash
# Enable color pass-through
./logwisp -c

# Or via systemd
ExecStart=/opt/logwisp/bin/logwisp -c
```

## How It Works

When color mode is enabled (`-c` flag), LogWisp preserves ANSI escape codes in log messages. These are properly JSON-escaped in the SSE stream.

### Example Log with Colors

Original log file content:
```
\033[31mERROR\033[0m: Database connection failed
\033[33mWARN\033[0m: High memory usage detected
\033[32mINFO\033[0m: Service started successfully
```

SSE output with `-c`:
```json
{
  "time": "2024-01-01T12:00:00.123456Z",
  "source": "app.log",
  "message": "\u001b[31mERROR\u001b[0m: Database connection failed"
}
```

## Client-Side Handling

### Terminal Clients

For terminal-based clients (like curl), the escape codes will render as colors:

```bash
# This will show colored output in terminals that support ANSI codes
curl -N http://localhost:8080/stream | jq -r '.message'
```

### Web Clients

For web-based clients, you'll need to convert ANSI codes to HTML:

```javascript
// Example using ansi-to-html library
const AnsiToHtml = require('ansi-to-html');
const convert = new AnsiToHtml();

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  const html = convert.toHtml(data.message);
  document.getElementById('log').innerHTML += html + '<br>';
};
```

### Custom Processing

```python
# Python example with colorama
import json
import colorama
from colorama import init

init()  # Initialize colorama for Windows support

# Process SSE stream
for line in stream:
    if line.startswith('data: '):
        data = json.loads(line[6:])
        # Colorama will handle ANSI codes automatically
        print(data['message'])
```

### Common ANSI Color Codes

| Code | Color/Style |
|------|-------------|
| `\033[0m` | Reset |
| `\033[1m` | Bold |
| `\033[31m` | Red |
| `\033[32m` | Green |
| `\033[33m` | Yellow |
| `\033[34m` | Blue |
| `\033[35m` | Magenta |
| `\033[36m` | Cyan |

### Limitations

1. **JSON Escaping**: ANSI codes are JSON-escaped in the stream (e.g., `\033` becomes `\u001b`)
2. **Client Support**: The client must support or convert ANSI codes
3. **Performance**: No significant impact, but slightly larger message sizes

### Security Note

Color codes are passed through as-is. Ensure monitored logs come from trusted sources to avoid terminal escape sequence attacks.

### Disabling Colors

To strip color codes instead of passing them through:
- Don't use the `-c` flag
- Or set up a preprocessing pipeline:
  ```bash
  tail -f colored.log | sed 's/\x1b\[[0-9;]*m//g' > plain.log
  ```

## API

### Endpoints

- `GET /stream` - Server-Sent Events stream of log entries
- `GET /status` - Service status information

### Log Entry Format

```json
{
  "time": "2024-01-01T12:00:00Z",
  "source": "app.log",
  "level": "error",
  "message": "Something went wrong",
  "fields": {"key": "value"}
}
```

## Usage Examples

### Basic Usage
```bash
# Start with defaults
./logwisp

# View logs
curl -N http://localhost:8080/stream
```

### With Environment Variables
```bash
# Change port and add rate limiting
LOGWISP_PORT=9090 \
LOGWISP_STREAM_RATE_LIMIT_ENABLED=true \
LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SEC=5 \
./logwisp
```

### Monitor Multiple Locations
```bash
# Via environment variable
LOGWISP_MONITOR_TARGETS="/var/log:*.log:false,/app/logs:*.json:false,/tmp/debug.log::true" \
./logwisp

# Or via config file
cat > ~/.config/logwisp.toml << EOF
[[monitor.targets]]
path = "/var/log"
pattern = "*.log"
is_file = false

[[monitor.targets]]
path = "/app/logs"
pattern = "*.json"
is_file = false

[[monitor.targets]]
path = "/tmp/debug.log"
is_file = true
EOF
```

### Production Deployment

Example systemd service with environment overrides:

```ini
[Unit]
Description=LogWisp Log Streaming Service
After=network.target

[Service]
Type=simple
User=logwisp
ExecStart=/usr/local/bin/logwisp
Restart=always

# Environment overrides
Environment="LOGWISP_PORT=8080"
Environment="LOGWISP_STREAM_RATE_LIMIT_ENABLED=true"
Environment="LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SEC=100"
Environment="LOGWISP_MONITOR_TARGETS=/var/log:*.log:false,/opt/app/logs:*.log:false"

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/var/log

[Install]
WantedBy=multi-user.target
```

## Rate Limiting

When enabled, rate limiting is applied per client IP address:

```toml
[stream.rate_limit]
enabled = true
requests_per_second = 10  # Sustained rate
burst_size = 20           # Allow bursts up to this size
cleanup_interval_s = 60   # Clean old clients every minute
```

Rate limiting uses the `X-Forwarded-For` header if present, falling back to `RemoteAddr`.

## Building from Source

Requirements:
- Go 1.23 or later

```bash
go mod download
go build -o logwisp ./src/cmd/logwisp
```

## File Rotation Detection

LogWisp automatically detects log file rotation by:
- Monitoring file inode changes (Linux/Unix)
- Detecting file size decrease
- Resetting read position when rotation is detected

## Security Notes

1. **No built-in authentication** - Use a reverse proxy for auth
2. **No TLS support** - Use a reverse proxy for HTTPS
3. **Path validation** - Monitors only specified paths
4. **Rate limiting** - Optional but recommended for internet-facing deployments

## Design Decisions

- **Unix philosophy**: Single purpose - stream logs
- **No CLI arguments**: Configuration via file and environment only
- **SSE over WebSocket**: Simpler, works everywhere
- **Atomic config management**: Using LixenWraith/config package
- **Graceful shutdown**: Proper cleanup on SIGINT/SIGTERM

## License

BSD-3-Clause