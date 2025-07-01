<p align="center">
  <img src="assets/logo.svg" alt="LogWisp Logo" width="200"/>
</p>

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
- Optional ANSI color pass-through

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

## Command Line Options

```bash
logwisp [OPTIONS] [TARGET...]

OPTIONS:
  -c, --color           Enable color pass-through for ANSI escape codes
  --config FILE         Config file path (default: ~/.config/logwisp.toml)
  --port PORT           HTTP port (default: 8080)
  --buffer-size SIZE    Stream buffer size (default: 1000)
  --check-interval MS   File check interval in ms (default: 100)
  --rate-limit          Enable rate limiting
  --rate-requests N     Rate limit requests/sec (default: 10)
  --rate-burst N        Rate limit burst size (default: 20)

TARGET:
  path[:pattern[:isfile]]   Path to monitor (file or directory)
                           pattern: glob pattern for directories (default: *.log)
                           isfile: true/false (auto-detected if omitted)

EXAMPLES:
  # Monitor current directory for *.log files
  logwisp

  # Monitor specific file with color support
  logwisp -c /var/log/app.log

  # Monitor multiple locations
  logwisp /var/log:*.log /app/logs:error*.log:false /tmp/debug.log::true

  # Custom port with rate limiting
  logwisp --port 9090 --rate-limit --rate-requests 100 --rate-burst 200
```

## Configuration

LogWisp uses a three-level configuration hierarchy:

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file** (~/.config/logwisp.toml)
4. **Default values** (lowest priority)

### Default Values

| Setting | Default | Description |
|---------|---------|-------------|
| `port` | 8080 | HTTP listen port |
| `monitor.check_interval_ms` | 100 | File check interval (milliseconds) |
| `monitor.targets` | [{"path": "./", "pattern": "*.log", "is_file": false}] | Paths to monitor |
| `stream.buffer_size` | 1000 | Per-client event buffer size |
| `stream.rate_limit.enabled` | false | Enable rate limiting |
| `stream.rate_limit.requests_per_second` | 10 | Sustained request rate |
| `stream.rate_limit.burst_size` | 20 | Maximum burst size |
| `stream.rate_limit.cleanup_interval_s` | 60 | Client cleanup interval |

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
| `LOGWISP_STREAM_RATE_LIMIT_CLEANUP_INTERVAL_S` | `stream.rate_limit.cleanup_interval_s` | Cleanup interval |

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

### Complete Configuration Example

```toml
# Port to listen on (default: 8080)
port = 8080

[monitor]
# How often to check for file changes in milliseconds (default: 100)
check_interval_ms = 100

# Paths to monitor
# Default: [{"path": "./", "pattern": "*.log", "is_file": false}]

# Monitor all .log files in current directory
[[monitor.targets]]
path = "./"
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
# Buffer size for each client connection (default: 1000)
# Controls how many log entries can be queued per client
buffer_size = 1000

[stream.rate_limit]
# Enable rate limiting (default: false)
enabled = false

# Requests per second per client (default: 10)
# This is the sustained rate
requests_per_second = 10

# Burst size - max requests at once (default: 20)
# Allows temporary bursts above the sustained rate
burst_size = 20

# How often to clean up old client limiters in seconds (default: 60)
# Clients inactive for 2x this duration are removed
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

### How It Works

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

### Client-Side Handling

#### Terminal Clients

For terminal-based clients (like curl), the escape codes will render as colors:

```bash
# This will show colored output in terminals that support ANSI codes
curl -N http://localhost:8080/stream | jq -r '.message'
```

#### Web Clients

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

#### Custom Processing

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
- `GET /status` - Service status and configuration information

### Log Entry Format

```json
{
  "time": "2024-01-01T12:00:00.123456Z",
  "source": "app.log",
  "level": "error",
  "message": "Something went wrong",
  "fields": {"key": "value"}
}
```

### SSE Event Types

| Event | Description | Data Format |
|-------|-------------|-------------|
| `connected` | Initial connection | `{"client_id": "123456789"}` |
| `data` | Log entry | JSON log entry |
| `disconnected` | Client disconnected | `{"reason": "slow_client"}` |
| `timeout` | Client timeout | `{"reason": "client_timeout"}` |
| `:` | Heartbeat (comment) | ISO timestamp |

### Status Response Format

```json
{
  "service": "LogWisp",
  "version": "2.0.0",
  "port": 8080,
  "color_mode": false,
  "config": {
    "monitor": {
      "check_interval_ms": 100,
      "targets_count": 2
    },
    "stream": {
      "buffer_size": 1000,
      "rate_limit": {
        "enabled": true,
        "requests_per_second": 10,
        "burst_size": 20
      }
    }
  },
  "streamer": {
    "active_clients": 5,
    "buffer_size": 1000,
    "color_mode": false,
    "total_dropped": 42
  },
  "rate_limiter": "Active clients: 3"
}
```

## Usage Examples

### Basic Usage
```bash
# Start with defaults
./logwisp

# Monitor specific file
./logwisp /var/log/app.log

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
# Via command line
./logwisp /var/log:*.log /app/logs:*.json /tmp/debug.log

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
ExecStart=/usr/local/bin/logwisp -c
Restart=always
RestartSec=5

# Environment overrides
Environment="LOGWISP_PORT=8080"
Environment="LOGWISP_STREAM_BUFFER_SIZE=5000"
Environment="LOGWISP_STREAM_RATE_LIMIT_ENABLED=true"
Environment="LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SEC=100"
Environment="LOGWISP_MONITOR_TARGETS=/var/log:*.log:false,/opt/app/logs:*.log:false"

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/var/log /opt/app/logs

[Install]
WantedBy=multi-user.target
```

## Performance Tuning

### Buffer Size

The `stream.buffer_size` setting controls how many log entries can be queued per client:
- **Small buffers (100-500)**: Lower memory usage, clients skip entries during bursts
- **Default (1000)**: Good balance for most use cases
- **Large buffers (5000+)**: Handle burst traffic better, higher memory usage

When a client's buffer is full, new messages are skipped for that client until it catches up. The client remains connected and will receive future messages once buffer space is available.

### Check Interval

The `monitor.check_interval_ms` setting controls file polling frequency:
- **Fast (10-50ms)**: Near real-time updates, higher CPU usage
- **Default (100ms)**: Good balance
- **Slow (500ms+)**: Lower CPU usage, more latency

### Rate Limiting

When to enable rate limiting:
- Internet-facing deployments
- Shared environments
- Protection against misbehaving clients

Rate limiting applies only to establishing SSE connections, not to individual messages. Once connected, clients receive all messages (subject to buffer capacity).

## Troubleshooting

### Client Missing Messages

If clients miss messages during bursts:
1. Check `total_dropped` and `clients_with_drops` in status endpoint
2. Increase `stream.buffer_size` to handle larger bursts
3. Messages are skipped when buffer is full, but clients stay connected

### High Memory Usage

If memory usage is high:
1. Reduce `stream.buffer_size`
2. Enable rate limiting to limit concurrent connections
3. Each client uses `buffer_size * avg_message_size` memory

### Browser Stops Receiving Updates

This shouldn't happen with the current implementation. If it does:
1. Check browser developer console for errors
2. Verify no proxy/firewall is timing out the connection
3. Ensure reverse proxy (if used) doesn't buffer SSE responses

## File Rotation Detection

LogWisp automatically detects log file rotation using multiple methods:
- Inode changes (Linux/Unix)
- File size decrease
- Modification time reset
- Read position beyond file size

When rotation is detected, LogWisp:
1. Logs a rotation event
2. Resets read position to beginning
3. Continues streaming from new file

## Security Notes

1. **No built-in authentication** - Use a reverse proxy for auth
2. **No TLS support** - Use a reverse proxy for HTTPS
3. **Path validation** - Only specified paths can be monitored
4. **Directory traversal protection** - Paths containing ".." are rejected
5. **Rate limiting** - Optional but recommended for public deployments
6. **ANSI escape sequences** - Only enable color mode for trusted log sources

## Design Decisions

- **Unix philosophy**: Single purpose - stream logs
- **SSE over WebSocket**: Simpler, works everywhere, built-in reconnect
- **No database**: Stateless operation, instant startup
- **Atomic config management**: Using LixenWraith/config package
- **Graceful shutdown**: Proper cleanup on SIGINT/SIGTERM
- **Platform agnostic**: POSIX-compliant where possible

## Building from Source

Requirements:
- Go 1.23 or later

```bash
git clone https://github.com/yourusername/logwisp
cd logwisp
go mod download
go build -o logwisp ./src/cmd/logwisp
```

## License

BSD-3-Clause