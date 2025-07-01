# LogWisp - Simple Log Streaming

A lightweight log streaming service that monitors files and streams updates via Server-Sent Events (SSE).

## Philosophy

LogWisp follows the Unix philosophy: do one thing and do it well. It monitors log files and streams them over HTTP/SSE. That's it.

## Features

- Monitors multiple files and directories
- Streams log updates in real-time via SSE
- Supports both plain text and JSON formatted logs
- Automatic file rotation detection
- Simple TOML configuration
- No authentication or complex features - use a reverse proxy if needed

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

LogWisp looks for configuration at `~/.config/logwisp.toml`. If not found, it uses sensible defaults.

Example configuration:
```toml
port = 8080

[monitor]
check_interval_ms = 100

[[monitor.targets]]
path = "/var/log"
pattern = "*.log"

[[monitor.targets]]
path = "/home/user/app/logs"
pattern = "app-*.log"

[stream]
buffer_size = 1000
```

## API

- `GET /stream` - Server-Sent Events stream of log entries

Log entry format:
```json
{
  "time": "2024-01-01T12:00:00Z",
  "source": "app.log",
  "level": "error",
  "message": "Something went wrong",
  "fields": {"key": "value"}
}
```

## Building from Source

Requirements:
- Go 1.23 or later

```bash
go mod download
go build -o logwisp ./src/cmd/logwisp
```

## Usage Examples

### Basic Usage
```bash
# Start LogWisp (monitors current directory by default)
./logwisp

# In another terminal, view the stream
curl -N http://localhost:8080/stream
```

### With Custom Config
```bash
# Create config
cat > ~/.config/logwisp.toml << EOF
port = 9090

[[monitor.targets]]
path = "/var/log/nginx"
pattern = "*.log"
EOF

# Run
./logwisp
```

### Production Deployment

For production use, consider:

1. Run behind a reverse proxy (nginx, caddy) for SSL/TLS
2. Use systemd or similar for process management
3. Add authentication at the proxy level if needed
4. Set appropriate file permissions on monitored logs

Example systemd service:
```ini
[Unit]
Description=LogWisp Log Streaming Service
After=network.target

[Service]
Type=simple
User=logwisp
ExecStart=/usr/local/bin/logwisp
Restart=always

[Install]
WantedBy=multi-user.target
```

## Design Decisions

- **No built-in authentication**: Use a reverse proxy
- **No TLS**: Use a reverse proxy
- **No complex features**: Follows Unix philosophy
- **File-based configuration**: Simple, no CLI args needed
- **SSE over WebSocket**: Simpler, works everywhere

## License

BSD-3-Clause