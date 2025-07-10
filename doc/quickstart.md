# Quick Start Guide

Get LogWisp up and running in 5 minutes!

## Installation

### From Source
```bash
# Clone the repository
git clone https://github.com/yourusername/logwisp.git
cd logwisp

# Build and install
make install

# Or just build
make build
./logwisp --version
```

### Using Go Install
```bash
go install github.com/yourusername/logwisp/src/cmd/logwisp@latest
```

## Basic Usage

### 1. Monitor Current Directory

Start LogWisp with defaults (monitors `*.log` files in current directory):

```bash
logwisp
```

### 2. Stream Logs

In another terminal, connect to the log stream:

```bash
# Using curl (SSE stream)
curl -N http://localhost:8080/stream

# Check status
curl http://localhost:8080/status | jq .
```

### 3. Create Some Logs

Generate test logs to see streaming in action:

```bash
# In a third terminal
echo "[ERROR] Something went wrong!" >> test.log
echo "[INFO] Application started" >> test.log
echo "[WARN] Low memory warning" >> test.log
```

## Common Scenarios

### Monitor Specific Directory

Create a configuration file `~/.config/logwisp.toml`:

```toml
[[streams]]
name = "myapp"

[streams.monitor]
targets = [
    { path = "/var/log/myapp", pattern = "*.log", is_file = false }
]

[streams.httpserver]
enabled = true
port = 8080
```

Run LogWisp:
```bash
logwisp
```

### Filter Only Errors and Warnings

Add filters to your configuration:

```toml
[[streams]]
name = "errors"

[streams.monitor]
targets = [
    { path = "./", pattern = "*.log" }
]

[[streams.filters]]
type = "include"
patterns = ["ERROR", "WARN", "CRITICAL", "FATAL"]

[streams.httpserver]
enabled = true
port = 8080
```

### Multiple Log Sources

Monitor different applications on different ports:

```toml
# Stream 1: Web application
[[streams]]
name = "webapp"
[streams.monitor]
targets = [{ path = "/var/log/nginx", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080

# Stream 2: Database
[[streams]]
name = "database"  
[streams.monitor]
targets = [{ path = "/var/log/postgresql", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8081
```

### TCP Streaming

For high-performance streaming, use TCP:

```toml
[[streams]]
name = "highperf"

[streams.monitor]
targets = [{ path = "/var/log/app", pattern = "*.log" }]

[streams.tcpserver]
enabled = true
port = 9090
buffer_size = 5000
```

Connect with netcat:
```bash
nc localhost 9090
```

### Router Mode

Consolidate multiple streams on one port using router mode:

```bash
# With the multi-stream config above
logwisp --router

# Access streams at:
# http://localhost:8080/webapp/stream
# http://localhost:8080/database/stream
# http://localhost:8080/status (global status)
```

## Quick Tips

### Enable Debug Logging
```bash
logwisp --log-level debug --log-output stderr
```

### Run in Background
```bash
logwisp --background --config /etc/logwisp/prod.toml
```

### Rate Limiting
Protect your streams from abuse:

```toml
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 10.0
burst_size = 20
max_connections_per_ip = 5
```

### JSON Output Format
For structured logging:

```toml
[logging.console]
format = "json"
```

## What's Next?

- Read the [Configuration Guide](configuration.md) for all options
- Learn about [Filters](filters.md) for advanced pattern matching
- Explore [Rate Limiting](ratelimiting.md) for production deployments
- Check out [Example Configurations](examples/) for more scenarios

## Getting Help

- Run `logwisp --help` for CLI options
- Check `http://localhost:8080/status` for runtime statistics
- Enable debug logging for troubleshooting
- Visit our [GitHub repository](https://github.com/yourusername/logwisp) for issues and discussions