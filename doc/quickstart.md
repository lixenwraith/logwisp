# Quick Start Guide

Get LogWisp up and running in 5 minutes with the new pipeline architecture!

## Installation

### From Source
```bash
git clone https://github.com/lixenwraith/logwisp.git
cd logwisp
make install
```

### Using Go Install

```bash
go install github.com/lixenwraith/logwisp/src/cmd/logwisp@latest
```

## Basic Usage

### 1. Monitor Current Directory

Start LogWisp with defaults (monitors `*.log` files in current directory):

```bash
logwisp
```

### 2. Stream Logs

Connect to the log stream:

```bash
# SSE stream
curl -N http://localhost:8080/stream

# Check status
curl http://localhost:8080/status | jq .
```

### 3. Generate Test Logs

```bash
echo "[ERROR] Something went wrong!" >> test.log
echo "[INFO] Application started" >> test.log
echo "[WARN] Low memory warning" >> test.log
```

## Common Scenarios

### Monitor Specific Directory

Create `~/.config/logwisp.toml`:

```toml
[[pipelines]]
name = "myapp"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/myapp", pattern = "*.log" }

[[pipelines.sinks]]
type = "http"
options = { port = 8080 }
```

### Filter Only Errors

```toml
[[pipelines]]
name = "errors"

[[pipelines.sources]]
type = "directory"
options = { path = "./", pattern = "*.log" }

[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "WARN", "CRITICAL"]

[[pipelines.sinks]]
type = "http"
options = { port = 8080 }
```

### Multiple Outputs

Send logs to both HTTP stream and file:

```toml
[[pipelines]]
name = "multi-output"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log" }

# HTTP streaming
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }

# File archival
[[pipelines.sinks]]
type = "file"
options = { directory = "/var/log/archive", name = "app" }
```

### TCP Streaming

For high-performance streaming:

```toml
[[pipelines]]
name = "highperf"

[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log" }

[[pipelines.sinks]]
type = "tcp"
options = { port = 9090, buffer_size = 5000 }
```

Connect with netcat:
```bash
nc localhost 9090
```

### Router Mode

Run multiple pipelines on shared ports:

```bash
logwisp --router

# Access pipelines at:
# http://localhost:8080/myapp/stream
# http://localhost:8080/errors/stream
# http://localhost:8080/status (global)
```

## Quick Tips

### Enable Debug Logging
```bash
logwisp --log-level debug --log-output stderr
```

### Rate Limiting
```toml
[[pipelines.sinks]]
type = "http"
options = {
    port = 8080,
    rate_limit = {
        enabled = true,
        requests_per_second = 10.0,
        burst_size = 20
    }
}
```

### Console Output
```toml
[[pipelines.sinks]]
type = "stdout"  # or "stderr"
options = {}
```