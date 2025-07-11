# Router Mode Guide

Router mode enables multiple pipelines to share HTTP ports through path-based routing.

## Overview

**Standard mode**: Each pipeline needs its own port
- Pipeline 1: `http://localhost:8080/stream`
- Pipeline 2: `http://localhost:8081/stream`

**Router mode**: Pipelines share ports via paths
- Pipeline 1: `http://localhost:8080/app/stream`
- Pipeline 2: `http://localhost:8080/database/stream`
- Global status: `http://localhost:8080/status`

## Enabling Router Mode

```bash
logwisp --router --config /etc/logwisp/multi-pipeline.toml
```

## Configuration

```toml
# All pipelines can use the same port
[[pipelines]]
name = "app"
[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/app", pattern = "*.log" }
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }  # Same port OK

[[pipelines]]
name = "database"
[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/postgresql", pattern = "*.log" }
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }  # Shared port
```

## Path Structure

Paths are prefixed with pipeline name:

| Pipeline | Config Path | Router Path |
|----------|-------------|-------------|
| `app` | `/stream` | `/app/stream` |
| `app` | `/status` | `/app/status` |
| `database` | `/stream` | `/database/stream` |

### Custom Paths

```toml
[[pipelines.sinks]]
type = "http"
options = {
    stream_path = "/logs",    # Becomes /app/logs
    status_path = "/health"   # Becomes /app/health
}
```

## Endpoints

### Pipeline Endpoints
```bash
# SSE stream
curl -N http://localhost:8080/app/stream

# Pipeline status
curl http://localhost:8080/database/status
```

### Global Status
```bash
curl http://localhost:8080/status
```

Returns:
```json
{
  "service": "LogWisp Router",
  "pipelines": {
    "app": { /* stats */ },
    "database": { /* stats */ }
  },
  "total_pipelines": 2
}
```

## Use Cases

### Microservices
```toml
[[pipelines]]
name = "frontend"
[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/frontend", pattern = "*.log" }
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }

[[pipelines]]
name = "backend"
[[pipelines.sources]]
type = "directory"
options = { path = "/var/log/backend", pattern = "*.log" }
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }

# Access:
# http://localhost:8080/frontend/stream
# http://localhost:8080/backend/stream
```

### Environment-Based
```toml
[[pipelines]]
name = "prod"
[[pipelines.filters]]
type = "include"
patterns = ["ERROR", "WARN"]
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }

[[pipelines]]
name = "dev"
# No filters - all logs
[[pipelines.sinks]]
type = "http"
options = { port = 8080 }
```

## Limitations

1. **HTTP Only**: Router mode only works for HTTP/SSE
2. **No TCP Routing**: TCP remains on separate ports
3. **Path Conflicts**: Pipeline names must be unique

## Load Balancer Integration

```nginx
upstream logwisp {
    server logwisp1:8080;
    server logwisp2:8080;
}

location /logs/ {
    proxy_pass http://logwisp/;
    proxy_buffering off;
}
```