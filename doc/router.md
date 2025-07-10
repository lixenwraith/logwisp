# Router Mode Guide

Router mode allows multiple LogWisp streams to share HTTP ports through path-based routing, simplifying deployment and access control.

## Overview

In standard mode, each stream requires its own port:
- Stream 1: `http://localhost:8080/stream`
- Stream 2: `http://localhost:8081/stream`
- Stream 3: `http://localhost:8082/stream`

In router mode, streams share ports via paths:
- Stream 1: `http://localhost:8080/app/stream`
- Stream 2: `http://localhost:8080/database/stream`
- Stream 3: `http://localhost:8080/system/stream`
- Global status: `http://localhost:8080/status`

## Enabling Router Mode

Start LogWisp with the `--router` flag:

```bash
logwisp --router --config /etc/logwisp/multi-stream.toml
```

## Configuration

### Basic Router Configuration

```toml
# All streams can use the same port in router mode
[[streams]]
name = "app"
[streams.monitor]
targets = [{ path = "/var/log/app", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080  # Same port OK

[[streams]]
name = "database"
[streams.monitor]
targets = [{ path = "/var/log/postgresql", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080  # Shared port

[[streams]]
name = "nginx"
[streams.monitor]
targets = [{ path = "/var/log/nginx", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080  # Shared port
```

### Path Structure

In router mode, paths are automatically prefixed with the stream name:

| Stream Name | Configuration Path | Router Mode Path |
|------------|-------------------|------------------|
| `app` | `/stream` | `/app/stream` |
| `app` | `/status` | `/app/status` |
| `database` | `/stream` | `/database/stream` |
| `database` | `/status` | `/database/status` |

### Custom Paths

You can customize the paths in each stream:

```toml
[[streams]]
name = "api"
[streams.httpserver]
stream_path = "/logs"      # Becomes /api/logs
status_path = "/health"    # Becomes /api/health
```

## URL Endpoints

### Stream Endpoints

Access individual streams:

```bash
# SSE stream for 'app' logs
curl -N http://localhost:8080/app/stream

# Status for 'database' stream
curl http://localhost:8080/database/status

# Custom path example
curl -N http://localhost:8080/api/logs
```

### Global Status

Router mode provides a global status endpoint:

```bash
curl http://localhost:8080/status | jq .
```

Returns aggregated information:
```json
{
  "service": "LogWisp Router",
  "version": "1.0.0",
  "port": 8080,
  "total_streams": 3,
  "streams": {
    "app": { /* stream stats */ },
    "database": { /* stream stats */ },
    "nginx": { /* stream stats */ }
  },
  "router": {
    "uptime_seconds": 3600,
    "total_requests": 15234,
    "routed_requests": 15220,
    "failed_requests": 14
  }
}
```

## Port Sharing

### How It Works

1. Router server listens on configured ports
2. Examines request path to determine target stream
3. Routes request to appropriate stream handler
4. Stream handles request as if standalone

### Port Assignment Rules

In router mode:
- Multiple streams can use the same port
- Router detects and consolidates shared ports
- Each unique port gets one router server
- TCP servers remain independent (no routing)

Example with multiple ports:

```toml
# Streams 1-3 share port 8080
[[streams]]
name = "app"
[streams.httpserver]
port = 8080

[[streams]]
name = "db"
[streams.httpserver]
port = 8080

[[streams]]
name = "web"
[streams.httpserver]
port = 8080

# Stream 4 uses different port
[[streams]]
name = "admin"
[streams.httpserver]
port = 9090

# Result: 2 router servers (8080 and 9090)
```

## Use Cases

### Microservices Architecture

Route logs from different services:

```toml
[[streams]]
name = "frontend"
[streams.monitor]
targets = [{ path = "/var/log/frontend", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080

[[streams]]
name = "backend"
[streams.monitor]
targets = [{ path = "/var/log/backend", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080

[[streams]]
name = "worker"
[streams.monitor]
targets = [{ path = "/var/log/worker", pattern = "*.log" }]
[streams.httpserver]
enabled = true
port = 8080
```

Access via:
- Frontend logs: `http://localhost:8080/frontend/stream`
- Backend logs: `http://localhost:8080/backend/stream`
- Worker logs: `http://localhost:8080/worker/stream`

### Environment-Based Routing

Different log levels per environment:

```toml
[[streams]]
name = "prod"
[streams.monitor]
targets = [{ path = "/logs/prod", pattern = "*.log" }]
[[streams.filters]]
type = "include"
patterns = ["ERROR", "WARN"]
[streams.httpserver]
port = 8080

[[streams]]
name = "staging"
[streams.monitor]
targets = [{ path = "/logs/staging", pattern = "*.log" }]
[[streams.filters]]
type = "include"
patterns = ["ERROR", "WARN", "INFO"]
[streams.httpserver]
port = 8080

[[streams]]
name = "dev"
[streams.monitor]
targets = [{ path = "/logs/dev", pattern = "*.log" }]
# No filters - all logs
[streams.httpserver]
port = 8080
```

### Department Access

Separate streams for different teams:

```toml
[[streams]]
name = "engineering"
[streams.monitor]
targets = [{ path = "/logs/apps", pattern = "*.log" }]
[streams.httpserver]
port = 8080
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 50.0

[[streams]]
name = "security"
[streams.monitor]
targets = [{ path = "/logs/audit", pattern = "*.log" }]
[streams.httpserver]
port = 8080
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 5.0
max_connections_per_ip = 1

[[streams]]
name = "support"
[streams.monitor]
targets = [{ path = "/logs/customer", pattern = "*.log" }]
[[streams.filters]]
type = "exclude"
patterns = ["password", "token", "secret"]
[streams.httpserver]
port = 8080
```

## Advanced Features

### Mixed Mode Deployment

Combine router and standalone modes:

```toml
# Public streams via router
[[streams]]
name = "public-api"
[streams.httpserver]
enabled = true
port = 8080  # Router mode

[[streams]]
name = "public-web"
[streams.httpserver]
enabled = true
port = 8080  # Router mode

# Internal stream standalone
[[streams]]
name = "internal"
[streams.httpserver]
enabled = true
port = 9999  # Different port, standalone

# High-performance TCP
[[streams]]
name = "metrics"
[streams.tcpserver]
enabled = true
port = 9090  # TCP not affected by router
```

### Load Balancer Integration

Router mode works well with load balancers:

```nginx
# Nginx configuration
upstream logwisp {
    server logwisp1:8080;
    server logwisp2:8080;
    server logwisp3:8080;
}

location /logs/ {
    proxy_pass http://logwisp/;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
}
```

Access becomes:
- `https://example.com/logs/app/stream`
- `https://example.com/logs/database/stream`
- `https://example.com/logs/status`

### Path-Based Access Control

Use reverse proxy for authentication:

```nginx
# Require auth for security logs
location /logs/security/ {
    auth_basic "Security Logs";
    auth_basic_user_file /etc/nginx/security.htpasswd;
    proxy_pass http://localhost:8080/security/;
}

# Public access for status
location /logs/app/ {
    proxy_pass http://localhost:8080/app/;
}
```

## Limitations

### Router Mode Limitations

1. **HTTP Only**: Router mode only works for HTTP/SSE streams
2. **No TCP Routing**: TCP streams remain on separate ports
3. **Path Conflicts**: Stream names must be unique
4. **Same Config**: All streams on a port share SSL/auth settings

### When Not to Use Router Mode

- High-performance scenarios (use TCP)
- Streams need different SSL certificates
- Complex authentication per stream
- Network isolation requirements

## Troubleshooting

### "Path not found"

Check available routes:
```bash
curl http://localhost:8080/invalid-path
```

Response shows available routes:
```json
{
  "error": "Not Found",
  "requested_path": "/invalid-path",
  "available_routes": [
    "/status (global status)",
    "/app/stream (stream: app)",
    "/app/status (status: app)",
    "/database/stream (stream: database)",
    "/database/status (status: database)"
  ]
}
```

### "Port conflict"

If you see port conflicts:
1. Ensure `--router` flag is used
2. Check all streams have `httpserver.enabled = true`
3. Verify no other services use the port

### Debug Routing

Enable debug logging:
```bash
logwisp --router --log-level debug
```

Look for routing decisions:
```
Router request method=GET path=/app/stream remote_addr=127.0.0.1:54321
Routing request to stream stream=app original_path=/app/stream remaining_path=/stream
```

### Performance Impact

Router mode adds minimal overhead:
- ~100-200ns per request for path matching
- Negligible memory overhead
- No impact on streaming performance

## Best Practices

### Naming Conventions

Use clear, consistent stream names:
```toml
# Good: Clear purpose
name = "frontend-prod"
name = "backend-staging"
name = "worker-payments"

# Bad: Ambiguous
name = "logs1"
name = "stream2"
name = "test"
```

### Path Organization

Group related streams:
```
/prod/frontend/stream
/prod/backend/stream
/staging/frontend/stream
/staging/backend/stream
```

### Documentation

Document your routing structure:
```toml
# Stream for production API logs
# Access: https://logs.example.com/api-prod/stream
[[streams]]
name = "api-prod"
```

### Monitoring

Use global status for overview:
```bash
# Monitor all streams
watch -n 5 'curl -s localhost:8080/status | jq .streams'

# Check specific stream
curl -s localhost:8080/status | jq '.streams.app'
```

## Migration Guide

### From Standalone to Router

1. **Update configuration** - ensure consistent ports:
   ```toml
   # Change from different ports
   [streams.httpserver]
   port = 8080  # Was 8081, 8082, etc.
   ```

2. **Start with router flag**:
   ```bash
   logwisp --router --config existing.toml
   ```

3. **Update client URLs**:
   ```bash
   # Old: http://localhost:8081/stream
   # New: http://localhost:8080/streamname/stream
   ```

4. **Update monitoring**:
   ```bash
   # Global status now available
   curl http://localhost:8080/status
   ```

### Gradual Migration

Run both modes during transition:
```bash
# Week 1: Run standalone (current)
logwisp --config prod.toml

# Week 2: Run both
logwisp --config prod.toml &  # Standalone
logwisp --router --config prod-router.toml &  # Router

# Week 3: Router only
logwisp --router --config prod.toml
```

## See Also

- [Configuration Guide](configuration.md) - Stream configuration
- [HTTP Streaming](api.md#http-sse) - SSE protocol details
- [Load Balancing](integrations.md#load-balancers) - Integration patterns
- [Security Best Practices](security.md) - Securing router deployments