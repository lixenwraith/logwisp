# Networking

*Note: Under redesign*

## TLS Configuration

*Note: As of the latest architecture updates, network TLS, mTLS, and Rate Limiting features are undergoing a redesign and are currently acting as placeholders. The documentation below details the structure for future updates.*
 
## Connection Management

### TCP Keep-Alive

```toml
[[pipelines.plugin_sinks]]
id = "tcp_out"
type = "tcp"
[pipelines.plugin_sinks.config]
keep_alive = true
keep_alive_period_ms = 30000  # 30 seconds
```

### Connection Timeouts

```toml
[[pipelines.plugin_sinks]]
id = "http_out"
type = "http"
[pipelines.plugin_sinks.config]
write_timeout_ms = 10000  # 10 seconds
```

## Heartbeat Configuration

Keep connections alive with periodic heartbeats. Note that Heartbeat is a flow-level feature in the new architecture.

```toml
[pipelines.flow.heartbeat]
enabled = true
interval_ms = 30000
include_timestamp = true
include_stats = false
format = "comment"  # comment|event|json
```

## Network Protocols

### HTTP/HTTPS

- HTTP/1.1 support
- Persistent connections
- Server-Sent Events (SSE)

### TCP

- Raw TCP sockets
- Newline-delimited protocol

## Port Configuration

### Default Ports

| Service | Default Port | Protocol |
|---------|--------------|----------|
| HTTP Sink | 8080 | HTTP |
| TCP Sink | 9090 | TCP |

### Port Conflict Prevention

LogWisp validates port usage at startup:
- Detects port conflicts across pipelines
- Prevents duplicate bindings

## Troubleshooting

### Common Issues

**Connection Refused**
- Check firewall rules
- Verify service is running
- Confirm correct port/host

**TLS Handshake Failure**
- Verify certificate validity
- Check certificate chain
- Confirm TLS versions match

**Rate Limit Exceeded**
- Adjust rate limit parameters
- Add IP to whitelist
- Implement client-side throttling

**Connection Timeout**
- Increase timeout values
- Check network latency
- Verify keep-alive settings
