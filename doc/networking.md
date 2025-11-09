# Networking

Network configuration for LogWisp connections, including TLS, rate limiting, and access control.

## TLS Configuration

### TLS Support Matrix

| Component | TLS Support | Notes |
|-----------|-------------|-------|
| HTTP Source | ✓ | Full TLS 1.2/1.3 |
| HTTP Sink | ✓ | Full TLS 1.2/1.3 |
| HTTP Client | ✓ | Client certificates |
| TCP Source | ✗ | No encryption |
| TCP Sink | ✗ | No encryption |
| TCP Client | ✗ | No encryption |

### Server TLS Configuration

```toml
[pipelines.sources.http.tls]
enabled = true
cert_file = "/path/to/server.pem"
key_file = "/path/to/server.key"
min_version = "TLS1.2"  # TLS1.2|TLS1.3
client_auth = false
client_ca_file = "/path/to/client-ca.pem"
verify_client_cert = true
```

### Client TLS Configuration

```toml
[pipelines.sinks.http_client.tls]
enabled = true
server_ca_file = "/path/to/ca.pem"  # For server verification
server_name = "logs.example.com"
insecure_skip_verify = false
client_cert_file = "/path/to/client.pem"  # For mTLS
client_key_file = "/path/to/client.key"   # For mTLS
```

### TLS Certificate Generation

Using the `tls` command:

```bash
# Generate CA certificate
logwisp tls -ca -o myca

# Generate server certificate
logwisp tls -server -ca-cert myca.pem -ca-key myca.key -host localhost,server.example.com -o server

# Generate client certificate
logwisp tls -client -ca-cert myca.pem -ca-key myca.key -o client
```

Command options:

| Flag | Description |
|------|-------------|
| `-ca` | Generate CA certificate |
| `-server` | Generate server certificate |
| `-client` | Generate client certificate |
| `-host` | Comma-separated hostnames/IPs |
| `-o` | Output file prefix |
| `-days` | Certificate validity (default: 365) |

## Network Rate Limiting

### Configuration Options

```toml
[pipelines.sources.http.net_limit]
enabled = true
max_connections_per_ip = 10
max_connections_total = 100
requests_per_second = 100.0
burst_size = 200
response_code = 429
response_message = "Rate limit exceeded"
ip_whitelist = ["192.168.1.0/24"]
ip_blacklist = ["10.0.0.0/8"]
```

### Rate Limiting Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `enabled` | bool | Enable rate limiting |
| `max_connections_per_ip` | int | Per-IP connection limit |
| `max_connections_total` | int | Global connection limit |
| `requests_per_second` | float | Request rate limit |
| `burst_size` | int | Token bucket burst capacity |
| `response_code` | int | HTTP response code when limited |
| `response_message` | string | Response message when limited |

### IP Access Control

**Whitelist**: Only specified IPs/networks allowed
```toml
ip_whitelist = [
    "192.168.1.0/24",  # Local network
    "10.0.0.0/8",      # Private network
    "203.0.113.5"      # Specific IP
]
```

**Blacklist**: Specified IPs/networks denied
```toml
ip_blacklist = [
    "192.168.1.100",   # Blocked host
    "10.0.0.0/16"      # Blocked subnet
]
```

Processing order:
1. Blacklist (immediate deny if matched)
2. Whitelist (must match if configured)
3. Rate limiting
4. Authentication

## Connection Management

### TCP Keep-Alive

```toml
[pipelines.sources.tcp]
keep_alive = true
keep_alive_period_ms = 30000  # 30 seconds
```

Benefits:
- Detect dead connections
- Prevent connection timeout
- Maintain NAT mappings

### Connection Timeouts

```toml
[pipelines.sources.http]
read_timeout_ms = 10000   # 10 seconds
write_timeout_ms = 10000  # 10 seconds

[pipelines.sinks.tcp_client]
dial_timeout = 10         # Connection timeout
write_timeout = 30        # Write timeout
read_timeout = 10         # Read timeout
```

### Connection Limits

Global limits:
```toml
max_connections = 100     # Total concurrent connections
```

Per-IP limits:
```toml
max_connections_per_ip = 10
```

## Heartbeat Configuration

Keep connections alive with periodic heartbeats:

### HTTP Sink Heartbeat

```toml
[pipelines.sinks.http.heartbeat]
enabled = true
interval_ms = 30000
include_timestamp = true
include_stats = false
format = "comment"  # comment|event|json
```

Formats:
- **comment**: SSE comment (`: heartbeat`)
- **event**: SSE event with data
- **json**: JSON-formatted heartbeat

### TCP Sink Heartbeat

```toml
[pipelines.sinks.tcp.heartbeat]
enabled = true
interval_ms = 30000
include_timestamp = true
include_stats = false
format = "json"  # json|txt
```

## Network Protocols

### HTTP/HTTPS

- HTTP/1.1 and HTTP/2 support
- Persistent connections
- Chunked transfer encoding
- Server-Sent Events (SSE)

### TCP

- Raw TCP sockets
- Newline-delimited protocol
- Binary-safe transmission
- No encryption available

## Port Configuration

### Default Ports

| Service | Default Port | Protocol |
|---------|--------------|----------|
| HTTP Source | 8081 | HTTP/HTTPS |
| HTTP Sink | 8080 | HTTP/HTTPS |
| TCP Source | 9091 | TCP |
| TCP Sink | 9090 | TCP |

### Port Conflict Prevention

LogWisp validates port usage at startup:
- Detects port conflicts across pipelines
- Prevents duplicate bindings
- Suggests alternative ports

## Network Security

### Best Practices

1. **Use TLS for HTTP** connections when possible
2. **Implement rate limiting** to prevent DoS
3. **Configure IP whitelists** for restricted access
4. **Enable authentication** for all network endpoints
5. **Use non-standard ports** to reduce scanning exposure
6. **Monitor connection metrics** for anomalies
7. **Set appropriate timeouts** to prevent resource exhaustion

### Security Warnings

- TCP connections are **always unencrypted**
- HTTP Basic/Token auth **requires TLS**
- Avoid `skip_verify` in production
- Never expose unauthenticated endpoints publicly

## Load Balancing

### Client-Side Load Balancing

Configure multiple endpoints (future feature):
```toml
[[pipelines.sinks.http_client]]
urls = [
    "https://log1.example.com/ingest",
    "https://log2.example.com/ingest"
]
strategy = "round-robin"  # round-robin|random|least-conn
```

### Server-Side Considerations

- Use reverse proxy for load distribution
- Configure session affinity if needed
- Monitor individual instance health

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