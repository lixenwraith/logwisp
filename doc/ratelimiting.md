# Rate Limiting Guide

LogWisp provides configurable rate limiting to protect against abuse, prevent resource exhaustion, and ensure fair access to log streams.

## How Rate Limiting Works

LogWisp uses a **token bucket algorithm** for smooth, burst-tolerant rate limiting:

1. Each client (or globally) gets a bucket with a fixed capacity
2. Tokens are added to the bucket at a configured rate
3. Each request consumes one token
4. If no tokens are available, the request is rejected
5. The bucket can accumulate tokens up to its capacity for bursts

## Configuration

### Basic Configuration

```toml
[streams.httpserver.rate_limit]
enabled = true                    # Enable rate limiting
requests_per_second = 10.0        # Token refill rate
burst_size = 20                   # Maximum tokens (bucket capacity)
limit_by = "ip"                   # "ip" or "global"
```

### Complete Options

```toml
[streams.httpserver.rate_limit]
# Core settings
enabled = true                    # Enable/disable rate limiting
requests_per_second = 10.0        # Token generation rate (float)
burst_size = 20                   # Token bucket capacity

# Limiting strategy
limit_by = "ip"                   # "ip" or "global"

# Connection limits
max_connections_per_ip = 5        # Max concurrent connections per IP
max_total_connections = 100       # Max total concurrent connections

# Response configuration
response_code = 429               # HTTP status code when limited
response_message = "Rate limit exceeded"  # Error message

# Same options available for TCP
[streams.tcpserver.rate_limit]
enabled = true
requests_per_second = 5.0
burst_size = 10
limit_by = "ip"
```

## Limiting Strategies

### Per-IP Limiting (Default)

Each client IP address gets its own token bucket:

```toml
[streams.httpserver.rate_limit]
enabled = true
limit_by = "ip"
requests_per_second = 10.0
burst_size = 20
```

**Use cases:**
- Fair access for multiple users
- Prevent single client from monopolizing resources
- Public-facing endpoints

**Example behavior:**
- Client A: Can make 10 req/sec
- Client B: Also can make 10 req/sec
- Total: Up to 10 × number of clients

### Global Limiting

All clients share a single token bucket:

```toml
[streams.httpserver.rate_limit]
enabled = true
limit_by = "global"
requests_per_second = 50.0
burst_size = 100
```

**Use cases:**
- Protect backend resources
- Control total system load
- Internal services with known clients

**Example behavior:**
- All clients combined: 50 req/sec max
- One aggressive client can consume all tokens

## Connection Limits

In addition to request rate limiting, you can limit concurrent connections:

### Per-IP Connection Limit

```toml
[streams.httpserver.rate_limit]
max_connections_per_ip = 5    # Each IP can have max 5 connections
```

**Behavior:**
- Prevents connection exhaustion attacks
- Limits resource usage per client
- Checked before rate limits

### Total Connection Limit

```toml
[streams.httpserver.rate_limit]
max_total_connections = 100   # Max 100 connections total
```

**Behavior:**
- Protects server resources
- Prevents memory exhaustion
- Global limit across all IPs

## Response Behavior

### HTTP Responses

When rate limited, HTTP clients receive:

```json
{
    "error": "Rate limit exceeded",
    "retry_after": "60"
}
```

With these headers:
- Status code: 429 (default) or configured value
- Content-Type: application/json

Configure custom responses:

```toml
[streams.httpserver.rate_limit]
response_code = 503                    # Service Unavailable
response_message = "Server overloaded, please retry later"
```

### TCP Behavior

TCP connections are **silently dropped** when rate limited:
- No error message sent
- Connection immediately closed
- Prevents information leakage

## Configuration Examples

### Light Protection

For internal or trusted environments:

```toml
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 50.0
burst_size = 100
limit_by = "ip"
```

### Moderate Protection

For semi-public endpoints:

```toml
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 10.0
burst_size = 30
limit_by = "ip"
max_connections_per_ip = 5
max_total_connections = 200
```

### Strict Protection

For public or sensitive endpoints:

```toml
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 2.0
burst_size = 5
limit_by = "ip"
max_connections_per_ip = 2
max_total_connections = 50
response_code = 503
response_message = "Service temporarily unavailable"
```

### Debug/Development

Disable for testing:

```toml
[streams.httpserver.rate_limit]
enabled = false
```

## Use Case Scenarios

### Public Log Viewer

Prevent abuse while allowing legitimate use:

```toml
[[streams]]
name = "public-logs"

[streams.httpserver]
enabled = true
port = 8080

[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 5.0      # 5 new connections per second
burst_size = 10                # Allow short bursts
limit_by = "ip"
max_connections_per_ip = 3     # Max 3 streams per user
max_total_connections = 100
```

### Internal Monitoring

Protect against accidental overload:

```toml
[[streams]]
name = "internal-metrics"

[streams.httpserver]
enabled = true
port = 8081

[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 100.0    # High limit for internal use
burst_size = 200
limit_by = "global"            # Total system limit
max_total_connections = 500
```

### High-Security Audit Logs

Very restrictive access:

```toml
[[streams]]
name = "audit"

[streams.httpserver]
enabled = true
port = 8443

[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 0.5      # 1 request every 2 seconds
burst_size = 2
limit_by = "ip"
max_connections_per_ip = 1     # Single connection only
max_total_connections = 10
response_code = 403            # Forbidden (hide rate limit)
response_message = "Access denied"
```

### Multi-Tenant Service

Different limits per stream:

```toml
# Free tier
[[streams]]
name = "logs-free"
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 1.0
burst_size = 5
max_connections_per_ip = 1

# Premium tier
[[streams]]
name = "logs-premium"
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 50.0
burst_size = 100
max_connections_per_ip = 10
```

## Monitoring Rate Limits

### Status Endpoint

Check rate limit statistics:

```bash
curl http://localhost:8080/status | jq '.server.features.rate_limit'
```

Response includes:
```json
{
  "enabled": true,
  "total_requests": 15234,
  "blocked_requests": 89,
  "active_ips": 12,
  "total_connections": 8,
  "config": {
    "requests_per_second": 10,
    "burst_size": 20,
    "limit_by": "ip"
  }
}
```

### Debug Logging

Enable debug logs to see rate limit decisions:

```bash
logwisp --log-level debug
```

Look for messages:
```
Request rate limited ip=192.168.1.100
Connection limit exceeded ip=192.168.1.100 connections=5 limit=5
Created new IP limiter ip=192.168.1.100 total_ips=3
```

## Testing Rate Limits

### Test Script

```bash
#!/bin/bash
# Test rate limiting behavior

URL="http://localhost:8080/stream"
PARALLEL=10
DURATION=10

echo "Testing rate limits..."
echo "URL: $URL"
echo "Parallel connections: $PARALLEL"
echo "Duration: ${DURATION}s"
echo

# Function to connect and count lines
test_connection() {
    local id=$1
    local count=0
    local start=$(date +%s)
    
    while (( $(date +%s) - start < DURATION )); do
        if curl -s -N --max-time 1 "$URL" >/dev/null 2>&1; then
            ((count++))
            echo "[$id] Connected successfully (total: $count)"
        else
            echo "[$id] Rate limited!"
        fi
        sleep 0.1
    done
}

# Run parallel connections
for i in $(seq 1 $PARALLEL); do
    test_connection $i &
done

wait
echo "Test complete"
```

### Load Testing

Using Apache Bench (ab):

```bash
# Test burst handling
ab -n 100 -c 20 http://localhost:8080/status

# Test sustained load
ab -n 1000 -c 5 -r http://localhost:8080/status
```

Using curl:

```bash
# Test connection limit
for i in {1..10}; do
    curl -N http://localhost:8080/stream &
done
```

## Tuning Guidelines

### Setting requests_per_second

Consider:
- Expected legitimate traffic
- Server capacity
- Client retry behavior

**Formula**: `requests_per_second = expected_clients × requests_per_client`

### Setting burst_size

General rule: `burst_size = 2-3 × requests_per_second`

Examples:
- `10 req/s → burst_size = 20-30`
- `1 req/s → burst_size = 3-5`
- `100 req/s → burst_size = 200-300`

### Connection Limits

Based on available memory:
- Each HTTP connection: ~1-2MB
- Each TCP connection: ~0.5-1MB

**Formula**: `max_connections = available_memory / memory_per_connection`

## Common Issues

### "All requests blocked"

Check if:
- Rate limits too strict
- Burst size too small
- Using global limiting with many clients

### "Memory growth"

Possible causes:
- No connection limits set
- Slow clients holding connections
- Too high burst_size

Solutions:
```toml
max_connections_per_ip = 5
max_total_connections = 100
```

### "Legitimate users blocked"

Consider:
- Increasing burst_size for short spikes
- Using per-IP instead of global limiting
- Different streams for different user tiers

## Security Considerations

### Information Disclosure

Rate limit responses can reveal information:

```toml
# Default - informative
response_code = 429
response_message = "Rate limit exceeded"

# Security-focused - generic
response_code = 503
response_message = "Service unavailable"

# High security - misleading
response_code = 403
response_message = "Forbidden"
```

### DDoS Protection

Rate limiting helps but isn't complete DDoS protection:
- Use with firewall rules
- Consider CDN/proxy rate limiting
- Monitor for distributed attacks

### Resource Exhaustion

Protect against:
- Connection exhaustion
- Memory exhaustion
- CPU exhaustion

```toml
# Comprehensive protection
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 10.0
burst_size = 20
max_connections_per_ip = 5
max_total_connections = 100
limit_by = "ip"
```

## Best Practices

1. **Start Conservative**: Begin with strict limits and relax as needed
2. **Monitor Statistics**: Use `/status` endpoint to track behavior
3. **Test Thoroughly**: Verify limits work as expected under load
4. **Document Limits**: Make rate limits clear to users
5. **Provide Retry Info**: Help clients implement proper retry logic
6. **Different Tiers**: Consider different limits for different user types
7. **Regular Review**: Adjust limits based on usage patterns

## See Also

- [Configuration Guide](configuration.md) - Complete configuration reference
- [Security Best Practices](security.md) - Security hardening
- [Performance Tuning](performance.md) - Optimization guidelines
- [Troubleshooting](troubleshooting.md) - Common issues