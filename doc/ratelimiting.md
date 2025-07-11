# Rate Limiting Guide

LogWisp provides configurable rate limiting to protect against abuse and ensure fair access.

## How It Works

Token bucket algorithm:
1. Each client gets a bucket with fixed capacity
2. Tokens refill at configured rate
3. Each request consumes one token
4. No tokens = request rejected

## Configuration

```toml
[[pipelines.sinks]]
type = "http"  # or "tcp"
options = {
    port = 8080,
    rate_limit = {
        enabled = true,
        requests_per_second = 10.0,
        burst_size = 20,
        limit_by = "ip",  # or "global"
        max_connections_per_ip = 5,
        max_total_connections = 100,
        response_code = 429,
        response_message = "Rate limit exceeded"
    }
}
```

## Strategies

### Per-IP Limiting (Default)
Each IP gets its own bucket:
```toml
limit_by = "ip"
requests_per_second = 10.0
# Client A: 10 req/sec
# Client B: 10 req/sec
```

### Global Limiting
All clients share one bucket:
```toml
limit_by = "global"
requests_per_second = 50.0
# All clients combined: 50 req/sec
```

## Connection Limits

```toml
max_connections_per_ip = 5    # Per IP
max_total_connections = 100   # Total
```

## Response Behavior

### HTTP
Returns JSON with configured status:
```json
{
    "error": "Rate limit exceeded",
    "retry_after": "60"
}
```

### TCP
Connections silently dropped.

## Examples

### Light Protection
```toml
rate_limit = {
    enabled = true,
    requests_per_second = 50.0,
    burst_size = 100
}
```

### Moderate Protection
```toml
rate_limit = {
    enabled = true,
    requests_per_second = 10.0,
    burst_size = 30,
    max_connections_per_ip = 5
}
```

### Strict Protection
```toml
rate_limit = {
    enabled = true,
    requests_per_second = 2.0,
    burst_size = 5,
    max_connections_per_ip = 2,
    response_code = 503
}
```

## Monitoring

Check statistics:
```bash
curl http://localhost:8080/status | jq '.sinks[0].details.rate_limit'
```

## Testing

```bash
# Test rate limits
for i in {1..20}; do
    curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/status
done
```

## Tuning

- **requests_per_second**: Expected load
- **burst_size**: 2-3× requests_per_second
- **Connection limits**: Based on memory