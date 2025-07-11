# Status Monitoring

LogWisp provides comprehensive monitoring through status endpoints and operational logs.

## Status Endpoints

### Pipeline Status

```bash
# Standalone mode
curl http://localhost:8080/status

# Router mode
curl http://localhost:8080/pipelinename/status
```

Example response:
```json
{
  "service": "LogWisp",
  "version": "1.0.0",
  "server": {
    "type": "http",
    "port": 8080,
    "active_clients": 5,
    "buffer_size": 1000,
    "uptime_seconds": 3600
  },
  "sources": [{
    "type": "directory",
    "total_entries": 152341,
    "dropped_entries": 12,
    "active_watchers": 3
  }],
  "filters": {
    "filter_count": 2,
    "total_processed": 152341,
    "total_passed": 48234
  },
  "sinks": [{
    "type": "http",
    "total_processed": 48234,
    "active_connections": 5
  }]
}
```

## Key Metrics

### Source Metrics
| Metric | Description | Healthy Range |
|--------|-------------|---------------|
| `active_watchers` | Files being watched | 1-1000 |
| `total_entries` | Entries processed | Increasing |
| `dropped_entries` | Buffer overflows | < 1% of total |

### Sink Metrics
| Metric | Description | Warning Signs |
|--------|-------------|---------------|
| `active_connections` | Current clients | Near limit |
| `total_processed` | Entries sent | Should match filter output |

### Filter Metrics
| Metric | Description | Notes |
|--------|-------------|-------|
| `total_processed` | Entries checked | All entries |
| `total_passed` | Passed filters | Check if too low/high |

## Operational Logging

### Log Levels
```toml
[logging]
level = "info"  # debug, info, warn, error
```

### Important Messages

**Startup**:
```
LogWisp starting version=1.0.0
Pipeline created successfully pipeline=app
HTTP server started port=8080
```

**Connections**:
```
HTTP client connected remote_addr=192.168.1.100 active_clients=6
TCP connection opened active_connections=3
```

**Errors**:
```
Failed to open file path=/var/log/app.log error=permission denied
Request rate limited ip=192.168.1.100
```

## Health Checks

### Basic Check
```bash
#!/bin/bash
if curl -s -f http://localhost:8080/status > /dev/null; then
    echo "Healthy"
else
    echo "Unhealthy"
    exit 1
fi
```

### Advanced Check
```bash
#!/bin/bash
STATUS=$(curl -s http://localhost:8080/status)
DROPPED=$(echo "$STATUS" | jq '.sources[0].dropped_entries')
TOTAL=$(echo "$STATUS" | jq '.sources[0].total_entries')

if [ $((DROPPED * 100 / TOTAL)) -gt 5 ]; then
    echo "High drop rate"
    exit 1
fi
```

### Docker
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:8080/status || exit 1
```

## Integration

### Prometheus Export
```bash
#!/bin/bash
STATUS=$(curl -s http://localhost:8080/status)

cat << EOF
# HELP logwisp_active_clients Active streaming clients
# TYPE logwisp_active_clients gauge
logwisp_active_clients $(echo "$STATUS" | jq '.server.active_clients')

# HELP logwisp_total_entries Total log entries
# TYPE logwisp_total_entries counter
logwisp_total_entries $(echo "$STATUS" | jq '.sources[0].total_entries')
EOF
```

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Service Down | Status fails | Critical |
| High Drops | >10% dropped | Warning |
| No Activity | 0 entries/min | Warning |
| Rate Limited | >20% blocked | Warning |

## Performance Monitoring

### CPU Usage
```bash
top -p $(pgrep logwisp)
```

### Memory Usage
```bash
ps aux | grep logwisp
```

### Connections
```bash
ss -tan | grep :8080 | wc -l
```

## Troubleshooting

Enable debug logging:
```bash
logwisp --log-level debug --log-output stderr
```

Check specific components:
```bash
curl -s http://localhost:8080/status | jq '.sources'
curl -s http://localhost:8080/status | jq '.filters'
curl -s http://localhost:8080/status | jq '.sinks'
```