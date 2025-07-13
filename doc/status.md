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
    "uptime_seconds": 3600,
    "mode": {"standalone": true, "router": false}
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
    "active_connections": 5,
    "details": {
      "port": 8080,
      "buffer_size": 1000,
      "rate_limit": {
        "enabled": true,
        "total_requests": 98234,
        "blocked_requests": 234
      }
    }
  }],
  "endpoints": {
    "transport": "/stream",
    "status": "/status"
  },
  "features": {
    "heartbeat": {
      "enabled": true,
      "interval": 30,
      "format": "comment"
    },
    "ssl": {
      "enabled": false
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_second": 10.0,
      "burst_size": 20
    }
  }
}
```

## Key Metrics

### Source Metrics
| Metric | Description | Healthy Range |
|--------|-------------|---------------|
| `active_watchers` | Files being watched | 1-1000 |
| `total_entries` | Entries processed | Increasing |
| `dropped_entries` | Buffer overflows | < 1% of total |
| `active_connections` | Network connections (HTTP/TCP sources) | Within limits |

### Sink Metrics
| Metric | Description | Warning Signs |
|--------|-------------|---------------|
| `active_connections` | Current clients | Near limit |
| `total_processed` | Entries sent | Should match filter output |
| `total_batches` | Batches sent (client sinks) | Increasing |
| `failed_batches` | Failed sends (client sinks) | > 0 indicates issues |

### Filter Metrics
| Metric | Description | Notes |
|--------|-------------|-------|
| `total_processed` | Entries checked | All entries |
| `total_passed` | Passed filters | Check if too low/high |
| `total_matched` | Pattern matches | Per filter stats |

### Rate Limit Metrics
| Metric | Description | Action |
|--------|-------------|--------|
| `blocked_requests` | Rejected requests | Increase limits if high |
| `active_ips` | Unique IPs tracked | Monitor for attacks |
| `total_connections` | Current connections | Check against limits |

## Operational Logging

### Log Levels
```toml
[logging]
level = "info"  # debug, info, warn, error
```

## Health Checks

### Basic Check
```bash
#!/usr/bin/env bash
if curl -s -f http://localhost:8080/status > /dev/null; then
    echo "Healthy"
else
    echo "Unhealthy"
    exit 1
fi
```

### Advanced Check
```bash
#!/usr/bin/env bash
STATUS=$(curl -s http://localhost:8080/status)
DROPPED=$(echo "$STATUS" | jq '.sources[0].dropped_entries')
TOTAL=$(echo "$STATUS" | jq '.sources[0].total_entries')

if [ $((DROPPED * 100 / TOTAL)) -gt 5 ]; then
    echo "High drop rate"
    exit 1
fi

# Check client sink failures
FAILED=$(echo "$STATUS" | jq '.sinks[] | select(.type=="http_client") | .details.failed_batches // 0' | head -1)
if [ "$FAILED" -gt 10 ]; then
    echo "High failure rate"
    exit 1
fi
```