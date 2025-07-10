# Monitoring & Status Guide

LogWisp provides comprehensive monitoring capabilities through status endpoints, operational logs, and metrics.

## Status Endpoints

### Stream Status

Each stream exposes its own status endpoint:

```bash
# Standalone mode
curl http://localhost:8080/status

# Router mode
curl http://localhost:8080/streamname/status
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
    "mode": {
      "standalone": true,
      "router": false
    }
  },
  "monitor": {
    "active_watchers": 3,
    "total_entries": 152341,
    "dropped_entries": 12,
    "start_time": "2024-01-20T10:00:00Z",
    "last_entry_time": "2024-01-20T11:00:00Z"
  },
  "filters": {
    "filter_count": 2,
    "total_processed": 152341,
    "total_passed": 48234,
    "filters": [
      {
        "type": "include",
        "logic": "or",
        "pattern_count": 3,
        "total_processed": 152341,
        "total_matched": 48234,
        "total_dropped": 0
      }
    ]
  },
  "features": {
    "heartbeat": {
      "enabled": true,
      "interval": 30,
      "format": "comment"
    },
    "rate_limit": {
      "enabled": true,
      "total_requests": 8234,
      "blocked_requests": 89,
      "active_ips": 12,
      "total_connections": 5
    }
  }
}
```

### Global Status (Router Mode)

In router mode, a global status endpoint provides aggregated information:

```bash
curl http://localhost:8080/status
```

## Key Metrics

### Monitor Metrics

Track file watching performance:

| Metric | Description | Healthy Range |
|--------|-------------|---------------|
| `active_watchers` | Number of files being watched | 1-1000 |
| `total_entries` | Total log entries processed | Increasing |
| `dropped_entries` | Entries dropped due to buffer full | < 1% of total |
| `entries_per_second` | Current processing rate | Varies |

### Connection Metrics

Monitor client connections:

| Metric | Description | Warning Signs |
|--------|-------------|---------------|
| `active_clients` | Current SSE connections | Near limit |
| `tcp_connections` | Current TCP connections | Near limit |
| `total_connections` | All active connections | > 80% of max |

### Filter Metrics

Understand filtering effectiveness:

| Metric | Description | Optimization |
|--------|-------------|--------------|
| `total_processed` | Entries checked | - |
| `total_passed` | Entries that passed | Very low = too restrictive |
| `total_dropped` | Entries filtered out | Very high = review patterns |

### Rate Limit Metrics

Track rate limiting impact:

| Metric | Description | Action Needed |
|--------|-------------|---------------|
| `blocked_requests` | Rejected requests | High = increase limits |
| `active_ips` | Unique clients | High = scale out |
| `blocked_percentage` | Rejection rate | > 10% = review |

## Operational Logging

### Log Levels

Configure LogWisp's operational logging:

```toml
[logging]
output = "both"     # file and stderr
level = "info"      # info for production
```

Log levels and their use:
- **DEBUG**: Detailed internal operations
- **INFO**: Normal operations, connections
- **WARN**: Recoverable issues
- **ERROR**: Errors requiring attention

### Important Log Messages

#### Startup Messages
```
LogWisp starting version=1.0.0 config_file=/etc/logwisp.toml
Stream registered with router stream=app
TCP endpoint configured transport=system port=9090
HTTP endpoints configured transport=app stream_url=http://localhost:8080/stream
```

#### Connection Events
```
HTTP client connected remote_addr=192.168.1.100:54231 active_clients=6
HTTP client disconnected remote_addr=192.168.1.100:54231 active_clients=5
TCP connection opened remote_addr=192.168.1.100:54232 active_connections=3
```

#### Error Conditions
```
Failed to open file for checking path=/var/log/app.log error=permission denied
Scanner error while reading file path=/var/log/huge.log error=token too long
Request rate limited ip=192.168.1.100
Connection limit exceeded ip=192.168.1.100 connections=5 limit=5
```

#### Performance Warnings
```
Dropped log entry - subscriber buffer full
Dropped entry for slow client remote_addr=192.168.1.100
Check interval too small: 5ms (min: 10ms)
```

## Health Checks

### Basic Health Check

Simple up/down check:

```bash
#!/bin/bash
# health_check.sh

STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/status)

if [ "$STATUS" -eq 200 ]; then
    echo "LogWisp is healthy"
    exit 0
else
    echo "LogWisp is unhealthy (status: $STATUS)"
    exit 1
fi
```

### Advanced Health Check

Check specific conditions:

```bash
#!/bin/bash
# advanced_health_check.sh

RESPONSE=$(curl -s http://localhost:8080/status)

# Check if processing logs
ENTRIES=$(echo "$RESPONSE" | jq -r '.monitor.total_entries')
if [ "$ENTRIES" -eq 0 ]; then
    echo "WARNING: No log entries processed"
    exit 1
fi

# Check dropped entries
DROPPED=$(echo "$RESPONSE" | jq -r '.monitor.dropped_entries')
TOTAL=$(echo "$RESPONSE" | jq -r '.monitor.total_entries')
DROP_PERCENT=$(( DROPPED * 100 / TOTAL ))

if [ "$DROP_PERCENT" -gt 5 ]; then
    echo "WARNING: High drop rate: ${DROP_PERCENT}%"
    exit 1
fi

# Check connections
CONNECTIONS=$(echo "$RESPONSE" | jq -r '.server.active_clients')
echo "OK: Processing logs, $CONNECTIONS active clients"
exit 0
```

### Container Health Check

Docker/Kubernetes configuration:

```dockerfile
# Dockerfile
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/status || exit 1
```

```yaml
# Kubernetes
livenessProbe:
  httpGet:
    path: /status
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /status
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Monitoring Integration

### Prometheus Metrics

Export metrics in Prometheus format:

```bash
#!/bin/bash
# prometheus_exporter.sh

while true; do
    STATUS=$(curl -s http://localhost:8080/status)
    
    # Extract metrics
    CLIENTS=$(echo "$STATUS" | jq -r '.server.active_clients')
    ENTRIES=$(echo "$STATUS" | jq -r '.monitor.total_entries')
    DROPPED=$(echo "$STATUS" | jq -r '.monitor.dropped_entries')
    
    # Output Prometheus format
    cat << EOF
# HELP logwisp_active_clients Number of active streaming clients
# TYPE logwisp_active_clients gauge
logwisp_active_clients $CLIENTS

# HELP logwisp_total_entries Total log entries processed
# TYPE logwisp_total_entries counter
logwisp_total_entries $ENTRIES

# HELP logwisp_dropped_entries Total log entries dropped
# TYPE logwisp_dropped_entries counter
logwisp_dropped_entries $DROPPED
EOF

    sleep 60
done
```

### Grafana Dashboard

Key panels for Grafana:

1. **Active Connections**
    - Query: `logwisp_active_clients`
    - Visualization: Graph
    - Alert: > 80% of max

2. **Log Processing Rate**
    - Query: `rate(logwisp_total_entries[5m])`
    - Visualization: Graph
    - Alert: < 1 entry/min

3. **Drop Rate**
    - Query: `rate(logwisp_dropped_entries[5m]) / rate(logwisp_total_entries[5m])`
    - Visualization: Gauge
    - Alert: > 5%

4. **Rate Limit Rejections**
    - Query: `rate(logwisp_blocked_requests[5m])`
    - Visualization: Graph
    - Alert: > 10/min

### Datadog Integration

Send custom metrics:

```bash
#!/bin/bash
# datadog_metrics.sh

while true; do
    STATUS=$(curl -s http://localhost:8080/status)
    
    # Send metrics to Datadog
    echo "$STATUS" | jq -r '
        "logwisp.connections:\(.server.active_clients)|g",
        "logwisp.entries:\(.monitor.total_entries)|c",
        "logwisp.dropped:\(.monitor.dropped_entries)|c"
    ' | while read metric; do
        echo "$metric" | nc -u -w1 localhost 8125
    done
    
    sleep 60
done
```

## Performance Monitoring

### CPU Usage

Monitor CPU usage by component:

```bash
# Check process CPU
top -p $(pgrep logwisp) -b -n 1

# Profile CPU usage
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

Common CPU consumers:
- File watching (reduce check_interval_ms)
- Regex filtering (simplify patterns)
- JSON encoding (reduce clients)

### Memory Usage

Track memory consumption:

```bash
# Check process memory
ps aux | grep logwisp

# Detailed memory stats
cat /proc/$(pgrep logwisp)/status | grep -E "Vm(RSS|Size)"
```

Memory optimization:
- Reduce buffer sizes
- Limit connections
- Simplify filters

### Network Bandwidth

Monitor streaming bandwidth:

```bash
# Network statistics
netstat -i
iftop -i eth0 -f "port 8080"

# Connection count
ss -tan | grep :8080 | wc -l
```

## Alerting

### Basic Alerts

Essential alerts to configure:

| Alert | Condition | Severity |
|-------|-----------|----------|
| Service Down | Status endpoint fails | Critical |
| High Drop Rate | > 10% entries dropped | Warning |
| No Log Activity | 0 entries/min for 5 min | Warning |
| Connection Limit | > 90% of max connections | Warning |
| Rate Limit High | > 20% requests blocked | Warning |

### Alert Script

Example monitoring script:

```bash
#!/bin/bash
# monitor_alerts.sh

check_alert() {
    local name=$1
    local condition=$2
    local message=$3
    
    if eval "$condition"; then
        echo "ALERT: $name - $message"
        # Send to alerting system
        # curl -X POST https://alerts.example.com/...
    fi
}

while true; do
    STATUS=$(curl -s http://localhost:8080/status)
    
    if [ -z "$STATUS" ]; then
        check_alert "SERVICE_DOWN" "true" "LogWisp not responding"
        sleep 60
        continue
    fi
    
    # Extract metrics
    DROPPED=$(echo "$STATUS" | jq -r '.monitor.dropped_entries')
    TOTAL=$(echo "$STATUS" | jq -r '.monitor.total_entries')
    CLIENTS=$(echo "$STATUS" | jq -r '.server.active_clients')
    
    # Check conditions
    check_alert "HIGH_DROP_RATE" \
        "[ $((DROPPED * 100 / TOTAL)) -gt 10 ]" \
        "Drop rate above 10%"
        
    check_alert "HIGH_CONNECTIONS" \
        "[ $CLIENTS -gt 90 ]" \
        "Near connection limit: $CLIENTS/100"
    
    sleep 60
done
```

## Troubleshooting with Monitoring

### No Logs Appearing

Check monitor stats:
```bash
curl -s http://localhost:8080/status | jq '.monitor'
```

Look for:
- `active_watchers` = 0 (no files found)
- `total_entries` not increasing (files not updating)

### High CPU Usage

Enable debug logging:
```bash
logwisp --log-level debug --log-output stderr
```

Watch for:
- Frequent "checkFile" messages (reduce check_interval)
- Many filter operations (optimize patterns)

### Memory Growth

Monitor over time:
```bash
while true; do
    ps aux | grep logwisp | grep -v grep
    curl -s http://localhost:8080/status | jq '.server.active_clients'
    sleep 10
done
```

### Connection Issues

Check connection stats:
```bash
# Current connections
curl -s http://localhost:8080/status | jq '.server'

# Rate limit stats
curl -s http://localhost:8080/status | jq '.features.rate_limit'
```

## Best Practices

1. **Regular Monitoring**: Check status endpoints every 30-60 seconds
2. **Set Alerts**: Configure alerts for critical conditions
3. **Log Rotation**: Rotate LogWisp's own logs to prevent disk fill
4. **Baseline Metrics**: Establish normal ranges for your environment
5. **Capacity Planning**: Monitor trends for scaling decisions
6. **Test Monitoring**: Verify alerts work before issues occur

## See Also

- [Performance Tuning](performance.md) - Optimization guide
- [Troubleshooting](troubleshooting.md) - Common issues
- [Configuration Guide](configuration.md) - Monitoring configuration
- [Integration Examples](integrations.md) - Monitoring system integration