# Operations Guide

Running, monitoring, and maintaining LogWisp in production.

## Starting LogWisp

### Manual Start

```bash
# Foreground with default config
logwisp

# Background mode
logwisp --background

# With specific configuration
logwisp --config /etc/logwisp/production.toml
```

### Service Management

**Linux (systemd):**
```bash
sudo systemctl start logwisp
sudo systemctl stop logwisp
sudo systemctl restart logwisp
sudo systemctl status logwisp
```

**FreeBSD (rc.d):**
```bash
sudo service logwisp start
sudo service logwisp stop
sudo service logwisp restart
sudo service logwisp status
```

## Configuration Management

### Hot Reload

Enable automatic configuration reload:
```toml
config_auto_reload = true
```

Or via command line:
```bash
logwisp --config-auto-reload
```

Trigger manual reload:
```bash
kill -HUP $(pidof logwisp)
# or
kill -USR1 $(pidof logwisp)
```

### Configuration Validation

Test configuration without starting:
```bash
logwisp --config test.toml --quiet --disable-status-reporter
```

Check for errors:
- Port conflicts
- Invalid patterns
- Missing required fields
- File permissions

## Monitoring

### Status Reporter

Built-in periodic status logging (30-second intervals):

```
[INFO] Status report active_pipelines=2 time=15:04:05
[INFO] Pipeline status pipeline=app entries_processed=10523
[INFO] Pipeline status pipeline=system entries_processed=5231
```

Disable if not needed:
```toml
disable_status_reporter = true
```

### HTTP Status Endpoint

When using HTTP sink:
```bash
curl http://localhost:8080/status | jq .
```

Response structure:
```json
{
  "uptime": "2h15m30s",
  "pipelines": {
    "default": {
      "sources": 1,
      "sinks": 2,
      "processed": 15234,
      "filtered": 523,
      "dropped": 12
    }
  }
}
```

### Metrics Collection

Track via logs:
- Total entries processed
- Entries filtered
- Entries dropped
- Active connections
- Buffer utilization

## Log Management

### LogWisp's Operational Logs

Configuration for LogWisp's own logs:

```toml
[logging]
output = "file"
level = "info"

[logging.file]
directory = "/var/log/logwisp"
name = "logwisp"
max_size_mb = 100
retention_hours = 168
```

### Log Rotation

Automatic rotation based on:
- File size threshold
- Total size limit
- Retention period

Manual rotation:
```bash
# Move current log
mv /var/log/logwisp/logwisp.log /var/log/logwisp/logwisp.log.1
# Send signal to reopen
kill -USR1 $(pidof logwisp)
```

### Log Levels

Operational log levels:
- **debug**: Detailed debugging information
- **info**: General operational messages
- **warn**: Warning conditions
- **error**: Error conditions

Production recommendation: `info` or `warn`

## Performance Tuning

### Buffer Sizing

Adjust buffers based on load:

```toml
# High-volume source
[[pipelines.sources]]
type = "http"
[pipelines.sources.http]
buffer_size = 5000  # Increase for burst traffic

# Slow consumer sink
[[pipelines.sinks]]
type = "http_client"
[pipelines.sinks.http_client]
buffer_size = 10000  # Larger buffer for slow endpoints
batch_size = 500     # Larger batches
```

### Rate Limiting

Protect against overload:

```toml
[pipelines.rate_limit]
rate = 1000.0        # Entries per second
burst = 2000.0       # Burst capacity
policy = "drop"      # Drop excess entries
```

### Connection Limits

Prevent resource exhaustion:

```toml
[pipelines.sources.http.net_limit]
max_connections_total = 1000
max_connections_per_ip = 50
```

## Troubleshooting

### Common Issues

**High Memory Usage**
- Check buffer sizes
- Monitor goroutine count
- Review retention settings

**Dropped Entries**
- Increase buffer sizes
- Add rate limiting
- Check sink performance

**Connection Errors**
- Verify network connectivity
- Check firewall rules
- Review TLS certificates

### Debug Mode

Enable detailed logging:
```bash
logwisp --logging.level=debug --logging.output=stderr
```

### Health Checks

Implement external monitoring:
```bash
#!/bin/bash
# Health check script
if ! curl -sf http://localhost:8080/status > /dev/null; then
  echo "LogWisp health check failed"
  exit 1
fi
```

## Backup and Recovery

### Configuration Backup

```bash
# Backup configuration
cp /etc/logwisp/logwisp.toml /backup/logwisp-$(date +%Y%m%d).toml

# Version control
git add /etc/logwisp/
git commit -m "LogWisp config update"
```

### State Recovery

LogWisp maintains minimal state:
- File read positions (automatic)
- Connection state (automatic)

Recovery after crash:
1. Service automatically restarts (systemd/rc.d)
2. File sources resume from last position
3. Network sources accept new connections
4. Clients reconnect automatically

## Security Operations

### Certificate Management

Monitor certificate expiration:
```bash
openssl x509 -in /path/to/cert.pem -noout -enddate
```

Rotate certificates:
1. Generate new certificates
2. Update configuration
3. Reload service (SIGHUP)

### Access Auditing

Monitor access patterns:
- Review connection logs
- Monitor rate limit hits

## Maintenance

### Planned Maintenance

1. Notify users of maintenance window
2. Stop accepting new connections
3. Drain existing connections
4. Perform maintenance
5. Restart service

### Upgrade Process

1. Download new version
2. Test with current configuration
3. Stop old version
4. Install new version
5. Start service
6. Verify operation

### Cleanup Tasks

Regular maintenance:
- Remove old log files
- Clean temporary files
- Verify disk space
- Update documentation

## Disaster Recovery

### Backup Strategy

- Configuration files: Daily
- TLS certificates: After generation
- Authentication credentials: Secure storage

### Recovery Procedures

Service failure:
1. Check service status
2. Review error logs
3. Verify configuration
4. Restart service

Data loss:
1. Restore configuration from backup
2. Regenerate certificates if needed
3. Recreate authentication credentials
4. Restart service

### Business Continuity

- Run multiple instances for redundancy
- Use load balancer for distribution
- Implement monitoring alerts
- Document recovery procedures