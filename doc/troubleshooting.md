# Troubleshooting Guide

This guide helps diagnose and resolve common issues with LogWisp.

## Diagnostic Tools

### Enable Debug Logging

The first step in troubleshooting is enabling debug logs:

```bash
# Via command line
logwisp --log-level debug --log-output stderr

# Via environment
export LOGWISP_LOGGING_LEVEL=debug
logwisp

# Via config
[logging]
level = "debug"
output = "stderr"
```

### Check Status Endpoint

Verify LogWisp is running and processing:

```bash
# Basic check
curl http://localhost:8080/status

# Pretty print
curl -s http://localhost:8080/status | jq .

# Check specific metrics
curl -s http://localhost:8080/status | jq '.monitor'
```

### Test Log Streaming

Verify streams are working:

```bash
# Test SSE stream (should show heartbeats if enabled)
curl -N http://localhost:8080/stream

# Test with timeout
timeout 5 curl -N http://localhost:8080/stream

# Test TCP stream
nc localhost 9090
```

## Common Issues

### No Logs Appearing

**Symptoms:**
- Stream connects but no log entries appear
- Status shows `total_entries: 0`

**Diagnosis:**

1. Check monitor configuration:
   ```bash
   curl -s http://localhost:8080/status | jq '.monitor'
   ```

2. Verify file paths exist:
   ```bash
   # Check your configured paths
   ls -la /var/log/myapp/
   ```

3. Check file permissions:
   ```bash
   # LogWisp user must have read access
   sudo -u logwisp ls /var/log/myapp/
   ```

4. Verify files match pattern:
   ```bash
   # If pattern is "*.log"
   ls /var/log/myapp/*.log
   ```

5. Check if files are being updated:
   ```bash
   # Should show recent timestamps
   ls -la /var/log/myapp/*.log
   tail -f /var/log/myapp/app.log
   ```

**Solutions:**

- Fix file permissions:
  ```bash
  sudo chmod 644 /var/log/myapp/*.log
  sudo usermod -a -G adm logwisp  # Add to log group
  ```

- Correct path configuration:
  ```toml
  targets = [
      { path = "/correct/path/to/logs", pattern = "*.log" }
  ]
  ```

- Use absolute paths:
  ```toml
  # Bad: Relative path
  targets = [{ path = "./logs", pattern = "*.log" }]
  
  # Good: Absolute path
  targets = [{ path = "/var/log/app", pattern = "*.log" }]
  ```

### High CPU Usage

**Symptoms:**
- LogWisp process using excessive CPU
- System slowdown

**Diagnosis:**

1. Check process CPU:
   ```bash
   top -p $(pgrep logwisp)
   ```

2. Review check intervals:
   ```bash
   grep check_interval /etc/logwisp/logwisp.toml
   ```

3. Count active watchers:
   ```bash
   curl -s http://localhost:8080/status | jq '.monitor.active_watchers'
   ```

4. Check filter complexity:
   ```bash
   curl -s http://localhost:8080/status | jq '.filters'
   ```

**Solutions:**

- Increase check interval:
  ```toml
  [streams.monitor]
  check_interval_ms = 1000  # Was 50ms
  ```

- Reduce watched files:
  ```toml
  # Instead of watching entire directory
  targets = [
      { path = "/var/log/specific-app.log", is_file = true }
  ]
  ```

- Simplify filter patterns:
  ```toml
  # Complex regex (slow)
  patterns = ["^\\[\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\]\\s+\\[(ERROR|WARN)\\]"]
  
  # Simple patterns (fast)
  patterns = ["ERROR", "WARN"]
  ```

### Memory Growth

**Symptoms:**
- Increasing memory usage over time
- Eventually runs out of memory

**Diagnosis:**

1. Monitor memory usage:
   ```bash
   watch -n 10 'ps aux | grep logwisp'
   ```

2. Check connection count:
   ```bash
   curl -s http://localhost:8080/status | jq '.server.active_clients'
   ```

3. Check for dropped entries:
   ```bash
   curl -s http://localhost:8080/status | jq '.monitor.dropped_entries'
   ```

**Solutions:**

- Limit connections:
  ```toml
  [streams.httpserver.rate_limit]
  enabled = true
  max_connections_per_ip = 5
  max_total_connections = 100
  ```

- Reduce buffer sizes:
  ```toml
  [streams.httpserver]
  buffer_size = 500  # Was 5000
  ```

- Enable rate limiting:
  ```toml
  [streams.httpserver.rate_limit]
  enabled = true
  requests_per_second = 10.0
  ```

### Connection Refused

**Symptoms:**
- Cannot connect to LogWisp
- `curl: (7) Failed to connect`

**Diagnosis:**

1. Check if LogWisp is running:
   ```bash
   ps aux | grep logwisp
   systemctl status logwisp
   ```

2. Verify listening ports:
   ```bash
   sudo netstat -tlnp | grep logwisp
   # or
   sudo ss -tlnp | grep logwisp
   ```

3. Check firewall:
   ```bash
   sudo iptables -L -n | grep 8080
   sudo ufw status
   ```

**Solutions:**

- Start the service:
  ```bash
  sudo systemctl start logwisp
  ```

- Fix port configuration:
  ```toml
  [streams.httpserver]
  enabled = true  # Must be true
  port = 8080     # Correct port
  ```

- Open firewall:
  ```bash
  sudo ufw allow 8080/tcp
  ```

### Rate Limit Errors

**Symptoms:**
- HTTP 429 responses
- "Rate limit exceeded" errors

**Diagnosis:**

1. Check rate limit stats:
   ```bash
   curl -s http://localhost:8080/status | jq '.features.rate_limit'
   ```

2. Test rate limits:
   ```bash
   # Rapid requests
   for i in {1..20}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/status; done
   ```

**Solutions:**

- Increase rate limits:
  ```toml
  [streams.httpserver.rate_limit]
  requests_per_second = 50.0  # Was 10.0
  burst_size = 100            # Was 20
  ```

- Use per-IP limiting:
  ```toml
  limit_by = "ip"  # Instead of "global"
  ```

- Disable for internal use:
  ```toml
  enabled = false
  ```

### Filter Not Working

**Symptoms:**
- Unwanted logs still appearing
- Wanted logs being filtered out

**Diagnosis:**

1. Check filter configuration:
   ```bash
   curl -s http://localhost:8080/status | jq '.filters'
   ```

2. Test patterns:
   ```bash
   # Test regex pattern
   echo "ERROR: test message" | grep -E "your-pattern"
   ```

3. Enable debug logging to see filter decisions:
   ```bash
   logwisp --log-level debug 2>&1 | grep filter
   ```

**Solutions:**

- Fix pattern syntax:
  ```toml
  # Word boundaries
  patterns = ["\\bERROR\\b"]  # Not "ERROR" which matches "TERROR"
  
  # Case insensitive
  patterns = ["(?i)error"]
  ```

- Check filter order:
  ```toml
  # Include filters run first
  [[streams.filters]]
  type = "include"
  patterns = ["ERROR", "WARN"]
  
  # Then exclude filters
  [[streams.filters]]
  type = "exclude"
  patterns = ["IGNORE_THIS"]
  ```

- Use correct logic:
  ```toml
  logic = "or"   # Match ANY pattern
  # not
  logic = "and"  # Match ALL patterns
  ```

### Logs Dropping

**Symptoms:**
- `dropped_entries` counter increasing
- Missing log entries in stream

**Diagnosis:**

1. Check drop statistics:
   ```bash
   curl -s http://localhost:8080/status | jq '{
     dropped: .monitor.dropped_entries,
     total: .monitor.total_entries,
     percent: (.monitor.dropped_entries / .monitor.total_entries * 100)
   }'
   ```

2. Monitor drop rate:
   ```bash
   watch -n 5 'curl -s http://localhost:8080/status | jq .monitor.dropped_entries'
   ```

**Solutions:**

- Increase buffer sizes:
  ```toml
  [streams.httpserver]
  buffer_size = 5000  # Was 1000
  ```

- Add flow control:
  ```toml
  [streams.monitor]
  check_interval_ms = 500  # Slow down reading
  ```

- Reduce clients:
  ```toml
  [streams.httpserver.rate_limit]
  max_total_connections = 50
  ```

## Performance Issues

### Slow Response Times

**Diagnosis:**
```bash
# Measure response time
time curl -s http://localhost:8080/status > /dev/null

# Check system load
uptime
top
```

**Solutions:**
- Reduce concurrent operations
- Increase system resources
- Use TCP instead of HTTP for high volume

### Network Bandwidth

**Diagnosis:**
```bash
# Monitor network usage
iftop -i eth0 -f "port 8080"

# Check connection count
ss -tan | grep :8080 | wc -l
```

**Solutions:**
- Enable compression (future feature)
- Filter more aggressively
- Use TCP for local connections

## Debug Commands

### System Information

```bash
# LogWisp version
logwisp --version

# System resources
free -h
df -h
ulimit -a

# Network state
ss -tlnp
netstat -anp | grep logwisp
```

### Process Inspection

```bash
# Process details
ps aux | grep logwisp

# Open files
lsof -p $(pgrep logwisp)

# System calls (Linux)
strace -p $(pgrep logwisp) -e trace=open,read,write

# File system activity
inotifywait -m /var/log/myapp/
```

### Configuration Validation

```bash
# Test configuration
logwisp --config test.toml --log-level debug --log-output stderr

# Check file syntax
cat /etc/logwisp/logwisp.toml | grep -E "^\s*\["

# Validate TOML
python3 -m pip install toml
python3 -c "import toml; toml.load('/etc/logwisp/logwisp.toml'); print('Valid')"
```

## Getting Help

### Collect Diagnostic Information

Create a diagnostic bundle:

```bash
#!/bin/bash
# diagnostic.sh

DIAG_DIR="logwisp-diag-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIAG_DIR"

# Version
logwisp --version > "$DIAG_DIR/version.txt" 2>&1

# Configuration (sanitized)
grep -v "password\|secret\|token" /etc/logwisp/logwisp.toml > "$DIAG_DIR/config.toml"

# Status
curl -s http://localhost:8080/status > "$DIAG_DIR/status.json"

# System info
uname -a > "$DIAG_DIR/system.txt"
free -h >> "$DIAG_DIR/system.txt"
df -h >> "$DIAG_DIR/system.txt"

# Process info
ps aux | grep logwisp > "$DIAG_DIR/process.txt"
lsof -p $(pgrep logwisp) > "$DIAG_DIR/files.txt" 2>&1

# Recent logs
journalctl -u logwisp -n 1000 > "$DIAG_DIR/logs.txt" 2>&1

# Create archive
tar -czf "$DIAG_DIR.tar.gz" "$DIAG_DIR"
rm -rf "$DIAG_DIR"

echo "Diagnostic bundle created: $DIAG_DIR.tar.gz"
```

### Report Issues

When reporting issues, include:
1. LogWisp version
2. Configuration (sanitized)
3. Error messages
4. Steps to reproduce
5. Diagnostic bundle

## See Also

- [Monitoring Guide](monitoring.md) - Status and metrics
- [Performance Tuning](performance.md) - Optimization
- [Configuration Guide](configuration.md) - Settings reference
- [FAQ](faq.md) - Frequently asked questions