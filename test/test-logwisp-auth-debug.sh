#!/usr/bin/env bash
# FILE: test-logwisp-auth-debug.sh

# Creates test directories and starts network services
set -e

# Create test directories
mkdir -p test-logs test-data

# Generate Argon2id hash using logwisp auth
echo "=== Generating Argon2id hash ==="
./logwisp auth -u testuser -p secret123 > auth_output.txt 2>&1
HASH=$(grep 'password_hash = ' auth_output.txt | cut -d'"' -f2)
if [ -z "$HASH" ]; then
    echo "Failed to generate hash. Output:"
    cat auth_output.txt
    exit 1
fi
echo "Generated hash format: ${HASH:0:15}..."  # Show hash format prefix
echo "Full hash: $HASH"

# Determine hash type
if [[ "$HASH" == "\$argon2id\$"* ]]; then
    echo "Hash type: Argon2id"
elif [[ "$HASH" == "\$2a\$"* ]] || [[ "$HASH" == "\$2b\$"* ]]; then
    echo "Hash type: bcrypt"
else
    echo "Hash type: Unknown"
fi

# Create test config with debug logging to stdout
cat > test-auth.toml << EOF
# General LogWisp settings
log_dir = "test-logs"
log_level = "debug"  # CHANGED: Set to debug
data_dir = "test-data"

# Logging configuration for troubleshooting
[logging]
target = "all"
level = "debug"
[logging.console]
enabled = true
target = "stdout"  # CHANGED: Log to stdout for visibility
format = "txt"

[[pipelines]]
name = "tcp-test"
[pipelines.auth]
type = "basic"
[[pipelines.auth.basic_auth.users]]
username = "testuser"
password_hash = "$HASH"

[[pipelines.sources]]
type = "tcp"
[pipelines.sources.options]
port = 5514
host = "127.0.0.1"

[[pipelines.sinks]]
type = "stdout"

# Second pipeline for HTTP
[[pipelines]]
name = "http-test"
[pipelines.auth]
type = "basic"
[[pipelines.auth.basic_auth.users]]
username = "httpuser"
password_hash = "$HASH"

[[pipelines.sources]]
type = "http"
[pipelines.sources.options]
port = 8080
host = "127.0.0.1"
path = "/ingest"

[[pipelines.sinks]]
type = "stdout"  # CHANGED: Simplify to stdout for debugging
EOF

# Start LogWisp with visible debug output
echo "=== Starting LogWisp with debug logging ==="
./logwisp -c test-auth.toml 2>&1 | tee logwisp-debug.log &
LOGWISP_PID=$!

# Wait for startup with longer timeout
echo "Waiting for LogWisp to start..."
for i in {1..20}; do
    if nc -z 127.0.0.1 5514 2>/dev/null && nc -z 127.0.0.1 8080 2>/dev/null; then
        echo "LogWisp started successfully"
        break
    fi
    if [ $i -eq 20 ]; then
        echo "LogWisp failed to start. Check logwisp-debug.log"
        kill $LOGWISP_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Give extra time for auth initialization
sleep 2

echo "=== Testing HTTP Auth ==="

# Test with verbose curl to see headers
echo "Testing no auth (expecting 401)..."
curl -v -s -o response.txt -w "STATUS:%{http_code}\n" \
    http://127.0.0.1:8080/ingest -d '{"test":"data"}' 2>&1 | tee curl-noauth.log | grep -E "STATUS:|< HTTP"

# Test invalid auth
echo "Testing invalid auth (expecting 401)..."
curl -v -s -o response.txt -w "STATUS:%{http_code}\n" \
    -u baduser:badpass http://127.0.0.1:8080/ingest -d '{"test":"data"}' 2>&1 | tee curl-badauth.log | grep -E "STATUS:|< HTTP"

# Test valid auth with detailed output
echo "Testing valid auth (expecting 202/200)..."
curl -v -s -o response.txt -w "STATUS:%{http_code}\n" \
    -u httpuser:secret123 http://127.0.0.1:8080/ingest \
    -H "Content-Type: application/json" \
    -d '{"message":"test log","level":"info"}' 2>&1 | tee curl-validauth.log | grep -E "STATUS:|< HTTP"

# Show response body if not 200/202
STATUS=$(grep "STATUS:" curl-validauth.log | cut -d: -f2)
if [ "$STATUS" != "200" ] && [ "$STATUS" != "202" ]; then
    echo "Response body:"
    cat response.txt
fi

# Check logs for auth-related errors
echo "=== Checking logs for auth errors ==="
grep -i "auth" logwisp-debug.log | grep -i "error" | tail -5 || echo "No auth errors found"
grep -i "authenticator" logwisp-debug.log | tail -5 || echo "No authenticator messages"

# Cleanup
echo "=== Cleanup ==="
kill $LOGWISP_PID 2>/dev/null || true
echo "Logs saved to logwisp-debug.log, curl-*.log"
# Optionally keep logs for analysis
# rm -f test-auth.toml auth_output.txt response.txt
# rm -rf test-logs test-data
