# Installation Guide

This guide covers installing LogWisp on various platforms and deployment scenarios.

## Requirements

### System Requirements

- **OS**: Linux, macOS, FreeBSD, Windows (with WSL)
- **Architecture**: amd64, arm64
- **Memory**: 64MB minimum, 256MB recommended
- **Disk**: 10MB for binary, plus log storage
- **Go**: 1.23+ (for building from source)

### Runtime Dependencies

LogWisp is a single static binary with no runtime dependencies. It only requires:
- Read access to monitored log files
- Network access for serving streams
- Write access for operational logs (optional)

## Installation Methods

### Pre-built Binaries

Download the latest release:

```bash
# Linux (amd64)
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-linux-amd64
chmod +x logwisp-linux-amd64
sudo mv logwisp-linux-amd64 /usr/local/bin/logwisp

# macOS (Intel)
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-darwin-amd64
chmod +x logwisp-darwin-amd64
sudo mv logwisp-darwin-amd64 /usr/local/bin/logwisp

# macOS (Apple Silicon)
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-darwin-arm64
chmod +x logwisp-darwin-arm64
sudo mv logwisp-darwin-arm64 /usr/local/bin/logwisp
```

Verify installation:
```bash
logwisp --version
```

### From Source

Build from source code:

```bash
# Clone repository
git clone https://github.com/yourusername/logwisp.git
cd logwisp

# Build
make build

# Install
sudo make install

# Or install to custom location
make install PREFIX=/opt/logwisp
```

### Using Go Install

Install directly with Go:

```bash
go install github.com/yourusername/logwisp/src/cmd/logwisp@latest
```

Note: This installs to `$GOPATH/bin` (usually `~/go/bin`)

### Docker

Official Docker image:

```bash
# Pull image
docker pull yourusername/logwisp:latest

# Run with volume mount
docker run -d \
  --name logwisp \
  -p 8080:8080 \
  -v /var/log:/logs:ro \
  -v $PWD/config.toml:/config/logwisp.toml:ro \
  yourusername/logwisp:latest \
  --config /config/logwisp.toml
```

Build your own image:

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o logwisp ./src/cmd/logwisp

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/logwisp /usr/local/bin/
ENTRYPOINT ["logwisp"]
```

## Platform-Specific Instructions

### Linux

#### Debian/Ubuntu

Create package (planned):
```bash
# Future feature
sudo apt install logwisp
```

Manual installation:
```bash
# Download binary
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-linux-amd64 -O logwisp
chmod +x logwisp
sudo mv logwisp /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/logwisp
sudo cp config/logwisp.toml.example /etc/logwisp/logwisp.toml

# Create systemd service
sudo tee /etc/systemd/system/logwisp.service << EOF
[Unit]
Description=LogWisp Log Monitoring Service
After=network.target

[Service]
Type=simple
User=logwisp
Group=logwisp
ExecStart=/usr/local/bin/logwisp --config /etc/logwisp/logwisp.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=logwisp

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/var/log
ReadWritePaths=/var/log/logwisp

[Install]
WantedBy=multi-user.target
EOF

# Create user
sudo useradd -r -s /bin/false logwisp

# Create log directory
sudo mkdir -p /var/log/logwisp
sudo chown logwisp:logwisp /var/log/logwisp

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable logwisp
sudo systemctl start logwisp
```

#### Red Hat/CentOS/Fedora

```bash
# Similar to Debian, but use:
sudo yum install wget  # or dnf on newer versions

# SELinux context (if enabled)
sudo semanage fcontext -a -t bin_t /usr/local/bin/logwisp
sudo restorecon -v /usr/local/bin/logwisp
```

#### Arch Linux

AUR package (community maintained):
```bash
# Future feature
yay -S logwisp
```

### macOS

#### Homebrew

Formula (planned):
```bash
# Future feature
brew install logwisp
```

#### Manual Installation

```bash
# Download and install
curl -L https://github.com/yourusername/logwisp/releases/latest/download/logwisp-darwin-$(uname -m) -o logwisp
chmod +x logwisp
sudo mv logwisp /usr/local/bin/

# Create LaunchDaemon
sudo tee /Library/LaunchDaemons/com.logwisp.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.logwisp</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/logwisp</string>
        <string>--config</string>
        <string>/usr/local/etc/logwisp/logwisp.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/logwisp.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/logwisp.error.log</string>
</dict>
</plist>
EOF

# Load service
sudo launchctl load /Library/LaunchDaemons/com.logwisp.plist
```

### FreeBSD

#### Ports

```bash
# Future feature
cd /usr/ports/sysutils/logwisp
make install clean
```

#### Manual Installation

```bash
# Download
fetch https://github.com/yourusername/logwisp/releases/latest/download/logwisp-freebsd-amd64
chmod +x logwisp-freebsd-amd64
mv logwisp-freebsd-amd64 /usr/local/bin/logwisp

# RC script
cat > /usr/local/etc/rc.d/logwisp << 'EOF'
#!/bin/sh

# PROVIDE: logwisp
# REQUIRE: DAEMON
# KEYWORD: shutdown

. /etc/rc.subr

name="logwisp"
rcvar="${name}_enable"
command="/usr/local/bin/logwisp"
command_args="--config /usr/local/etc/logwisp/logwisp.toml"
pidfile="/var/run/${name}.pid"

load_rc_config $name
: ${logwisp_enable:="NO"}

run_rc_command "$1"
EOF

chmod +x /usr/local/etc/rc.d/logwisp

# Enable
sysrc logwisp_enable="YES"
service logwisp start
```

### Windows

#### Windows Subsystem for Linux (WSL)

```bash
# Inside WSL, follow Linux instructions
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-linux-amd64
chmod +x logwisp-linux-amd64
./logwisp-linux-amd64
```

#### Native Windows (planned)

Future support for native Windows service.

## Container Deployment

### Docker Compose

```yaml
version: '3.8'

services:
  logwisp:
    image: yourusername/logwisp:latest
    container_name: logwisp
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"  # If using TCP
    volumes:
      - /var/log:/logs:ro
      - ./logwisp.toml:/config/logwisp.toml:ro
    command: ["--config", "/config/logwisp.toml"]
    environment:
      - LOGWISP_LOGGING_LEVEL=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/status"]
      interval: 30s
      timeout: 3s
      retries: 3
```

### Kubernetes

Deployment manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: logwisp
  labels:
    app: logwisp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: logwisp
  template:
    metadata:
      labels:
        app: logwisp
    spec:
      containers:
      - name: logwisp
        image: yourusername/logwisp:latest
        args:
          - --config
          - /config/logwisp.toml
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: tcp
        volumeMounts:
        - name: logs
          mountPath: /logs
          readOnly: true
        - name: config
          mountPath: /config
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
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: logs
        hostPath:
          path: /var/log
      - name: config
        configMap:
          name: logwisp-config
---
apiVersion: v1
kind: Service
metadata:
  name: logwisp
spec:
  selector:
    app: logwisp
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: tcp
    port: 9090
    targetPort: 9090
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: logwisp-config
data:
  logwisp.toml: |
    [[streams]]
    name = "k8s"
    [streams.monitor]
    targets = [{ path = "/logs", pattern = "*.log" }]
    [streams.httpserver]
    enabled = true
    port = 8080
```

## Post-Installation

### Verify Installation

1. Check version:
   ```bash
   logwisp --version
   ```

2. Test configuration:
   ```bash
   logwisp --config /etc/logwisp/logwisp.toml --log-level debug
   ```

3. Check service status:
   ```bash
   # systemd
   sudo systemctl status logwisp
   
   # macOS
   sudo launchctl list | grep logwisp
   
   # FreeBSD
   service logwisp status
   ```

4. Test streaming:
   ```bash
   curl -N http://localhost:8080/stream
   ```

### Security Hardening

1. **Create dedicated user**:
   ```bash
   sudo useradd -r -s /bin/false -d /var/lib/logwisp logwisp
   ```

2. **Set file permissions**:
   ```bash
   sudo chown root:root /usr/local/bin/logwisp
   sudo chmod 755 /usr/local/bin/logwisp
   sudo chown -R logwisp:logwisp /etc/logwisp
   sudo chmod 640 /etc/logwisp/logwisp.toml
   ```

3. **Configure firewall**:
   ```bash
   # UFW
   sudo ufw allow 8080/tcp comment "LogWisp HTTP"
   
   # firewalld
   sudo firewall-cmd --permanent --add-port=8080/tcp
   sudo firewall-cmd --reload
   ```

4. **Enable SELinux/AppArmor** (if applicable)

### Initial Configuration

1. Copy example configuration:
   ```bash
   sudo cp /usr/local/share/logwisp/examples/logwisp.toml.example /etc/logwisp/logwisp.toml
   ```

2. Edit configuration:
   ```bash
   sudo nano /etc/logwisp/logwisp.toml
   ```

3. Set up log monitoring:
   ```toml
   [[streams]]
   name = "myapp"
   [streams.monitor]
   targets = [
       { path = "/var/log/myapp", pattern = "*.log" }
   ]
   ```

4. Restart service:
   ```bash
   sudo systemctl restart logwisp
   ```

## Uninstallation

### Linux
```bash
# Stop service
sudo systemctl stop logwisp
sudo systemctl disable logwisp

# Remove files
sudo rm /usr/local/bin/logwisp
sudo rm /etc/systemd/system/logwisp.service
sudo rm -rf /etc/logwisp
sudo rm -rf /var/log/logwisp

# Remove user
sudo userdel logwisp
```

### macOS
```bash
# Stop service
sudo launchctl unload /Library/LaunchDaemons/com.logwisp.plist

# Remove files
sudo rm /usr/local/bin/logwisp
sudo rm /Library/LaunchDaemons/com.logwisp.plist
sudo rm -rf /usr/local/etc/logwisp
```

### Docker
```bash
docker stop logwisp
docker rm logwisp
docker rmi yourusername/logwisp:latest
```

## Troubleshooting Installation

### Permission Denied

If you get permission errors:
```bash
# Check file ownership
ls -la /usr/local/bin/logwisp

# Fix permissions
sudo chmod +x /usr/local/bin/logwisp

# Check log directory
sudo mkdir -p /var/log/logwisp
sudo chown logwisp:logwisp /var/log/logwisp
```

### Service Won't Start

Check logs:
```bash
# systemd
sudo journalctl -u logwisp -f

# Manual run
sudo -u logwisp /usr/local/bin/logwisp --config /etc/logwisp/logwisp.toml
```

### Port Already in Use

Find conflicting process:
```bash
sudo lsof -i :8080
# or
sudo netstat -tlnp | grep 8080
```

## See Also

- [Quick Start](quickstart.md) - Get running quickly
- [Configuration Guide](configuration.md) - Configure LogWisp
- [Troubleshooting](troubleshooting.md) - Common issues
- [Security Best Practices](security.md) - Hardening guide