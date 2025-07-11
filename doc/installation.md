# Installation Guide

Installation process on tested platforms.

## Requirements

- **OS**: Linux, FreeBSD
- **Architecture**: amd64
- **Go**: 1.23+ (for building)

## Installation

### Pre-built Binaries

```bash
# Linux amd64
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-linux-amd64
chmod +x logwisp-linux-amd64
sudo mv logwisp-linux-amd64 /usr/local/bin/logwisp

# macOS Intel
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-darwin-amd64
chmod +x logwisp-darwin-amd64
sudo mv logwisp-darwin-amd64 /usr/local/bin/logwisp

# Verify
logwisp --version
```

### From Source

```bash
git clone https://github.com/yourusername/logwisp.git
cd logwisp
make build
sudo make install
```

### Go Install

```bash
go install github.com/lixenwraith/logwisp/src/cmd/logwisp@latest
```
Note: Binary created with this method will not contain version information.

## Platform-Specific

### Linux (systemd)

```bash
# Create service
sudo tee /etc/systemd/system/logwisp.service << EOF
[Unit]
Description=LogWisp Log Monitoring Service
After=network.target

[Service]
Type=simple
User=logwisp
ExecStart=/usr/local/bin/logwisp --config /etc/logwisp/logwisp.toml
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create user
sudo useradd -r -s /bin/false logwisp

# Create service user
sudo useradd -r -s /bin/false logwisp

# Create configuration directory
sudo mkdir -p /etc/logwisp
sudo chown logwisp:logwisp /etc/logwisp

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable logwisp
sudo systemctl start logwisp
```

### FreeBSD (rc.d)

```bash
# Create service script
sudo tee /usr/local/etc/rc.d/logwisp << 'EOF'
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
start_cmd="logwisp_start"
stop_cmd="logwisp_stop"

logwisp_start()
{
    echo "Starting logwisp service..."
    /usr/sbin/daemon -c -f -p ${pidfile} ${command} ${command_args}
}

logwisp_stop()
{
    if [ -f ${pidfile} ]; then
        echo "Stopping logwisp service..."
        kill $(cat ${pidfile})
        rm -f ${pidfile}
    fi
}

load_rc_config $name
: ${logwisp_enable:="NO"}
: ${logwisp_config:="/usr/local/etc/logwisp/logwisp.toml"}

run_rc_command "$1"
EOF

# Make executable
sudo chmod +x /usr/local/etc/rc.d/logwisp

# Create service user
sudo pw useradd logwisp -d /nonexistent -s /usr/sbin/nologin

# Create configuration directory
sudo mkdir -p /usr/local/etc/logwisp
sudo chown logwisp:logwisp /usr/local/etc/logwisp

# Enable service
sudo sysrc logwisp_enable="YES"

# Start service
sudo service logwisp start
```

## Post-Installation

### Verify Installation
```bash
# Check version
logwisp --version

# Test configuration
logwisp --config /etc/logwisp/logwisp.toml --log-level debug

# Check service
sudo systemctl status logwisp
```

### Linux Service Status
```bash
sudo systemctl status logwisp
```

### FreeBSD Service Status
```bash
sudo service logwisp status
```

### Initial Configuration

Create a basic configuration file:

```toml
# /etc/logwisp/logwisp.toml (Linux)
# /usr/local/etc/logwisp/logwisp.toml (FreeBSD)

[[pipelines]]
name = "myapp"

[[pipelines.sources]]
type = "directory"
options = { 
    path = "/path/to/application/logs",
    pattern = "*.log"
}

[[pipelines.sinks]]
type = "http"
options = { port = 8080 }
```

Restart service after configuration changes:

**Linux:**
```bash
sudo systemctl restart logwisp
```

**FreeBSD:**
```bash
sudo service logwisp restart
```

## Uninstallation

### Linux
```bash
sudo systemctl stop logwisp
sudo systemctl disable logwisp
sudo rm /usr/local/bin/logwisp
sudo rm /etc/systemd/system/logwisp.service
sudo rm -rf /etc/logwisp
sudo userdel logwisp
```

### FreeBSD
```bash
sudo service logwisp stop
sudo sysrc logwisp_enable="NO"
sudo rm /usr/local/bin/logwisp
sudo rm /usr/local/etc/rc.d/logwisp
sudo rm -rf /usr/local/etc/logwisp
sudo pw userdel logwisp
```