# Installation Guide

LogWisp installation and service configuration for Linux and FreeBSD systems.

## Installation Methods

### Pre-built Binaries

Download the latest release binary for your platform and install to `/usr/local/bin`:

```bash
# Linux amd64
wget https://github.com/yourusername/logwisp/releases/latest/download/logwisp-linux-amd64
chmod +x logwisp-linux-amd64
sudo mv logwisp-linux-amd64 /usr/local/bin/logwisp

# FreeBSD amd64  
fetch https://github.com/yourusername/logwisp/releases/latest/download/logwisp-freebsd-amd64
chmod +x logwisp-freebsd-amd64
sudo mv logwisp-freebsd-amd64 /usr/local/bin/logwisp
```

### Building from Source

Requires Go 1.24 or newer:

```bash
git clone https://github.com/yourusername/logwisp.git
cd logwisp
go build -o logwisp ./src/cmd/logwisp
sudo install -m 755 logwisp /usr/local/bin/
```

### Go Install Method

Install directly using Go (version information will not be embedded):

```bash
go install github.com/yourusername/logwisp/src/cmd/logwisp@latest
```

## Service Configuration

### Linux (systemd)

Create systemd service file `/etc/systemd/system/logwisp.service`:

```ini
[Unit]
Description=LogWisp Log Transport Service
After=network.target

[Service]
Type=simple
User=logwisp
Group=logwisp
ExecStart=/usr/local/bin/logwisp -c /etc/logwisp/logwisp.toml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
WorkingDirectory=/var/lib/logwisp

[Install]
WantedBy=multi-user.target
```

Setup service user and directories:

```bash
sudo useradd -r -s /bin/false logwisp
sudo mkdir -p /etc/logwisp /var/lib/logwisp /var/log/logwisp
sudo chown logwisp:logwisp /var/lib/logwisp /var/log/logwisp
sudo systemctl daemon-reload
sudo systemctl enable logwisp
sudo systemctl start logwisp
```

### FreeBSD (rc.d)

Create rc script `/usr/local/etc/rc.d/logwisp`:

```sh
#!/bin/sh

# PROVIDE: logwisp
# REQUIRE: DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="logwisp"
rcvar="${name}_enable"
pidfile="/var/run/${name}.pid"
command="/usr/local/bin/logwisp"
command_args="-c /usr/local/etc/logwisp/logwisp.toml"

load_rc_config $name
: ${logwisp_enable:="NO"}

run_rc_command "$1"
```

Setup service:

```bash
sudo chmod +x /usr/local/etc/rc.d/logwisp
sudo pw useradd logwisp -d /nonexistent -s /usr/sbin/nologin
sudo mkdir -p /usr/local/etc/logwisp /var/log/logwisp
sudo chown logwisp:logwisp /var/log/logwisp
sudo sysrc logwisp_enable="YES"
sudo service logwisp start
```

## Directory Structure

Standard installation directories:

| Purpose | Linux | FreeBSD |
|---------|-------|---------|
| Binary | `/usr/local/bin/logwisp` | `/usr/local/bin/logwisp` |
| Configuration | `/etc/logwisp/` | `/usr/local/etc/logwisp/` |
| Working Directory | `/var/lib/logwisp/` | `/var/db/logwisp/` |
| Log Files | `/var/log/logwisp/` | `/var/log/logwisp/` |
| PID File | `/var/run/logwisp.pid` | `/var/run/logwisp.pid` |

## Post-Installation Verification

Verify the installation:

```bash
# Check version
logwisp version

# Test configuration
logwisp -c /etc/logwisp/logwisp.toml --disable-status-reporter

# Check service status (Linux)
sudo systemctl status logwisp

# Check service status (FreeBSD)
sudo service logwisp status
```

## Uninstallation

### Linux

```bash
sudo systemctl stop logwisp
sudo systemctl disable logwisp
sudo rm /usr/local/bin/logwisp
sudo rm /etc/systemd/system/logwisp.service
sudo rm -rf /etc/logwisp /var/lib/logwisp /var/log/logwisp
sudo userdel logwisp
```

### FreeBSD

```bash
sudo service logwisp stop
sudo sysrc -x logwisp_enable
sudo rm /usr/local/bin/logwisp
sudo rm /usr/local/etc/rc.d/logwisp
sudo rm -rf /usr/local/etc/logwisp /var/db/logwisp /var/log/logwisp
sudo pw userdel logwisp
```