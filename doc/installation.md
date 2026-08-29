# Installation Guide

## Requirements

- **Operating systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go**: 1.26 or newer, to build from source

## Building from Source

```bash
git clone https://github.com/lixenwraith/logwisp.git
cd logwisp
make
sudo make install          # installs to $PREFIX/bin, default /usr/local/bin
```

The Makefile works with both GNU make and BSD make. Targets:

| Target | Effect |
|--------|--------|
| `make` / `make build` | Build `bin/logwisp` with version metadata |
| `make dev` | Build with the race detector enabled |
| `make install` | Install the binary to `$(PREFIX)/bin` (default `/usr/local`) |
| `make uninstall` | Intended to remove the installed binary — currently broken: it expands to `$(BINDIR)/bin/logwisp` instead of `$(BINDIR)/logwisp`, so it removes nothing. Delete the binary by hand |
| `make clean` | Remove the built binary |
| `make version` | Print the version, commit, and build time that would be embedded |

Version, commit hash, and build time are injected via `-ldflags` from `git
describe` and `git rev-parse`. A plain `go build` produces a working binary that
reports `dev` for all three:

```bash
go build -o bin/logwisp ./cmd/logwisp
```

`go install github.com/lixenwraith/logwisp/cmd/logwisp@latest` also works, with
the same loss of version metadata.

## Configuration

Copy the annotated reference configuration and edit it:

```bash
sudo mkdir -p /etc/logwisp
sudo cp config/logwisp.toml /etc/logwisp/logwisp.toml
```

LogWisp searches, in order: `-c <path>`, `--config=<path>`,
`$LOGWISP_CONFIG_DIR`/`$LOGWISP_CONFIG_FILE`, `~/.config/logwisp/logwisp.toml`,
`./logwisp.toml`. See [Configuration](configuration.md).

## Running as a Service

LogWisp has no daemon mode; run it in the foreground under a supervisor.

### Linux (systemd)

`/etc/systemd/system/logwisp.service`:

```ini
[Unit]
Description=LogWisp Log Transport Service
After=network.target

[Service]
Type=simple
User=logwisp
Group=logwisp
ExecStart=/usr/local/bin/logwisp -c /etc/logwisp/logwisp.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
WorkingDirectory=/var/lib/logwisp
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/logwisp /var/lib/logwisp

[Install]
WantedBy=multi-user.target
```

`ExecReload` gives you `systemctl reload logwisp` for configuration and
certificate rotation without dropping the process.

If a pipeline binds a port below 1024, add
`AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than running as root.

Setup:

```bash
sudo useradd -r -s /usr/sbin/nologin logwisp
sudo mkdir -p /etc/logwisp /var/lib/logwisp /var/log/logwisp
sudo chown logwisp:logwisp /var/lib/logwisp /var/log/logwisp
sudo systemctl daemon-reload
sudo systemctl enable --now logwisp
```

The service account needs **read** access to every directory a `file` source
watches and **write** access to every directory a `file` sink or
`logging.file` writes to.

### FreeBSD (rc.d)

`/usr/local/etc/rc.d/logwisp`:

```sh
#!/bin/sh

# PROVIDE: logwisp
# REQUIRE: DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="logwisp"
rcvar="${name}_enable"
pidfile="/var/run/${name}.pid"
procname="/usr/local/bin/logwisp"
command="/usr/sbin/daemon"
command_args="-p ${pidfile} -f ${procname} -c /usr/local/etc/logwisp/logwisp.toml"

load_rc_config $name
: ${logwisp_enable:="NO"}

run_rc_command "$1"
```

Setup:

```bash
sudo chmod +x /usr/local/etc/rc.d/logwisp
sudo pw useradd logwisp -d /nonexistent -s /usr/sbin/nologin
sudo mkdir -p /usr/local/etc/logwisp /var/log/logwisp
sudo chown logwisp:logwisp /var/log/logwisp
sudo sysrc logwisp_enable="YES"
sudo service logwisp start
```

## Directory Layout

| Purpose | Linux | FreeBSD |
|---------|-------|---------|
| Binary | `/usr/local/bin/logwisp` | `/usr/local/bin/logwisp` |
| Configuration | `/etc/logwisp/` | `/usr/local/etc/logwisp/` |
| TLS material | `/etc/logwisp/tls/` | `/usr/local/etc/logwisp/tls/` |
| Working directory | `/var/lib/logwisp/` | `/var/db/logwisp/` |
| Application logs | `/var/log/logwisp/` | `/var/log/logwisp/` |

Key files should be mode `0600` and owned by the service account.

## Verification

```bash
logwisp --version

# start in the foreground with debug logging and watch pipelines come up
logwisp -c /etc/logwisp/logwisp.toml --logging.level=debug --logging.output=stderr

sudo systemctl status logwisp      # Linux
sudo service logwisp status        # FreeBSD
```

Expect `Created source instance`, `Created sink instance`, and
`Starting pipeline` for each configured pipeline. There is no validate-only
mode; see [Operations](operations.md#checking-a-configuration).

## Test Scripts

Two end-to-end scripts under `test/` build multi-node chain topologies against a
local build:

```bash
make
./test/chain-test.sh --auto             # two independent relay pipelines
./test/chain-aggregate-test.sh --auto   # fan-in: both edges into one pipeline
```

Without `--auto` they run the relay in the foreground for interactive
inspection. They need bash 5+, coreutils, and curl, and they bind ports
15801–15804. Generated configuration and logs land in `test/run/`.

> Two of the three `--auto` assertions currently report `FAIL` against a
> working build. They grep the sink output for `"source":"edge-tcp/` and
> `"node":"edge-http"`, but the JSON formatter emits the `node/source` label
> under the key `trace`. The transport itself is healthy — the
> `total_processed` assertion passes and the streamed entries carry
> `"trace":"edge-tcp/random_rand"` as expected. Until the assertions are
> updated, verify the streams by eye with `nc 127.0.0.1 15803` and
> `curl -sN http://127.0.0.1:15804/stream`.

## Uninstall

### Linux

```bash
sudo systemctl disable --now logwisp
sudo rm /usr/local/bin/logwisp /etc/systemd/system/logwisp.service
sudo systemctl daemon-reload
sudo rm -rf /etc/logwisp /var/lib/logwisp /var/log/logwisp
sudo userdel logwisp
```

### FreeBSD

```bash
sudo service logwisp stop
sudo sysrc -x logwisp_enable
sudo rm /usr/local/bin/logwisp /usr/local/etc/rc.d/logwisp
sudo rm -rf /usr/local/etc/logwisp /var/db/logwisp /var/log/logwisp
sudo pw userdel logwisp
```
