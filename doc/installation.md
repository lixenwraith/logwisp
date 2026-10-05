# Installation Guide

## Requirements

- Operating systems: Linux (kernel 6.10+), FreeBSD (14.0+)
- Architecture: amd64; arm64 builds but is untested
- To build: Go 1.27.1 or newer (FreeBSD: the `go127` package), and GNU make
  or BSD make
- For `make e2e`: bash 5+, coreutils, curl, openssl and go (the proxy test
  builds its reverse proxy). Optional, else those checks SKIP: node with
  playwright and the Chromium builds `playwright install chromium` fetches
  (browser checks), an IPv6 loopback (`ipv6-test.sh`), docker as root with the
  `logwisp:dev` image (`deploy-test.sh`'s container run)

## Building from Source

```bash
git clone https://github.com/lixenwraith/logwisp.git
cd logwisp
make build              # bin/lw; plain `make` only lists the targets
```

The Makefile works with GNU make and BSD make alike. Targets:

- Build
  - `make build`: `bin/lw`, with version, commit and build time from git
  - `make release`: the same, static (`CGO_ENABLED=0`), `-trimpath`, stripped
  - `make dev`: built with the race detector
  - `make version`: the metadata a build would embed
  - `make clean`: remove `bin/`
- Check
  - `make test`: the Go tests
  - `make verify`: tests, `go vet`, `gofmt -l` on the Go files changed since
    `main`, linux and freebsd cross builds for amd64 and arm64, and the web
    client's `node --test` when node is installed
  - `make e2e`: builds, then runs every `test/*-test.sh --auto` in turn and
    reports passes, failures and skips; `E2E='test/scram-*-test.sh'` runs a
    subset; see [Test Scripts](#test-scripts)
- Container
  - `make image`, `make image-check`: see [Container Image](#container-image)
- Install
  - `make install`, `make uninstall`: see [Installing](#installing)

Variables:

- `GO`: the toolchain. On FreeBSD the default is the versioned package that
  `go.mod` asks for (`go127`); `make GO=/path/to/go` overrides it, and
  `check-go` names the package to install when it is missing.
- `GO_BUILDFLAGS`, `GO_LDFLAGS`: extra `go build` and linker flags for
  packagers. They are distinct from `GOFLAGS` and `LDFLAGS`, which the go
  command and the C linker read themselves.
- `SOURCE_DATE_EPOCH`: when set, the embedded build time comes from it, so
  package builds are reproducible.

A plain `go build -o bin/lw ./cmd/lw` works too, as does
`go install github.com/lixenwraith/logwisp/cmd/lw@latest` (or `@vX.Y.Z`).
Without the Makefile's `-ldflags`, `lw --version` reports what Go stamps into
the binary: the module version, or a pseudo-version with the commit in a
checkout.

## Installing

`make install` copies what a package ships and compiles nothing, so build
first. It honours `DESTDIR`, `PREFIX`, `SYSCONFDIR` and `BINDIR` (default
`$PREFIX/bin`, the path the systemd unit and the rc.d script run `lw` from):

- Linux defaults: `PREFIX=/usr`, `SYSCONFDIR=/etc`. Outside a package
  manager, prefer `PREFIX=/usr/local`; systemd reads units, sysusers and
  tmpfiles from there too.
- FreeBSD defaults: `PREFIX=/usr/local`, `SYSCONFDIR=/usr/local/etc`.
- `INSTALL_OS` (default: `uname -s`) picks the layout, so
  `INSTALL_OS=FreeBSD DESTDIR=...` stages the FreeBSD one on another system.

```bash
make release
sudo make install PREFIX=/usr/local
```

Every system gets:

- `$BINDIR/lw` and the manual `$PREFIX/share/man/man1/lw.1`
- `$PREFIX/share/doc/logwisp/` (this documentation) and
  `$PREFIX/share/licenses/logwisp/LICENSE`

### Linux (systemd)

- `$SYSCONFDIR/logwisp/logwisp.toml`: the annotated sample configuration,
  kept when one is already there. Edit it before starting the service.
- `$PREFIX/lib/systemd/system/logwisp.service`: runs
  `lw -c $SYSCONFDIR/logwisp/logwisp.toml` as the `logwisp` user, from
  `/var/lib/logwisp`; `systemctl reload` sends `SIGHUP`.
- `$PREFIX/lib/sysusers.d/logwisp.conf`: the `logwisp` account.
- `$PREFIX/lib/tmpfiles.d/logwisp.conf`: `/var/lib/logwisp` and
  `/var/log/logwisp`, owned by it.

```bash
sudo systemd-sysusers logwisp.conf
sudo systemd-tmpfiles --create logwisp.conf
sudo systemctl daemon-reload
sudo systemctl enable --now logwisp
```

The unit is hardened: no capabilities, a read-only view of the system with
only its two directories writable, `/home` hidden, and IPv4, IPv6 and Unix
sockets only. Widen it with a drop-in (`systemctl edit logwisp`) rather than
editing the unit:

- A `file` sink or `logging.file` elsewhere: `ReadWritePaths=/srv/logs`
- A `file` source under `/home`: `ProtectHome=read-only`
- A port below 1024: `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and
  `AmbientCapabilities=CAP_NET_BIND_SERVICE`

The service must read every key, credentials and password file it names.
Create a credentials file with its owner and mode first; `lw auth` keeps
both:

```bash
sudo install -m 0600 -o logwisp -g logwisp /dev/null /etc/logwisp/users.toml
sudo lw auth add-user --credentials /etc/logwisp/users.toml --user <name> \
  --password-file <file>
sudo systemctl reload logwisp
```

### FreeBSD (rc.d)

- `$SYSCONFDIR/logwisp/logwisp.toml.sample`, copied to `logwisp.toml` when
  none exists and `DESTDIR` is empty
- `$PREFIX/etc/rc.d/logwisp`: runs `lw` through `daemon(8)` as
  `logwisp_user`, with its output in syslog under the tag `logwisp`;
  `service logwisp reload` sends `SIGHUP`

```bash
sudo pw useradd logwisp -d /nonexistent -s /usr/sbin/nologin -c "LogWisp log transport"
sudo sysrc logwisp_enable=YES
sudo service logwisp start
```

rc.conf variables:

- `logwisp_enable`: `YES` to start at boot (default `NO`)
- `logwisp_config`: the configuration (default
  `/usr/local/etc/logwisp/logwisp.toml`)
- `logwisp_user`: the account (default `logwisp`)
- `logwisp_chdir`: the working directory (default `/var/db/logwisp`, created
  for `logwisp_user` when missing)
- `logwisp_args`: extra `lw` options, e.g. `--logging.level=debug` (default
  empty); `logwisp_flags` goes to `daemon(8)`, not to `lw`

### Uninstall

`sudo make uninstall` (with the `PREFIX` used to install) removes everything
`make install` wrote except `$SYSCONFDIR/logwisp`, which holds configuration
and credentials. Remove that, the working directories and the account by
hand.

## Container Image

The `Dockerfile` builds `lw` in a Go builder and copies it alone, static and
stripped, into `scratch`: `/lw` running as UID 65532, plus the CA bundle that
TLS dialers without a `ca_file` verify against. There is no shell and no
configuration in the image.

```bash
make image                    # logwisp:dev; IMAGE=, IMAGE_TAG= rename it
make image-check
```

`image-check` runs the image the way it should run in production: read-only,
`--network none`, `--cap-drop ALL`, `no-new-privileges`, as 65532. It prints
`--version`, then runs `--check` on `config/logwisp.toml` (or
`IMAGE_CHECK_CONFIG`) mounted read-only.

Building behind a proxy:

- A TLS-intercepting proxy: `make image BUILD_CA=/path/to/ca-bundle.pem`.
  The bundle reaches only the module download, as a BuildKit secret.
- An explicit proxy: pass Docker's predefined proxy build arguments, which
  never reach an image layer, e.g.
  `IMAGE_BUILD_FLAGS='--network host --build-arg HTTPS_PROXY=http://127.0.0.1:<port>'`.
- `CONTAINER_ENGINE=podman` works too.

### Running it securely

```bash
docker run -d --name logwisp \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v /etc/logwisp:/etc/logwisp:ro \
  -v /srv/logwisp/secrets:/run/secrets:ro \
  -p 8443:8443 \
  -e LOGWISP_LOGGING_LEVEL=info \
  logwisp:<tag> -c /etc/logwisp/logwisp.toml
```

- Configuration: mount it read-only at `/etc/logwisp` and name it with `-c`.
  The files must be readable by UID 65532.
- Scalar settings: environment variables, `LOGWISP_<PATH>`.
- Pipelines without a file: the pipeline variables, in the `--source` and
  `--sink` syntax (see [CLI](cli.md)); they replace the file's pipelines:

  ```bash
  -e LOGWISP_PIPELINE=relay \
  -e LOGWISP_SOURCE=tcp_chain,port=9000,tls.enabled=true,tls.cert_file=/run/secrets/tls.crt,tls.key_file=/run/secrets/tls.key,auth.type=scram,auth.credentials_file=/run/secrets/users.toml \
  -e LOGWISP_SINK=console
  ```

  Without a file lw logs warnings only and runs no status reporter; add
  `-e LOGWISP_LOGGING_LEVEL=info` (and `-e LOGWISP_STATUS_REPORTER=true`) for
  the service defaults. The image cannot set them: a variable would override
  a mounted file's value. Without `-i`, stdin is `/dev/null`, so a container
  needs a source other than `console`.

- Secrets: only as mounted files, at `/run/secrets` (Docker or Compose
  secrets, a Kubernetes secret volume), named by `tls.key_file`,
  `auth.credentials_file` and `auth.password_file`. Never put a password in
  the environment: `docker inspect` and `/proc` show it. Make each file
  readable by 65532 only (`chown 65532` and mode `0400`).
- Privileges: keep the image's non-root user, a read-only root filesystem,
  `--cap-drop ALL` and `no-new-privileges`. Without capabilities a listener
  needs a port of 1024 or above; publish it on any host port.
- Listeners bind `0.0.0.0` inside the container; `127.0.0.1` would be
  unreachable through `-p`.
- Writable data: a `file` sink or `logging.file` needs a volume writable by
  65532; nothing else is written.
- Reload: `docker kill -s HUP logwisp`.
- `lw auth` runs from the image too, with directories writable by 65532.
  Keep the generated passwords out of the directory the server mounts: it
  needs only `users.toml` (verifiers) and the TLS files, while a `.pass` file
  is the client's plaintext password.

  ```bash
  docker run --rm --read-only --cap-drop ALL --network none \
    -v /srv/logwisp/secrets:/work -v /srv/logwisp/passwords:/pw logwisp:<tag> \
    auth add-user --credentials /work/users.toml --user <name> --password-file /pw/<name>.pass
  ```

## Packaging Status

The foundation for distribution packages is in place:

- the `lw` binary name, and `make install` with `DESTDIR`, `PREFIX` and
  `SYSCONFDIR`
- the `doc/lw.1` manual
- service files in `deploy/package/`: `logwisp.service`, `logwisp.sysusers`,
  `logwisp.tmpfiles` and the FreeBSD `logwisp.rc`
- skeletons: `deploy/package/arch/PKGBUILD` and a `sysutils/logwisp` port in
  `deploy/package/freebsd/`

Still missing: release tags, which both skeletons download; finishing and
submitting the AUR package and the port; Debian packaging.
[To Do](todo.md) has the steps.

## Verification

```bash
lw --version
lw -c /etc/logwisp/logwisp.toml --logging.level=debug --logging.output=stderr
sudo systemctl status logwisp      # Linux
sudo service logwisp status        # FreeBSD
```

Expect `Created source instance`, `Created sink instance` and
`Starting pipeline` for each pipeline. To validate a configuration without
starting it, run `lw --check -c FILE`; see
[Operations](operations.md#checking-a-configuration).

## Test Scripts

The end-to-end scripts in `test/` run against `bin/lw` and share
`test/lib.sh`. `make e2e` runs each with `--auto` and reports it as PASS, FAIL
or SKIP (exit 77, e.g. no IPv6 loopback); only a failure fails the target.

- Modes:
  - without flags: start the daemons, print a guide of the ports and one-line
    commands (run `. test/run-X/env` first for `$LW`, `$CA` and the token
    helper), and wait for Ctrl-C
  - `--auto`: run the checks and tear down; `--keep` leaves the daemons up
    after a pass
  - `--follow`: show only WARN, ERROR and key events from the daemons
- Daemons log only to `test/run*/log/NAME.out`, never to the terminal.
- Colour only on a terminal; `NO_COLOR` turns it off, `FORCE_COLOR=1` on.
- Exit status: 0 all passed, 1 a failure, 77 skipped.
- Each script owns a port range and a gitignored run directory:

```
15801-15804  chain-test.sh, chain-aggregate-test.sh  test/run/
(no ports)   passthrough-test.sh                     test/run/passthrough/
15811-15814  mtls-chain-test.sh                      test/run-mtls/
15821-15825  scram-chain-test.sh                     test/run-scram/
15831-15832  scram-proxy-test.sh                     test/run-proxy/
15851-15855  ipv6-test.sh                            test/run-ipv6/
15871-15879  deploy-test.sh                          test/run-deploy/
15881-15889  acl-test.sh                             test/run/acl/
```

- `chain-test.sh`: two edges into a relay, one pipeline per chain transport;
  ports 15801-15804
- `chain-aggregate-test.sh`: the same edges, with the relay fanning both into
  both sinks; ports 15801-15804
- `passthrough-test.sh`: `file` source to `file` sink, a wide envelope byte
  for byte (`raw = true`) and, parsed, with no key dropped; no ports
- `mtls-chain-test.sh`: mTLS chain edges and viewers, allow lists, node
  binding; ports 15811-15814
- `scram-chain-test.sh`: SCRAM chain edges and viewers with `lw auth`
  credentials; ports 15821-15825
- `scram-proxy-test.sh`: browser and CLI logins to an `http` sink behind a
  TLS-terminating proxy; ports 15831-15832; the browser checks skip without
  node and playwright's Chromium: the headless shell for the scenarios with
  cookies, full Chromium for the profile that blocks them
- `ipv6-test.sh`: a relay on `::1` over both chain transports, IPv6 SANs,
  per-family listeners; ports 15851-15855; skips (exit 77) without an IPv6
  loopback
- `deploy-test.sh`: the configurations `deploy/lw-deploy.sh` writes, deployed
  and checked; ports 15871-15879
- `acl-test.sh`: each listener admitting or refusing peers by address before
  TLS, with clients from 127.0.0.1 and 127.0.0.2; ports 15881-15889
