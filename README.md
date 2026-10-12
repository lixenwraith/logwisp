<p align="center">
  <img src="logwisp-logo.svg" alt="LogWisp Logo" width="160"/>
  <br>
  <br>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.27.2-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD_3--Clause-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Platform-Linux%20|%20FreeBSD%20|%20amd64-lightgrey" alt="Platforms">
  <a href="doc/"><img src="https://img.shields.io/badge/Docs-Available-green.svg" alt="Documentation"></a>
</p>

# LogWisp

A pipeline-based log transport and processing system written in Go. LogWisp
collects log entries from files, stdin, or other LogWisp nodes; rate-limits,
filters, and formats them; and distributes them to files, consoles, live network
streams, or downstream LogWisp nodes.

## Features

### Pipeline

- **A Unix filter out of the box**: with no configuration, `lw` copies stdin
  to stdout line for line and exits at the end of input; flags add filters,
  formats, sources and sinks
- **Presets**: `tail`, `serve`, `edge` and `aggregator` build the common
  pipelines from a few keys (`lw --preset tail:path=/var/log/app`);
  `lw --dump` turns any command line into a configuration file
- **Independent pipelines**, each `sources → flow → sinks`, running concurrently
  in one process
- **Fan-in and fan-out**: many sources and many sinks per pipeline
- **Isolated sinks**: a stalled sink drops and counts its own events rather
  than stalling the pipeline or its sibling sinks; only the console sink
  waits, so a filter loses no line to a slow reader
- **Hot reload** via `SIGHUP`/`SIGUSR1` or a config file watch, with the new
  configuration validated before the old service is torn down

### On screen

`lw --tui` (`-T`) composes pipelines on a full-screen terminal, with the
configuration engine the website's configurator runs as WebAssembly:

- **Start anywhere**: from the pipelines `lw` would run with the same options
  (`-c FILE`, pipeline flags, a discovered file), from a preset, or from a
  pasted `lw` command line
- **Edit with the schema**: sources, flow stages and sinks side by side; the
  inspector edits each part's options from their defaults, every edit is
  checked, and `!` lists the problems
- **Run or print**: `r` runs the pipelines; `o` also prints them as a command
  line, environment variables or a TOML file once the screen closes
  (`lw -T > pipelines.toml`)
- **Tap**: `t` runs them in place and opens a live view of every entry with its
  fate, passed or the stage or filter that dropped it; `e` edits that stage,
  and `t` again reruns as a reload, keeping the running pipelines when the new
  ones do not build. Listeners bind, dialers connect and files are written for
  real; a password is asked in a masked dialog
- **Read any log**: the view parses LogWisp's JSON, lw's own log, pino, zap,
  slog, docker, journald, ECS, GCP, logfmt and stamped text into time, level,
  message and fields, filters them by level or pattern, and shows the payload
  as the sinks receive it. It never slows a pipeline: what it misses is
  counted
- **Any terminal**: `cmd | lw -T` taps piped input, since the screen draws on
  the controlling terminal; colors range from true color to none, and a text
  console gets CP437 glyphs

### Inputs

`file` (a directory's files tailed through rotation, a missing directory
waited for, JSON lines parsed),
`console` (stdin, one reader per process), `random` (generated entries, to
check a deployment before real logs), `null` (nothing; holds a source's place
until one is chosen), and the chain ingest listeners `tcp_chain` and
`http_chain`.

### Outputs

`console` (level names in color and control characters escaped on a
terminal), `file` (rotating with
retention), `http` (Server-Sent Events, a JSON status endpoint and a browser
viewer), `tcp` (broadcast server), `null` (discards; holds a sink's place
until one is chosen), and the chain forwarders `tcp_chain` and `http_chain`.

### Processing

- **Filters**: chainable include/exclude RE2 patterns with `or`/`and` logic
- **Formatters**: `raw`, `txt`, and `json` with selectable sanitizer policies
- **Rate limiting**: token bucket with an optional per-entry size cap
- **Heartbeats**: flow-level keep-alive entries that reach every sink

### Chaining

Multi-node topologies over a versioned protocol. Chain links carry the
**structured entry**, not the formatted text, so a relay can filter and reformat
as if the entries were local. Entries keep a `node` label identifying their
origin across any number of hops. Chain sinks reconnect automatically with
exponential backoff and jitter.

### Transport security and authentication

- TLS 1.2/1.3 on every network source and sink, listener and dialer alike
- Mutual TLS: listeners can require and verify client certificates; dialers can
  present a client identity
- Certificates without a PKI: `lw tls` makes a CA and certificates, and a
  listener can make its own at startup, self-signed (dialers pin its key with
  `pin_sha256`) or signed by a CA
- Authorization by certificate identity: an `auth` block admits named peers
  (exact or RE2) rather than everything the CA issued, gates the `http` sink's
  stream and status endpoints, and lets a dialer pin the server it talks to
- Password authentication (Argon2id-SCRAM) on the same block: listeners hold
  verifiers, never passwords, and do no KDF work; every login outside proxy
  mode is bound to the listener's certificate, so no relay presenting another
  one can use it; HTTP listeners issue short-lived bearer tokens. `lw auth`
  manages credentials files and logs viewers in; behind a site's
  TLS-terminating proxy, browsers log in through a shipped login page and a
  dependency-free JS client
- Node binding: a chain source can label entries from the sender's certificate
  identity or username instead of from what the sender claims, so origin
  attribution is not forgeable
- Address rules: an `acl` block admits or refuses peers by address, or by the
  client an L4 proxy's PROXY header names, and limits each client
- Fail-closed configuration: every option is validated when the file loads,
  unknown keys included, and startup warns about expiring certificates,
  disabled verification, unanchored allow patterns and world-readable secrets

See [Security](doc/security.md) for configuration and the exact boundary, and
[Current State](doc/security.md#current-state) for what is left out.

## Documentation

- [Installation](doc/installation.md): building, installing, services,
  the container image, packaging
- [Deployment](doc/deployment.md): `deploy/lw-deploy.sh` for edges,
  aggregators, containers, services, jails
- [Architecture](doc/architecture.md): component model, data flow,
  concurrency, back-pressure, the configuration engine's WebAssembly API
- [Configuration](doc/configuration.md): TOML structure, precedence,
  environment and CLI overrides
- [Sources](doc/sources.md) and [Sinks](doc/sinks.md): every plugin and its
  options
- [Filters](doc/filters.md) and [Formatters](doc/formatters.md): pattern
  matching, output shaping and sanitization
- [Chaining](doc/chaining.md): multi-node topologies and the wire protocol
- [Networking](doc/networking.md): listeners, dialers, timeouts, limits
- [Security](doc/security.md): TLS, mTLS, password (SCRAM) authentication,
  address ACLs, certificates made at startup; threat model and current limits
- [CLI](doc/cli.md): filter use, flags, pipeline specifications, presets,
  environment, signals, exit codes, `lw --tui`, `--schema`, `lw auth`,
  `lw tls`, `lw preset`, `lw config`; also the `lw(1)` manual,
  [`doc/lw.1`](doc/lw.1)
- [Operations](doc/operations.md): running, monitoring, tuning,
  troubleshooting
- [To Do](doc/todo.md): the maintainer's release and packaging steps, and
  what `lw --tui` and the schema leave for later

A fully annotated configuration covering every option ships as
[`config/logwisp.toml`](config/logwisp.toml).

## Quick Start

```bash
make build                      # plain `make` lists the targets
```

Without a configuration file, `lw` is a filter: stdin to stdout, line for
line, exiting 0 at the end of input. A pipeline without `--source` reads stdin,
one without `--sink` writes stdout:

```bash
./bin/lw < app.log > copy.log
tail -F app.log | ./bin/lw --filter include:patterns=ERROR,patterns=WARN

# stdin as a live SSE stream, with a browser viewer at http://127.0.0.1:8080/;
# the http sink binds 0.0.0.0 unless told
journalctl -f | ./bin/lw --sink http:host=127.0.0.1,port=8080

# tail a directory instead of stdin
./bin/lw --source 'file:directory=/var/log/myapp,pattern=*.log' \
    --format json:sanitizer_policy=json > all.json

# the same with a preset; on a terminal the level names are in color
./bin/lw --preset tail:path=/var/log/myapp

# compose on screen from a preset menu; r runs, t taps, o prints
./bin/lw -T

# tap a stream: t shows each line parsed, and its fate
journalctl -f -o json | ./bin/lw -T --preset pipe
```

As a service, a configuration file holds the pipelines:

```toml
# logwisp.toml
[[pipelines]]
name = "app"

[pipelines.flow.format]
type = "json"
sanitizer_policy = "json"

[[pipelines.plugin_sources]]
id = "app_logs"
type = "file"
[pipelines.plugin_sources.config]
directory = "/var/log/myapp"
pattern = "*.log"

[[pipelines.plugin_sinks]]
id = "sse"
type = "http"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = 8080
```

```bash
./bin/lw -c logwisp.toml                # until SIGINT or SIGTERM; logs to stderr
curl -N http://127.0.0.1:8080/stream    # from another shell
```

In a container, read-only and without capabilities:

```bash
make image
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    -v /etc/logwisp:/etc/logwisp:ro logwisp:dev -c /etc/logwisp/logwisp.toml
```

`make release && sudo make install` installs the binary, the manual, shell
completion, a systemd unit or FreeBSD rc.d script and its configuration.
Without root, `make release install` installs `lw`, its manual, completion and
documentation under `~/.local`, and no service; `lw config init` writes the
annotated configuration it reads. `make deb` and `make arch` package them for
Debian, Ubuntu and Arch. See [Installation](doc/installation.md).

## System Requirements

- **Operating systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go**: 1.27.2+ to build from source

Network sources and sinks use IPv4 or IPv6, following the address family of
the configured host.

## License

BSD 3-Clause License
