# LogWisp Documentation

LogWisp is a pipeline-based log transport and processing system written in Go.
It collects log entries from files, stdin, or other LogWisp nodes; rate-limits,
filters, and formats them; and distributes them to files, consoles, live network
streams, or downstream LogWisp nodes.

## Documentation Map

- [Installation](installation.md): building, installing, and running as a
  service
- [Deployment](deployment.md): `deploy/lw-deploy.sh` for edges, aggregators,
  containers, services, jails
- [Architecture](architecture.md): component model, data flow, concurrency,
  back-pressure
- [Configuration](configuration.md): TOML structure, precedence, environment
  and CLI overrides
- [Sources](sources.md): every input plugin and its options
- [Sinks](sinks.md): every output plugin and its options
- [Filters](filters.md): pattern-based inclusion and exclusion
- [Formatters](formatters.md): output shaping and sanitization
- [Chaining](chaining.md): multi-node topologies and the chain wire protocol
- [Networking](networking.md): listeners, dialers, timeouts, connection limits
- [Security](security.md): TLS, mTLS, and peer authorization; threat model and
  current limits
- [mTLS Authentication](mtls-auth-plan.md): design and rationale for
  certificate-based authorization
- [Password Authentication](scram-auth-plan.md): design and rationale for
  Argon2id-SCRAM authentication; mTLS hardening
- [CLI](cli.md): flags, signals, exit codes, `lw auth`; also the `lw(1)`
  manual, [`lw.1`](lw.1)
- [Operations](operations.md): running, monitoring, tuning, troubleshooting
- [To Do](todo.md): planned work: packaging, `lw --tui` and its shared configuration engine

A fully annotated configuration covering every option lives at
[`config/logwisp.toml`](../config/logwisp.toml).

## Capabilities

### Pipeline

- A Unix filter without configuration: stdin to stdout, line for line
- Independent named pipelines, each `sources → flow → sinks`
- Fan-in (many sources per pipeline) and fan-out (many sinks per pipeline)
- Isolated sinks: a stalled sink drops its own events rather than stall the
  pipeline; only the console sink waits, so a filter loses no line
- Hot reload of pipeline configuration via `SIGHUP`/`SIGUSR1` or a file watch

### Inputs

`file` (directory tail with rotation detection), `console` (stdin, one
reader per process),
`random` (synthetic generator), `null`, and the chain ingest listeners
`tcp_chain` and `http_chain`.

### Outputs

`console` (control characters escaped on a terminal), `file` (rotating),
`http` (Server-Sent Events plus a JSON status
endpoint), `tcp` (broadcast server), `null`, and the chain forwarders
`tcp_chain` and `http_chain`.

### Processing

- Token-bucket rate limiting with an optional per-entry size cap
- Chainable include/exclude regex filters with `or`/`and` logic
- `raw`, `txt`, and `json` formatting with selectable sanitizer policies
- Optional flow-level heartbeat entries

### Transport security and authentication

- TLS 1.2/1.3 on every network source and sink, listener and dialer alike
- Mutual TLS: listeners can require and verify client certificates; dialers can
  present a client identity
- Authorization by certificate identity, per listener: named peers rather than
  everything the CA issued, with the `http` sink's endpoints gated too
- Password authentication (Argon2id-SCRAM) bound to the listener's certificate,
  with bearer tokens on HTTP listeners and a `lw auth` CLI, and browser
  logins behind a TLS-terminating proxy
- Node binding, so a chain source labels entries from the sender's certificate
  identity or username rather than from what the sender claims

See [Security](security.md) for what each layer does and does not give you.

## Quick Start

Without a configuration file `lw` is a filter, exiting 0 at the end of input;
a pipeline without `--source` reads stdin and one without `--sink` writes
stdout:

```bash
lw < app.log > copy.log
tail -F app.log | lw --filter include:patterns=ERROR,patterns=WARN
```

As a service, a file holds the pipelines:

```toml
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
id = "stdout"
type = "console"
[pipelines.plugin_sinks.config]
target = "stdout"
```

```bash
lw -c config.toml
```

## System Requirements

- **Operating systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go**: 1.27.2+ to build from source

Network sources and sinks bind and dial IPv4 or IPv6, each keeping strictly to
the family of its host ([Networking](networking.md#address-family)).

## License

BSD 3-Clause.
