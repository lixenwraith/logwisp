# LogWisp Documentation

LogWisp is a pipeline-based log transport and processing system written in Go.
It collects log entries from files, stdin, or other LogWisp nodes; rate-limits,
filters, and formats them; and distributes them to files, consoles, live network
streams, or downstream LogWisp nodes.

## Documentation Map

| Document | Contents |
|----------|----------|
| [Installation](installation.md) | Building, installing, and running as a service |
| [Architecture](architecture.md) | Component model, data flow, concurrency, back-pressure |
| [Configuration](configuration.md) | TOML structure, precedence, environment and CLI overrides |
| [Sources](sources.md) | Every input plugin and its options |
| [Sinks](sinks.md) | Every output plugin and its options |
| [Filters](filters.md) | Pattern-based inclusion and exclusion |
| [Formatters](formatters.md) | Output shaping and sanitization |
| [Chaining](chaining.md) | Multi-node topologies and the chain wire protocol |
| [Networking](networking.md) | Listeners, dialers, timeouts, connection limits |
| [Security](security.md) | TLS and mTLS configuration, threat model, current limits |
| [mTLS Authentication Plan](mtls-auth-plan.md) | Design for certificate-based authorization |
| [CLI](cli.md) | Flags, signals, exit codes |
| [Operations](operations.md) | Running, monitoring, tuning, troubleshooting |

A fully annotated configuration covering every option lives at
[`config/logwisp.toml`](../config/logwisp.toml).

## Capabilities

### Pipeline

- Independent named pipelines, each `sources → flow → sinks`
- Fan-in (many sources per pipeline) and fan-out (many sinks per pipeline)
- Non-blocking sink dispatch: a stalled sink drops its own events and never
  stalls the pipeline or its sibling sinks
- Hot reload of pipeline configuration via `SIGHUP`/`SIGUSR1` or a file watch

### Inputs

`file` (directory tail with rotation detection), `console` (stdin),
`random` (synthetic generator), `null`, and the chain ingest listeners
`tcp_chain` and `http_chain`.

### Outputs

`console`, `file` (rotating), `http` (Server-Sent Events plus a JSON status
endpoint), `tcp` (broadcast server), `null`, and the chain forwarders
`tcp_chain` and `http_chain`.

### Processing

- Token-bucket rate limiting with an optional per-entry size cap
- Chainable include/exclude regex filters with `or`/`and` logic
- `raw`, `txt`, and `json` formatting with selectable sanitizer policies
- Optional flow-level heartbeat entries

### Transport security

- TLS 1.2/1.3 on every network source and sink, listener and dialer alike
- Mutual TLS: listeners can require and verify client certificates; dialers can
  present a client identity. See [Security](security.md) for what this does and
  does not currently give you.

## Quick Start

```toml
[[pipelines]]
name = "default"

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
logwisp -c config.toml
```

## System Requirements

- **Operating systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go**: 1.26+ to build from source

Network sources and sinks bind and dial over IPv4 only.

## License

BSD 3-Clause.
