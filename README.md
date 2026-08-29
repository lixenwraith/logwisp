<table>
  <tr>
    <td width="200" valign="middle">
      <img src="asset/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
    </td>
    <td>
      <h1>LogWisp</h1>
      <p>
        <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat&logo=go" alt="Go"></a>
        <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD_3--Clause-blue.svg" alt="License"></a>
        <a href="doc/"><img src="https://img.shields.io/badge/Docs-Available-green.svg" alt="Documentation"></a>
      </p>
    </td>
  </tr>
</table>

# LogWisp

A pipeline-based log transport and processing system written in Go. LogWisp
collects log entries from files, stdin, or other LogWisp nodes; rate-limits,
filters, and formats them; and distributes them to files, consoles, live network
streams, or downstream LogWisp nodes.

## Features

### Pipeline

- **Independent pipelines**, each `sources → flow → sinks`, running concurrently
  in one process
- **Fan-in and fan-out**: many sources and many sinks per pipeline
- **Never blocks**: a stalled sink drops its own events and is counted, rather
  than stalling the pipeline or its sibling sinks
- **Hot reload** via `SIGHUP`/`SIGUSR1` or a config file watch, with the new
  configuration validated before the old service is torn down

### Inputs

`file` (directory tail with rotation detection and JSON line parsing),
`console` (stdin), `random` (synthetic generator), `null`, and the chain ingest
listeners `tcp_chain` and `http_chain`.

### Outputs

`console`, `file` (rotating with retention), `http` (Server-Sent Events plus a
JSON status endpoint), `tcp` (broadcast server), `null`, and the chain
forwarders `tcp_chain` and `http_chain`.

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
- Authorization by certificate identity: an `auth` block admits named peers
  (exact or RE2) rather than everything the CA issued, gates the `http` sink's
  stream and status endpoints, and lets a dialer pin the server it talks to
- Node binding: a chain source can label entries from the sender's certificate
  instead of from what the sender claims, so origin attribution is not forgeable

See [Security](doc/security.md) for configuration and the exact boundary, and
the [mTLS authentication design](doc/mtls-auth-plan.md) for the rationale and
what is deliberately left out. Password, token, and SCRAM authentication were
removed during the restructure and are not currently available.

## Documentation

| Document | Contents |
|----------|----------|
| [Installation](doc/installation.md) | Building, installing, running as a service |
| [Architecture](doc/architecture.md) | Component model, data flow, concurrency, back-pressure |
| [Configuration](doc/configuration.md) | TOML structure, precedence, environment and CLI overrides |
| [Sources](doc/sources.md) | Every input plugin and its options |
| [Sinks](doc/sinks.md) | Every output plugin and its options |
| [Filters](doc/filters.md) | Pattern-based inclusion and exclusion |
| [Formatters](doc/formatters.md) | Output shaping and sanitization |
| [Chaining](doc/chaining.md) | Multi-node topologies and the chain wire protocol |
| [Networking](doc/networking.md) | Listeners, dialers, timeouts, connection limits |
| [Security](doc/security.md) | TLS, mTLS, and peer authorization; threat model and current limits |
| [mTLS Authentication](doc/mtls-auth-plan.md) | Design and rationale for certificate-based authorization |
| [CLI](doc/cli.md) | Flags, signals, exit codes |
| [Operations](doc/operations.md) | Running, monitoring, tuning, troubleshooting |

A fully annotated configuration covering every option ships as
[`config/logwisp.toml`](config/logwisp.toml).

## Quick Start

```bash
make
```

```toml
# logwisp.toml
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
logwisp -c logwisp.toml
```

Running with no configuration file starts a self-demonstrating pipeline: a
synthetic generator writing JSON to stdout.

## System Requirements

- **Operating systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go**: 1.26+ to build from source

Network sources and sinks bind and dial over IPv4 only.

## License

BSD 3-Clause License
