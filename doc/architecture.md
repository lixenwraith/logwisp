# Architecture Overview

LogWisp moves log entries through independent pipelines. Everything else —
plugins, sessions, TLS, statistics — hangs off that spine.

## Component Hierarchy

```
main
└── Service
    ├── Pipeline "app"
    │   ├── Registry           instance tracking, single-instance enforcement
    │   ├── Session Manager    per-pipeline connection/session bookkeeping
    │   ├── Sources[]          plugin instances, keyed by id
    │   ├── Flow
    │   │   ├── Rate Limiter   optional, token bucket
    │   │   ├── Filter Chain   optional, ordered
    │   │   ├── Formatter      raw | txt | json, with sanitizer
    │   │   └── Heartbeat      optional generator
    │   └── Sinks[]            plugin instances, keyed by id
    ├── Pipeline "audit"
    │   └── ...
    └── Status Reporter        optional, 30s interval
```

Package map:

| Package | Responsibility |
|---------|----------------|
| `cmd/logwisp` | Entry point, help, logger bootstrap, signal loop, status reporter |
| `internal/config` | Typed config schema, loading, top-level validation |
| `internal/service` | Owns the pipeline set; start, stop, shutdown, global stats |
| `internal/pipeline` | Pipeline runtime and per-pipeline plugin registry |
| `internal/flow` | Rate limiter, filter chain invocation, formatting, heartbeat |
| `internal/filter` | Regex filter and filter chain |
| `internal/format` | Adapter over `lixenwraith/log` formatter + sanitizer |
| `internal/source/*` | Source plugins |
| `internal/sink/*` | Sink plugins |
| `internal/plugin` | Global factory registry populated by plugin `init()` |
| `internal/chain` | Chain wire protocol: hello preamble, entry codec, backoff |
| `internal/tlsx` | The single seam between `TLSOptions` and `crypto/tls` |
| `internal/session` | Session manager and per-instance proxy |
| `internal/core` | Shared types (`LogEntry`, `TransportEvent`), capabilities, constants |
| `internal/tokenbucket` | Rate limiter primitive |
| `internal/sanitize` | Standalone hex-escaping helpers |

## Plugin Registration

Every plugin registers itself in an `init()` function, and
`cmd/logwisp/bootstrap.go` blank-imports each package to trigger those
`init()`s. Adding a plugin therefore means writing the package, calling
`plugin.RegisterSource` / `plugin.RegisterSink`, and adding one blank import.

Registration may attach metadata. The `console` source declares
`MaxInstances: 1`, because a process has only one stdin; the per-pipeline
registry rejects a second instance of any such type.

## Data Flow

### Entry lifecycle

1. **Source** produces a `core.LogEntry` and publishes it to every subscriber
   channel it has handed out. Publication is non-blocking: a full subscriber
   channel increments the source's `dropped_entries` counter.
2. **Flow** applies, in order: rate limit → filter chain → formatter. A drop at
   any stage ends the entry's life and increments `flow.total_dropped`.
3. The formatter output becomes a `core.TransportEvent`, which carries both the
   formatted `Payload` and the original structured `Entry`.
4. **Dispatch** sends the event to every sink's input channel with a
   non-blocking send.

`LogEntry` fields:

| Field | Purpose |
|-------|---------|
| `Time` | Entry timestamp |
| `Node` | Origin node label for chained topologies; stamped at the first hop, preserved by relays |
| `Source` | Origin identifier within the node (filename, plugin id, …) |
| `Level` | `DEBUG`/`INFO`/`WARN`/`ERROR`/`TRACE`, when detected |
| `Message` | Log content |
| `Fields` | Optional structured metadata as raw JSON |
| `RawSize` | Original byte size, used by the entry-size cap |

Carrying `Entry` alongside `Payload` is what makes chain sinks
format-independent: a `tcp_chain` or `http_chain` sink re-serializes the
structured entry rather than shipping whatever text the local formatter chose.

### Back-pressure and drops

There is exactly one drop policy and it is not configurable: **never block**.

| Stage | Full-buffer behaviour | Counter |
|-------|----------------------|---------|
| Source → subscriber | Drop the entry | source `dropped_entries` |
| Flow | Drop on rate limit, filter, or format error | `flow.total_dropped` |
| Pipeline → sink | Drop for that sink only | pipeline `total_dropped_by_sink` |
| TCP/HTTP sink → client queue | Drop for that client only | sink `dropped_writes` |

The `tcp_chain` sink is the one deliberate exception. It holds a line across
reconnects until it is written or the process shuts down, so a downstream
outage propagates backwards as a full input buffer and surfaces as
`total_dropped_by_sink` on the pipeline rather than as silent data loss inside
the sink. The `http_chain` sink retries a batch with backoff, and drops it only
on a non-retryable response or on shutdown (`dropped_batches`).

## Concurrency Model

- One goroutine per source drains that source's subscription and feeds the flow.
- The flow's formatter holds a mutex; the underlying formatter reuses an
  internal buffer and is not goroutine-safe.
- Each network sink runs one broadcast/broker goroutine plus, per connection, a
  writer goroutine (and for TCP, a reader goroutine that exists only to detect
  disconnects and refresh session activity).
- Chain sinks run a single run-loop goroutine that exclusively owns the
  connection or the pending batch, so no locking is needed around either.
- Statistics are atomics; configuration and registries use RW mutexes;
  shutdown is context cancellation plus wait groups.

### Shutdown ordering

`Pipeline.Stop` is deliberately ordered so in-flight data drains:

1. Stop all sources concurrently; each closes its subscriber channels.
2. Wait for the run loop, which ends when every subscription channel closes.
3. Stop all sinks concurrently.

## Network Architecture

All listeners bind `tcp4` and all dialers dial `tcp4`. IPv6 clients cannot
connect; this is deliberate, not an oversight.

| Plugin | Role | Protocol |
|--------|------|----------|
| `tcp` sink | Listener | Raw broadcast of formatted payloads |
| `http` sink | Listener | HTTP/1.1 SSE; HTTP/2 negotiated via ALPN when TLS is on |
| `tcp_chain` source | Listener | Chain protocol, persistent NDJSON stream |
| `http_chain` source | Listener | Chain protocol, NDJSON batches over POST |
| `tcp_chain` sink | Dialer | Chain protocol, persistent stream, auto-reconnect |
| `http_chain` sink | Dialer | Chain protocol, batched POST with retry |

TLS is built in exactly one place, `internal/tlsx`, which exposes
`Server(opts)` for listeners and `Client(opts, host)` for dialers. See
[Security](security.md).

## Sessions

Each pipeline owns a `session.Manager`. Plugins receive a `session.Proxy`
scoped to their instance id, so one plugin cannot see or remove another's
sessions. A session records the remote address, creation and last-activity
timestamps, and metadata — including `tls` and `tls_peer_cn` for TLS peers.

Idle sessions are reaped every 5 minutes against a 30-minute idle limit. The
HTTP sink's broker treats a vanished session as an eviction signal and closes
the corresponding SSE client.

Session metadata is currently bookkeeping only: nothing in the pipeline makes
an authorization decision from it. Closing that gap is the subject of the
[mTLS authentication plan](mtls-auth-plan.md).

## Configuration Reload

Reload (signal or file watch) rebuilds the entire service:

1. Re-read the config through the config manager.
2. Build a **new** service from it. If construction fails, the old service keeps
   running untouched.
3. Shut the old service down, start the new one, and restart the status
   reporter if it is enabled.

Because this is a full rebuild, listening sockets close and reopen and all
clients are disconnected. Application logging is configured once at startup and
is **not** re-applied on reload.

## Resource Management

- Every buffer is bounded; the drop-not-block policy keeps memory flat under
  load.
- Network sinks and chain sources accept a `max_connections` cap. Admission is
  a load-then-check, so a burst can over-admit by roughly one connection.
- Chain listeners bound a single line at `core.MaxLogEntryBytes` (1 MiB); an
  oversized line is a protocol violation and terminates the connection.
- The `http_chain` source caps each request body at `max_body_bytes`.
- File sinks rotate on size, cap total rotated size, and honour a retention
  window.

## Performance Notes

- In-memory entry processing is sub-millisecond; the formatter mutex is the
  only shared serialization point in the hot path.
- File tailing detects new content within roughly 100 ms (fixed poll), while
  `check_interval_ms` governs how quickly a *newly created* file is noticed.
- `http_chain` trades latency for efficiency: entries wait up to
  `flush_interval_ms` (default 1 s) before a batch is sent.
- Scale out with more pipelines per process, more sinks per pipeline, or more
  nodes chained together.
