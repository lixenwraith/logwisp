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

- `cmd/lw`: entry point, help, logger bootstrap, signal loop, status
  reporter.
- `internal/config`: typed config schema, loading, top-level validation.
- `internal/service`: owns the pipeline set; start, stop, shutdown, global
  stats.
- `internal/pipeline`: pipeline runtime and per-pipeline plugin registry.
- `internal/flow`: rate limiter, filter chain invocation, formatting,
  heartbeat.
- `internal/filter`: regex filter and filter chain.
- `internal/format`: adapter over the `lixenwraith/log` formatter and
  sanitizer.
- `internal/source/*`, `internal/sink/*`: the source and sink plugins.
- `internal/plugin`: global factory registry populated by plugin `init()`.
- `internal/chain`: chain wire protocol: hello preamble, entry codec, backoff.
- `internal/tlsx`: the single seam between `TLSOptions` and `crypto/tls`.
- `internal/authz`: the single seam between `AuthOptions` and the network
  plugins: `Admit`, `AuthorizeRequest`, `Greet`, `Prepare`.
- `internal/netacl`: a listener's `acl` block: address rules, PROXY headers
  and per-client limits; its `Table` is SCRAM throttling's limiter too.
- `internal/session`: session manager and per-instance proxy.
- `internal/core`: shared types (`LogEntry`, `TransportEvent`), capabilities,
  constants.
- `internal/tokenbucket`: rate limiter primitive.
- `internal/sanitize`: standalone hex-escaping helpers.

## Plugin Registration

Every plugin registers itself in an `init()` function, and
`cmd/lw/bootstrap.go` blank-imports each package to trigger those
`init()`s. Adding a plugin therefore means writing the package, calling
`plugin.RegisterSource` / `plugin.RegisterSink`, and adding one blank import.

Registration may attach metadata. The `console` source declares
`MaxInstances: 1`, because a process has only one stdin; the per-pipeline
registry rejects a second instance of any such type.

## Data Flow

### Entry lifecycle

1. **Source** produces a `core.LogEntry` and publishes it to every subscriber
   channel it has handed out; the pipeline subscribes before the source
   starts. Publication is non-blocking: a full subscriber channel increments
   the source's `dropped_entries` counter. The console source alone waits,
   since stdin can simply be read later.
2. **Flow** applies, in order: rate limit → filter chain → formatter. A drop at
   any stage ends the entry's life and increments `flow.total_dropped`.
3. The formatter output becomes a `core.TransportEvent`, which carries both the
   formatted `Payload` and the original structured `Entry`.
4. **Dispatch** sends the event to every sink's input channel with a
   non-blocking send, except to a sink declaring `CapBackpressure`.

`LogEntry` fields:

- `Time`: entry timestamp.
- `Node`: origin node label for chained topologies; stamped at the first hop,
  preserved by relays.
- `Source`: origin identifier within the node (filename, plugin id, …).
- `Level`: `TRACE`, `DEBUG`, `INFO`, `WARN` or `ERROR`, when detected; the
  words naming each are one table, `core.Levels`.
- `Message`: log content.
- `Fields`: optional structured metadata as raw JSON.
- `RawSize`: original byte size, used by the entry-size cap.

Carrying `Entry` alongside `Payload` is what makes chain sinks
format-independent: a `tcp_chain` or `http_chain` sink re-serializes the
structured entry rather than shipping whatever text the local formatter chose.

### Back-pressure and drops

The drop policy is not configurable: **never block**, except where waiting
loses nothing. Each stage drops and counts instead of waiting:

- Source → subscriber: a full channel drops the entry; source
  `dropped_entries`. The console source waits instead and reads stdin later.
- Flow: the rate limiter, a filter rejection or a format error drops it;
  `flow.total_dropped`.
- Pipeline → sink: a full sink input drops it for that sink only; pipeline
  `total_dropped_by_sink`. A sink declaring `core.CapBackpressure`, the console
  sink, makes dispatch wait instead, so a filter loses no line to a slow
  reader and its pipeline runs at the reader's pace; `Stop` ends the wait.
- TCP/HTTP sink → client queue: a full queue drops it for that client only;
  sink `dropped_writes`.

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

1. Release dispatch waits on backpressure sinks; stop all sources
   concurrently, each closing its subscriber channels.
2. Wait for the run loop, which ends when every subscription channel closes.
3. Stop all sinks concurrently; console and file sinks write their queue
   first. Then cancel the pipeline context.

A finite source ends on its own: the console source at the end of stdin. The
run loop then returns and the pipeline's `Finished` channel closes; once every
pipeline has finished, the service's `Done` closes and `main` shuts down as on
`SIGTERM`, exiting 0.

## Network Architecture

Each listener and dialer keeps strictly to the family of its host literal:
`tcp4` for IPv4, IPv6-only `tcp6` for IPv6 (`::` too); a hostname resolves.
See [Networking](networking.md#address-family).

The network plugins, by role:

- Listeners
  - `tcp` sink: raw broadcast of formatted payloads.
  - `http` sink: HTTP/1.1 SSE; HTTP/2 negotiated via ALPN when TLS is on.
  - `tcp_chain` source: chain protocol, persistent NDJSON stream.
  - `http_chain` source: chain protocol, NDJSON batches over POST.
- Dialers
  - `tcp_chain` sink: chain protocol, persistent stream, auto-reconnect.
  - `http_chain` sink: chain protocol, batched POST with retry.

TLS is built in exactly one place, `internal/tlsx`, which exposes
`Server(opts)` for listeners and `Client(opts, host)` for dialers. See
[Security](security.md).

## Sessions

Each pipeline owns a `session.Manager`. Plugins receive a `session.Proxy`
scoped to their instance id, so one plugin cannot see or remove another's
sessions. A session records the remote address, creation and last-activity
timestamps, and metadata — including `tls` and `tls_peer_cn` for TLS peers,
`auth_method` / `auth_identity` for authorized ones, and `peer_addr`, the proxy,
for a client a PROXY header names.

Idle sessions are reaped every 5 minutes against a 30-minute idle limit. The
HTTP sink's broker treats a vanished session as an eviction signal and closes
the corresponding SSE client.

Authorization decisions do not read session metadata — `internal/authz` makes
them from the handshake, the SCRAM exchange or a bearer token, at the point of
connection or request, and their outcome is *recorded* in the session. That
ordering matters: a session exists only for a peer that was already admitted.
See the [mTLS](mtls-auth-plan.md) and [SCRAM](scram-auth-plan.md)
authentication designs.

## Configuration Reload

Reload (signal or file watch) rebuilds the entire service:

1. Signals reread the selected file; watches consume a newly published snapshot.
   The application owns its manager and detached snapshots; no global mutable
   target is shared with the running service. Validate every candidate again.
2. Build a **new** service from it. If construction fails, the old service keeps
   running untouched.
3. Shut the old service down, start the new one, and restart the status
   reporter if it is enabled.

Because this is a full rebuild, listening sockets close and reopen and all
clients are disconnected. Application logging is configured once at startup and
is **not** re-applied on reload.

Watch errors do not rebuild services. Queued changes are combined, and an
unchanged pipeline/status snapshot is skipped. Signals always rebuild for
certificate rotation. Failed candidates release their session workers. Once the
old service has stopped, a bind/start failure requires another corrected reload
or process restart.

## Resource Management

- Every buffer is bounded; the drop-not-block policy keeps memory flat under
  load.
- The `tcp` and `http` sinks and the `tcp_chain` source accept a
  `max_connections` cap. Admission is a load-then-check, so a burst can
  over-admit by roughly one connection.
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
