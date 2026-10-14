# Architecture Overview

LogWisp moves log entries through independent pipelines. Everything else —
plugins, sessions, TLS, statistics — hangs off that spine.

## Component Hierarchy

```
main
├── Service
│   ├── Pipeline "app"
│   │   ├── Registry           creates each plugin from its factory
│   │   ├── Session Manager    per-pipeline connection/session bookkeeping
│   │   ├── Sources[]          plugin instances, keyed by id
│   │   ├── Flow
│   │   │   ├── Rate Limiter   optional, token bucket
│   │   │   ├── Filter Chain   optional, ordered
│   │   │   ├── Formatter      raw | txt | json, with sanitizer
│   │   │   └── Heartbeat      optional generator
│   │   └── Sinks[]            plugin instances, keyed by id
│   └── Pipeline "audit"
│       └── ...
└── Status Reporter            cmd/lw, optional, 30 s: Service.GetGlobalStats
```

Package map:

- `cmd/lw`: entry point: the command line (`cli.go`: lw's flags and the
  `auth`, `tls`, `preset` and `config` commands), help, completion, logger
  bootstrap, signal and reload loop, status reporter.
- `cmd/lwconf`: `internal/compose` as WebAssembly, and `lwconf.js`, which
  loads it: see [Configuration Engine](#configuration-engine).
- `internal/config`: option schema (tags, catalogue) and `Decode`; loading
  from file, environment and flags; presets; offline validation of every
  setting and plugin option.
- `internal/compose`: the configuration engine `lw --tui` and `cmd/lwconf`
  share. It edits pipelines and writes and reads back the command-line,
  environment and file forms; it reads no file and links no TLS, HTTP or
  terminal code.
- `internal/service`: owns the pipeline set; start, stop, shutdown, global
  stats.
- `internal/pipeline`: pipeline runtime and per-pipeline plugin registry.
- `internal/flow`: rate limiter, filter chain invocation, formatting,
  heartbeat.
- `internal/filter`: regex filter and filter chain.
- `internal/format`: adapter over the `lixenwraith/log` formatter and
  sanitizer.
- `internal/source`, `internal/sink`: the `Source` and `Sink` interfaces and
  their stats, and the stop helpers network sinks share (`sink.FlushBound`,
  `FlushContext`, `Drain`); their subpackages are the plugins.
- `internal/plugin`: global factory registry populated by plugin `init()`.
- `internal/chain`: chain wire protocol: hello preamble, entry codec, backoff.
- `internal/tlsx`: the single seam between `TLSOptions` and `crypto/tls`; also
  the certificates `lw tls` writes and a listener makes at startup, pins and
  startup warnings.
- `internal/authz`: the single seam between `AuthOptions` and the network
  plugins: `Admit`, `AuthorizeRequest`, `Greet`, `Prepare`; `Authorize`
  refuses under `scram`.
- `internal/netacl`: a listener's `acl` block: address rules, PROXY headers
  and per-client limits; its `Table` is SCRAM throttling's limiter too.
- `internal/session`: session manager and per-instance proxy.
- `internal/core`: shared types (`LogEntry`, `TransportEvent`, the viewer's
  `Tap`), the level table `core.Levels`, capabilities, constants, and
  `Network` and `Listen`, which keep a socket to its host's address family.
- `internal/tokenbucket`: rate limiter primitive.
- `internal/tui`: `lw --tui`, the diagram and the live view of what `t`
  runs; `cmd/lw/screen.go` runs the pipelines for it.
- `internal/logline`: reads a line of any common shape into time, level,
  tag, message and fields for the live view; holds the one rule for runes a
  terminal acts on, which the console sink shares.
- `internal/version`: version, commit and build time, stamped at build.
- `internal/testutil`: fixtures for tests only.
- `config`: embeds `logwisp.toml`, the annotated default configuration that
  `lw config init` writes and the packages install.

## Plugin Registration

Every plugin registers itself in an `init()` function, and
`cmd/lw/bootstrap.go` blank-imports each package to trigger it. Adding a
plugin means writing the package, calling `plugin.RegisterSource` /
`plugin.RegisterSink`, adding one blank import, and adding the type's row to
the catalogue in `internal/config/schema.go`, which registration requires.

The row holds the type's options struct, whose tags declare its defaults and
rules, and whether the type is single. The `console` source is single,
because a process has only one stdin; loading a configuration with a second
instance of a single type fails, naming both pipelines.

## Data Flow

### Entry lifecycle

1. **Source** produces a `core.LogEntry` and publishes it to every subscriber
   channel it has handed out; the pipeline subscribes before the source
   starts. Publication is non-blocking: a full subscriber channel increments
   the source's `dropped_entries` counter. The console source alone waits,
   since stdin can simply be read later.
2. **Flow** applies, in order: rate limit → filter chain → formatter. A rate
   limit or filter drop ends the entry's life and increments
   `flow.total_dropped`. The verdict, passed or the stage that dropped it (a
   filter by its index), goes to the pipeline's tap when a viewer set one, as
   `lw --tui`'s live view does.
3. The formatter output becomes a `core.TransportEvent`, which carries both the
   formatted `Payload` and the original structured `Entry`.
4. **Dispatch** sends the event to every sink's input channel with a
   non-blocking send, except to a sink declaring `CapBackpressure`.

A heartbeat joins at step 4: the flow writes it in its format with a
structured `Entry`, and the pipeline offers it to the tap and dispatches it,
so no rate limit or filter drops it and `flow.total_processed` does not count
it.

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
- Flow: the rate limiter or a filter rejection drops it; `flow.total_dropped`.
- Pipeline → sink: a full sink input drops it for that sink only; pipeline
  `total_dropped_by_sink`. A sink declaring `core.CapBackpressure`, the console
  and null sinks, makes dispatch wait instead, so a filter loses no line to a
  slow reader and its pipeline runs at the reader's pace; `Stop` ends the wait.
- TCP/HTTP sink → client queue: a full queue drops it for that client only;
  sink `dropped_writes`.
- Flow → tap: a full tap drops the record, copying nothing, which the live
  view counts as "screen missed". It copies the first 16 KiB of a longer
  message, fields or payload and 256 bytes of a level, source or node, so a
  viewer's rows pin no source's line, and takes dropped entries only while
  the view shows them.

The `tcp_chain` sink is the one deliberate exception. It holds a line across
reconnects until it is written or the sink stops (shutdown or reload, after
`sink.FlushBound`), so a downstream outage propagates backwards as a full
input buffer and surfaces as `total_dropped_by_sink` on the pipeline rather
than as silent data loss inside the sink. The `http_chain` sink retries a
batch with backoff, and drops it only on a non-retryable response or on
shutdown (`dropped_batches`).

## Concurrency Model

- One goroutine per source drains that source's subscription and feeds the flow.
- The flow's formatter holds a mutex; the underlying formatter reuses an
  internal buffer and is not goroutine-safe.
- Each network sink runs one broadcast/broker goroutine plus, per connection, a
  writer goroutine (and for TCP, a reader goroutine that exists only to detect
  disconnects and refresh session activity).
- Chain sinks run one run-loop goroutine that owns the pending line or batch;
  the `tcp_chain` sink adds a reader goroutine per link that closes the link
  when the source writes anything or closes it.
- Statistics are atomics; configuration and registries use RW mutexes;
  shutdown is context cancellation plus wait groups.

### Shutdown ordering

`Pipeline.Stop` is ordered so in-flight data drains:

1. Release dispatch waits on backpressure sinks; stop all sources
   concurrently, each closing its subscriber channels. From the release on,
   dispatch picks at random between a backpressure sink's input and the
   release, so it drops about half of the entries still in flight for one
   (`total_dropped_by_sink`) even with room.
2. Wait for the run loop, which ends when every subscription channel closes.
3. Stop all sinks concurrently: console and file sinks write their queue;
   network sinks deliver theirs within `sink.FlushBound`, their write or
   request timeout when set below 2 s, else 2 s. Then cancel the pipeline
   context.

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
`Server(opts, host)` for listeners and `Client(opts, host)` for dialers. See
[Security](security.md).

## Sessions

Each pipeline owns a `session.Manager`. Plugins receive a `session.Proxy`
scoped to their id, so a plugin sees and removes only the sessions under its
id; ids are unique per list, so a source and a sink that share one (the
built-in pipe's two `console`s) share that scope. A session records the
remote address, creation and last-activity timestamps, and metadata —
including `tls` and `tls_peer_cn` for TLS peers, `auth_method` /
`auth_identity` for authorized ones, and `peer_addr`, the proxy, for a client
a PROXY header names.

Idle sessions are reaped every 5 minutes against a 30-minute idle limit. The
HTTP sink's broker treats a vanished session as an eviction signal and closes
the corresponding SSE client.

Authorization decisions do not read session metadata — `internal/authz` makes
them from the handshake, the SCRAM exchange or a bearer token, at the point of
connection or request, and their outcome is *recorded* in the session, so a
session exists only for a peer that was already admitted. See
[Security](security.md#the-auth-block) and
[Chaining](chaining.md#wire-protocol).

## Configuration Reload

Reload (signal or file watch) rebuilds the entire service:

1. Signals (`SIGHUP`, `SIGUSR1`) reread the file; a watch takes the published
   snapshot. Every candidate is validated again.
2. Build a **new** service from it. If construction fails, the old service keeps
   running untouched.
3. Shut the old service down, start the new one, and restart the status
   reporter if it is enabled.

Because this is a full rebuild, listening sockets close and reopen and all
clients are disconnected. Application logging is configured once at startup and
is **not** re-applied on reload. `t` on the `lw --tui` screen reruns through
the same path, giving each new service the screen's tap before it starts.

Watch errors do not rebuild services. Queued changes are combined, and an
unchanged pipeline/status snapshot is skipped. Signals always rebuild for
certificate rotation. Failed candidates release their session workers. Once the
old service has stopped, a bind/start failure requires another corrected reload
or process restart.

## Configuration Engine

`internal/compose` is what `lw --tui` edits with and what the website runs as
WebAssembly, so no part of LogWisp is rewritten in JavaScript. `make wasm`
writes the files a site drops in
([Installation](installation.md#building-from-source)): `lwconf.wasm` is
7.1 MB, 1.9 MB at gzip -9, and the toolchain's `wasm_exec.js` uses no eval,
so the page needs only `'wasm-unsafe-eval'` in its `script-src`.

`lwconf.js` is one dependency-free ES module that knows the calls and shapes,
never a key:

- `load({execURL, execSRI, wasmURL, wasmSRI})` fetches both by their
  integrity and resolves to the engine.
- `fields(schema, role, type)` is a node's form rows, a table's a group.
- `value`, `at` and `group` read a node's value and sort problems by node.

The engine's calls take strings (`lwconf.js` writes objects as JSON) and
answer `{"value": ...}` or `{"error", "path", "pipeline", "node", "key",
"ask"}`, as far as the engine places the refusal:

- `schema()`: what `lw --schema` prints.
- `preset(name, values, dirs)`: a preset's pipelines; `values` maps a key to
  a string, a list key to strings.
- `parse(text, form, dirs)`: the pipelines of a form's pasted text.
- `validate(pipelines)`: `{pipelines, problems}`, the pipelines settled
  (defaults, kinds, ids) and the first problem of each part (a value of the
  wrong kind too) as `{path, pipeline, node, key, text}`.
- `emit(pipelines, form)`: the text of `command`, `environment` or `file`.
- `edit(pipelines, op)`: `{pipelines, node}`, the node left chosen. `op` is
  `{op, pipeline, ...}`:
  - `add_pipeline` and `rename_pipeline` (`name`), `remove_pipeline`
  - `add` (`role`, `type`), `retype` (`node`, `type`), `remove` (`node`)
  - `move_filter` (`from`, `to`)
  - `set` (`node`, `key`, `values`), `unset` (`node`, `key`)
- `dirs` answers whether a path a preset names is a directory,
  `{"/var/log/app.log": false}`; unanswered, a path ending in `/` is one, one
  with a glob a pattern, and any other is refused at `path` with `ask` naming
  it: answer it in `dirs` and call again.
- Pipelines are a JSON list in the file's shape (`name`, `flow`,
  `plugin_sources`, `plugin_sinks`); a misspelled key is refused. A node is
  `{role, id, index}`: `source` or `sink` by its id, `filters` by its index,
  or the flow stage `rate_limit`, `format` or `heartbeat`, which `set` turns
  on and `remove` off; `add` takes `source`, `sink`, or `filters` with the
  type `include` or `exclude`.

## Resource Management

- Every buffer is bounded; the drop-not-block policy keeps memory flat under
  load.
- `max_connections` caps connections on the `tcp` sink and the `tcp_chain`
  source, and streams on the `http` sink. Admission is a load-then-check, so a
  burst can over-admit by the connections that arrive before the count rises.
- A listener's `acl` block caps each client: `max_connections_per_client`,
  and on the `http` sink and `http_chain` source
  `requests_per_second_per_client` ([Security](security.md#per-client-limits)).
- Chain listeners bound a single line at `core.MaxLogEntryBytes` (1 MiB); an
  oversized line terminates a `tcp_chain` link and fails an `http_chain`
  batch with `400`.
- The `http_chain` source caps each request body at `max_body_bytes`.
- File sinks rotate on size, cap total rotated size, honour a retention
  window, and with `min_disk_free_mb` delete the oldest files to keep that
  much disk free.

## Performance Notes

- In-memory entry processing is sub-millisecond. Besides the formatter's
  mutex, an entry can take the rate limiter's bucket lock (`policy = "drop"`)
  and the pipeline's session-manager lock, which the network plugins and the
  console and random sources take as entries pass, to refresh session
  activity.
- File tailing detects new content within roughly 100 ms (fixed poll), while
  `check_interval_ms` governs how quickly a *newly created* file is noticed.
- `http_chain` trades latency for efficiency: entries wait up to
  `flush_interval_ms` (default 1 s) before a batch is sent.
- Scale out with more pipelines per process, more sinks per pipeline, or more
  nodes chained together.
