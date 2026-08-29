# Output Sinks

Sinks consume `core.TransportEvent` values — a formatted `Payload` plus the
original structured `Entry` — and deliver them somewhere. Each sink is declared
as a `[[pipelines.plugin_sinks]]` entry with an `id`, a `type`, and a
type-specific `config` table.

Registered types: `console`, `file`, `http`, `tcp`, `null`, `tcp_chain`,
`http_chain`.

Dispatch into a sink is non-blocking. A sink whose input queue is full drops the
event *for itself only* and the pipeline counts it in `total_dropped_by_sink`;
sibling sinks are unaffected.

---

## console

Writes formatted payloads to stdout or stderr.

```toml
[[pipelines.plugin_sinks]]
id   = "stdout"
type = "console"
[pipelines.plugin_sinks.config]
target      = "stdout"
buffer_size = 1000
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | `stdout` | `stdout` or `stderr` |
| `buffer_size` | int | `1000` | Sink input queue depth |

> `split` is **not** a valid target for this sink and is rejected at startup.
> Level-based splitting exists only for LogWisp's own application log
> (`logging.output = "split"`).

Payloads are written verbatim; the sink adds no framing. Whether entries are
newline-terminated is decided by the formatter.

---

## file

Rotating file writer.

```toml
[[pipelines.plugin_sinks]]
id   = "archive"
type = "file"
[pipelines.plugin_sinks.config]
directory         = "/var/log/logwisp"
name              = "output"
max_size_mb       = 100
max_total_size_mb = 1000
min_disk_free_mb  = 0
retention_hours   = 168.0
buffer_size       = 1000
flush_interval_ms = 100
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `directory` | string | **required** | Output directory |
| `name` | string | **required** | Base filename |
| `max_size_mb` | int | `100` | Rotate when the active file reaches this size |
| `max_total_size_mb` | int | `1000` | Cap across all rotated files |
| `min_disk_free_mb` | int | `0` | Free-space floor before writing; `0` = no floor |
| `retention_hours` | float | `168.0` | Delete rotated files older than this |
| `buffer_size` | int | `1000` | Sink input queue depth |
| `flush_interval_ms` | int | `100` | Forced flush interval |

> `min_disk_free_mb` has an unusual default. The constructor replaces only
> *negative* values with `100`; leaving the key unset yields `0`, which means no
> free-space floor. Set it explicitly if you want one.

The sink drives an internal writer configured for raw output with timestamps and
levels disabled, so what lands on disk is exactly the formatted payload.

---

## null

Discards everything, counting entries and bytes. Useful for benchmarking a
source or flow in isolation.

```toml
[[pipelines.plugin_sinks]]
id   = "discard"
type = "null"
```

No options. The input queue is fixed at 1000.

---

## http

Server-Sent Events stream plus a JSON status endpoint.

```toml
[[pipelines.plugin_sinks]]
id   = "sse"
type = "http"
[pipelines.plugin_sinks.config]
host               = "0.0.0.0"
port               = 8080
stream_path        = "/stream"
status_path        = "/status"
buffer_size        = 1000
client_buffer_size = 256
write_timeout_ms   = 0
max_connections    = 0

[pipelines.plugin_sinks.config.tls]
enabled        = true
cert_file      = "/etc/logwisp/tls/server.crt"
key_file       = "/etc/logwisp/tls/server.key"
client_auth    = true
client_ca_file = "/etc/logwisp/tls/client-ca.crt"

[pipelines.plugin_sinks.config.auth]
type  = "mtls"
allow = ["viewer-01"]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `0.0.0.0` | Bind address; IPv4 only |
| `port` | int | **required** | Listen port |
| `stream_path` | string | `/stream` | SSE endpoint; must start with `/` |
| `status_path` | string | `/status` | Status endpoint; must start with `/` and differ from `stream_path` |
| `buffer_size` | int | `1000` | Sink input queue depth |
| `client_buffer_size` | int | `256` | Per-client send queue depth |
| `write_timeout_ms` | int | `0` | Per-event write deadline; `0` = none |
| `max_connections` | int | `0` | Concurrent stream cap; `0` = unlimited |
| `tls` | table | — | Listener TLS; see [Security](security.md) |
| `auth` | table | — | Client authorization; see [Security](security.md#the-auth-block) |

**Behaviour**

- Only `GET` is routed to either path; anything else gets `405`.
- With an `auth` block, one middleware gates **both** endpoints: an
  unauthorized client gets `403` with no body detail, and the rejection is
  logged at WARN and counted in `auth_rejected`. The authorized identity is
  recorded in the client's session as `auth_method` / `auth_identity`.
- On connect the client receives an `event: connected` frame carrying its
  client id, session id, sink instance id, endpoint paths, and buffer size.
- Payloads are framed per the SSE spec, one `data:` line per newline in the
  payload, so multi-line entries stream correctly.
- The server sets no `WriteTimeout` (that would kill long-lived streams);
  per-write deadlines come from `write_timeout_ms` via `http.ResponseController`.
- A client whose send queue is full has that event dropped
  (`dropped_writes`); it is not disconnected.
- Clients whose session has been idle-expired by the session manager are
  evicted by the broker.
- On shutdown, connected clients receive
  `event: disconnect / data: {"reason":"server_shutdown"}`.
- HTTP/2 is negotiated via ALPN when TLS is enabled; plaintext is HTTP/1.1.

**Status endpoint** returns service and version identity, host, port, TLS flag,
the compiled auth policy, active client count, buffer size, uptime, endpoint
paths, and the `total_processed` / `dropped_writes` / `rejected_clients` /
`auth_rejected` counters.

> Without an `auth` block both endpoints are unauthenticated, and the stream
> response carries `Access-Control-Allow-Origin: *`, so any web origin can read
> it. Set `auth.type = "mtls"` (which requires `tls.client_auth`), bind to a
> trusted interface, or put an authenticating reverse proxy in front.

---

## tcp

Broadcasts formatted payloads to every connected TCP client.

```toml
[[pipelines.plugin_sinks]]
id   = "tap"
type = "tcp"
[pipelines.plugin_sinks.config]
host                 = "0.0.0.0"
port                 = 9090
buffer_size          = 1000
client_buffer_size   = 256
write_timeout_ms     = 5000
keep_alive           = true
keep_alive_period_ms = 30000
max_connections      = 0

[pipelines.plugin_sinks.config.tls]
enabled        = true
cert_file      = "/etc/logwisp/tls/server.crt"
key_file       = "/etc/logwisp/tls/server.key"
client_auth    = true
client_ca_file = "/etc/logwisp/tls/client-ca.crt"

[pipelines.plugin_sinks.config.auth]
type  = "mtls"
allow = ["viewer-01"]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `0.0.0.0` | Bind address; IPv4 only |
| `port` | int | **required** | Listen port |
| `buffer_size` | int | `1000` | Sink input queue depth |
| `client_buffer_size` | int | `256` | Per-client send queue depth |
| `write_timeout_ms` | int | `5000` | Per-write deadline |
| `keep_alive` | bool | `true` | Enable TCP keep-alive on accepted connections |
| `keep_alive_period_ms` | int | `30000` | Keep-alive idle period |
| `max_connections` | int | `0` | Concurrent connection cap; `0` = unlimited |
| `tls` | table | — | Listener TLS |
| `auth` | table | — | Client authorization; see [Security](security.md#the-auth-block) |

**Behaviour**

- The sink is write-only. Each connection also runs a reader that discards
  inbound bytes; it exists to detect disconnects and to refresh session
  activity when a client sends anything.
- A write that misses its deadline means the kernel buffer stayed full for the
  whole timeout, so the client is disconnected immediately rather than retried.
- A client whose send queue is full has that event dropped (`dropped_writes`)
  and stays connected.
- With TLS enabled the handshake runs under a 10 s bound *after* the
  `max_connections` check, so concurrent handshakes are bounded too.
- With an `auth` block, authorization runs after that handshake and *before*
  registration, so an unauthorized client never enters the client map and never
  receives a broadcast. Its connection is closed, the rejection logged at WARN,
  and `rejected_conns` incremented.

---

## tcp_chain

Forwards structured entries to a downstream LogWisp `tcp_chain` source over one
persistent connection. See [Chaining](chaining.md).

```toml
[[pipelines.plugin_sinks]]
id   = "to_relay"
type = "tcp_chain"
[pipelines.plugin_sinks.config]
host                 = "relay.internal"
port                 = 15801
node                 = "edge-01"
buffer_size          = 1000
dial_timeout_ms      = 5000
write_timeout_ms     = 5000
backoff_min_ms       = 500
backoff_max_ms       = 30000
keep_alive           = true
keep_alive_period_ms = 30000

[pipelines.plugin_sinks.config.tls]
enabled   = true
ca_file   = "/etc/logwisp/tls/ca.crt"
cert_file = "/etc/logwisp/tls/client.crt"
key_file  = "/etc/logwisp/tls/client.key"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | **required** | Downstream host |
| `port` | int | **required** | Downstream port |
| `node` | string | `os.Hostname()` | Origin label stamped on first-hop entries |
| `buffer_size` | int | `1000` | Sink input queue depth |
| `dial_timeout_ms` | int | `5000` | TCP connect timeout |
| `write_timeout_ms` | int | `5000` | Per-write deadline |
| `backoff_min_ms` | int | `500` | Reconnect backoff floor |
| `backoff_max_ms` | int | `30000` | Reconnect backoff ceiling |
| `keep_alive` | bool | `true` | Enable TCP keep-alive |
| `keep_alive_period_ms` | int | `30000` | Keep-alive idle period |
| `tls` | table | — | Dialer TLS; `cert_file`/`key_file` present a client identity |
| `auth` | table | — | Server identity pinning; see [Security](security.md#dialer-side-pinning) |

**Behaviour**

- The connection is established lazily, so pipeline start does not depend on the
  downstream being up.
- Each entry is serialized as one canonical JSON line. Delivery holds the line
  across reconnects until it is written or the process shuts down, with
  exponential backoff plus ±20 % jitter between attempts.
- Because delivery blocks the sink's run loop during an outage, back-pressure
  surfaces as a full input queue and is counted by the pipeline as
  `total_dropped_by_sink`.
- With TLS, dial and handshake are bounded together by
  `dial_timeout_ms` + 10 s.
- Events arriving without a structured entry are wrapped from the formatted
  payload and counted in `synthesized`.

An `auth` block on a dialer pins the server's identity: the policy runs as part
of the handshake, so a server it rejects is treated like any other connect
failure and retried under the normal backoff.

**Statistics**: `target`, `node`, `tls`, `auth`, `connected`, `reconnects`,
`write_errors`, `synthesized`.

---

## http_chain

Batches structured entries as NDJSON and POSTs them to a downstream LogWisp
`http_chain` source.

```toml
[[pipelines.plugin_sinks]]
id   = "to_collector"
type = "http_chain"
[pipelines.plugin_sinks.config]
host               = "collector.internal"
port               = 15802
ingest_path        = "/ingest"
node               = "edge-01"
buffer_size        = 1000
max_batch_count    = 100
max_batch_bytes    = 1048576
flush_interval_ms  = 1000
request_timeout_ms = 10000
backoff_min_ms     = 500
backoff_max_ms     = 30000

[pipelines.plugin_sinks.config.tls]
enabled   = true
ca_file   = "/etc/logwisp/tls/ca.crt"
cert_file = "/etc/logwisp/tls/client.crt"
key_file  = "/etc/logwisp/tls/client.key"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | **required** | Downstream host |
| `port` | int | **required** | Downstream port |
| `ingest_path` | string | `/ingest` | Endpoint path; must start with `/` |
| `node` | string | `os.Hostname()` | Origin label stamped on first-hop entries |
| `buffer_size` | int | `1000` | Sink input queue depth |
| `max_batch_count` | int | `100` | Flush after this many entries |
| `max_batch_bytes` | int | `1048576` | Flush after this many bytes (1 MiB) |
| `flush_interval_ms` | int | `1000` | Flush after this long |
| `request_timeout_ms` | int | `10000` | Covers dial, write, and response |
| `backoff_min_ms` | int | `500` | Retry backoff floor |
| `backoff_max_ms` | int | `30000` | Retry backoff ceiling |
| `tls` | table | — | Dialer TLS; `cert_file`/`key_file` present a client identity |
| `auth` | table | — | Server identity pinning; see [Security](security.md#dialer-side-pinning) |

**Behaviour**

- Delivery is at-least-once per batch: a retried batch can be delivered twice if
  the first attempt succeeded but the response was lost.
- Retries apply to transport errors, `408`, `429`, and `5xx`. Any other
  non-2xx response is treated as permanent, and the batch is dropped and counted
  in `dropped_batches`.
- HTTP/2 is off by design; batched NDJSON POSTs gain nothing from it.
- On shutdown a single best-effort flush of the pending batch is attempted.

**Statistics**: `target`, `node`, `tls`, `auth`, `batches_sent`,
`request_errors`, `dropped_batches`, `synthesized`.

---

## Sink Statistics

Every sink reports: `id`, `type`, `total_processed`, `active_connections`,
`start_time`, `last_processed`, and a type-specific `details` map.
