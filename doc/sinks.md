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

Writes formatted payloads to stdout or stderr. It is the sink of the built-in
`pipe` pipeline, and of every spec pipeline given no `--sink`.

```toml
[[pipelines.plugin_sinks]]
id   = "stdout"
type = "console"
[pipelines.plugin_sinks.config]
target      = "stdout"
buffer_size = 1000
escape      = "auto"
color       = "auto"
```

Options, each as type and default:

- `target` (string, `stdout`): `stdout` or `stderr`.
- `buffer_size` (int, `1000`): sink input queue depth.
- `escape` (string, `auto`): write control characters as `<hex>` of their
  bytes, `ESC` as `<1b>`: `auto` when the output is a terminal, `always`, or
  `never`.
- `color` (string, the top-level `color`, itself `auto`): paint level names:
  `auto` on a terminal with `NO_COLOR` unset and `TERM` not `dumb`, `always`,
  or `never`.

> `split` is **not** a valid target for this sink and is rejected at startup.
> Level-based splitting exists only for LogWisp's own application log
> (`logging.output = "split"`).

Payloads are written as the formatter made them, one record per line.

- Escaping: a log line must not drive the terminal that shows it (cursor and
  screen control, title changes, OSC 52 clipboard writes, bidi spoofing). C0
  and C1 controls other than tab, DEL, the bidi controls, the line and
  paragraph separators and invalid UTF-8 are escaped; other invisible
  characters, such as the joiners emoji and Indic scripts need, are kept.
  `never` keeps an application's own ANSI colours; under `auto`, pipes and
  files get the bytes unchanged.
- Color: the first whole word in a line, in any case, that names the entry's
  level is painted: `DEBUG`/`DBG` cyan (blue is hard to read on black),
  `INFO`/`INF` green, `WARNING`/`WARN` yellow, `ERROR`/`ERR`/`FATAL` bold red,
  `TRACE` grey. The colors are ANSI 16, so the terminal's theme picks the
  shades and a Linux or BSD text console renders them; the codes are the
  sink's own, written after escaping. A line whose source found no level
  stays plain. The codes go into whatever the format makes, JSON included:
  for output another program parses keep `auto` or `never`, not `always`.
- Backpressure: the sink never drops. When its output is slow (a slow reader,
  a paused terminal, a stalled log collector) the pipeline waits for it, with
  its other sinks. A service whose stdout may stall writes to a `file` sink
  instead. A closed stdout pipe ends lw with `SIGPIPE`, as it ends `cat`.
- On stop it writes what is queued.

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

Options, each as type and default:

- `directory` (string, **required**): output directory.
- `name` (string, **required**): base filename.
- `max_size_mb` (int, `100`): rotate when the active file reaches this size.
- `max_total_size_mb` (int, `1000`): cap across all rotated files.
- `min_disk_free_mb` (int, `0`): free-space floor before writing; `0` = none.
- `retention_hours` (float, `168.0`): delete rotated files older than this.
- `buffer_size` (int, `1000`): sink input queue depth, and the depth of the
  internal writer's queue, which drops and counts when full.
- `flush_interval_ms` (int, `100`): forced flush interval.

> `min_disk_free_mb` has an unusual default. The constructor replaces only
> *negative* values with `100`; leaving the key unset yields `0`, which means no
> free-space floor. Set it explicitly if you want one.

The sink drives an internal writer configured for raw output with timestamps and
levels disabled, so what lands on disk is exactly the formatted payload. On stop
it hands the writer what is queued before closing the file.

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

Server-Sent Events stream, a JSON status endpoint, and a browser viewer.

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

Options, each as type and default:

- `host` (string, `0.0.0.0`): bind address, IPv4 or IPv6 (`::`); the listener
  keeps to its family ([Networking](networking.md#address-family)).
- `port` (int, **required**): listen port.
- `stream_path` (string, `/stream`): SSE endpoint, matched exactly (`/logs/`
  does not answer `/logs/x`); it starts with `/`, is clean (no `//`, `.` or
  `..` segment) and holds none of `{`, `}`, `%`, `?`, `#`.
- `status_path` (string, `/status`): status endpoint, under the same rules;
  differs from `stream_path`.
- `buffer_size` (int, `1000`): sink input queue depth.
- `client_buffer_size` (int, `256`): per-client send queue depth.
- `write_timeout_ms` (int, `0`): per-event write deadline; `0` = none.
- `max_connections` (int, `0`): concurrent stream cap; `0` = unlimited.
- `login_page` (bool, `false`): `scram` in proxy mode only (an error
  elsewhere): the browser login page at `/auth/login`.
- `viewer_page` (bool, `false`): `scram` in proxy mode only (an error
  elsewhere): the live viewer at `/auth/view`; needs `login_page`. Without
  auth, or under `mtls`, the viewer is always served.
- `tls` (table): listener TLS; see [Security](security.md).
- `auth` (table): client authentication (`mtls` or `scram`); see
  [Security](security.md#the-auth-block).
- `acl` (table): `allow` and `deny`, addresses or CIDRs admitted and refused
  before TLS, and `proxy_protocol` with `proxy_from` for the client a PROXY
  header names; see [Security](security.md#the-acl-block).

**Behaviour**

- Only `GET` is routed to either path; anything else gets `405`, `HEAD` on
  `stream_path` included — a stream is a body, and a client registered to have
  its body discarded never reads and never leaves.
- With an `auth` block, one middleware gates **both** endpoints, with no body
  detail in a refusal. Under `mtls` a refused certificate gets `403`. Under
  `scram` a client logs in at `POST /auth`, which sits outside the gate (see
  [`lw auth token`](cli.md#lw-auth)), and sends
  `Authorization: Bearer <token>`; a missing, invalid or expired token gets
  `401` with `WWW-Authenticate`, a certificate that does not match the token's
  user `403`. A stream is checked when it connects and outlives its token; a
  reload ends it. `/auth` and every path under it are reserved.
- With `auth.trusted_proxies` (proxy mode) the sink sits behind a site's
  TLS-terminating reverse proxy: only the proxies may connect, browsers log in
  through `/auth/login` or the site's own copy of `/auth/scram.js`, and stream
  and status also accept the `logwisp_session` cookie. See
  [Browsers behind a TLS-terminating proxy](security.md#browsers-behind-a-tls-terminating-proxy).
- `GET /` answers `303` to `auth/view`, a relative `Location` that a proxy
  prefix keeps, wherever a browser can read the stream:
  - without auth, over plain http too: the viewer needs no secure context, so
    `http://ADDRESS:PORT/` works;
  - under `mtls`, with the browser's client certificate (`openssl pkcs12
    -export -in NAME.crt -inkey NAME.key -out NAME.p12` imports it);
  - in proxy mode with `viewer_page`, or to `auth/login` with `login_page`
    alone;
  - never under `scram` on the sink's own TLS, which a browser cannot log in
    to: `/` is refused like any other path;
  - an endpoint at `/` keeps the root, and the viewer stays at `/auth/view`.
  The viewer shows entries from when it connects (the sink keeps no backlog)
  and holds one stream against `max_connections`.
- Refusals are logged at WARN and counted in `auth_rejected`. The authorized
  identity is recorded in the client's session as `auth_method` /
  `auth_identity`.
- On connect the client receives an `event: connected` frame carrying its
  client id, session id, sink instance id, endpoint paths, and buffer size.
- Payloads are framed per the SSE spec, one `data:` line per line break in the
  payload (CRLF, LF or a lone CR), so multi-line entries stream correctly and
  no entry can inject an `event:`, `id:` or `retry:` field.
- The server sets no `WriteTimeout` (that would kill long-lived streams);
  per-write deadlines come from `write_timeout_ms` via `http.ResponseController`
  and cover the connected frame, every payload, and the idle comment.
- A quiet stream emits an SSE comment every 15 s. It refreshes the client's
  session and is how a peer that stopped reading is noticed.
- A client whose send queue is full has that event dropped
  (`dropped_writes`); it is not disconnected. A `dropped_writes` that rises while
  no client is behind is a burst larger than `client_buffer_size`, not
  backpressure: size the queue at or above whatever burst the pipeline's
  `rate_limit` releases at once.
- A client is registered only once its connected frame has flushed, so the
  broker never queues into a buffer whose reader has not started.
- Clients whose session has been idle-expired by the session manager are
  evicted by the broker. With the idle comment above, that reaches only a peer
  that has stopped accepting bytes on a sink configured `write_timeout_ms = 0`.
- On shutdown (a reload too), each stream writes its queue and what remains
  of the sink's input, then
  `event: disconnect / data: {"reason":"server_shutdown"}`, on its own and
  within `write_timeout_ms`, at most 2 s; a client still behind is cut then,
  and one that stopped reading costs the others nothing.
- HTTP/2 is negotiated via ALPN when TLS is enabled; plaintext is HTTP/1.1.

**Status endpoint** returns service and version identity, host, port, TLS flag,
the compiled auth policy and acl, active client count, sink and per-client
buffer sizes, connection limit, write timeout, uptime, endpoint paths, and the
`total_processed` / `dropped_writes` / `rejected_clients` / `auth_rejected` /
`acl_denied` counters.

**Statistics**: `dropped_writes`, `rejected_clients`, `auth`, `auth_allowed`,
`auth_rejected`; under `scram` also `auth_users`, `auth_throttled`,
`auth_busy`, `auth_binding_mismatch` and `auth_token_lifetime_ms`, and in
proxy mode `auth_trusted_proxies`; with `acl` rules or `proxy_from` also
`acl`, `acl_denied` and `acl_proxy_headers`.

> Without an `auth` block both endpoints are unauthenticated, and the stream
> response carries `Access-Control-Allow-Origin: *`, so any web origin can read
> it. With one, the header is omitted. Set an `auth` block, bind to a trusted
> interface, or put an authenticating reverse proxy in front.

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

Options, each as type and default:

- `host` (string, `0.0.0.0`): bind address, IPv4 or IPv6 (`::`); the listener
  keeps to its family ([Networking](networking.md#address-family)).
- `port` (int, **required**): listen port.
- `buffer_size` (int, `1000`): sink input queue depth.
- `client_buffer_size` (int, `256`): per-client send queue depth.
- `write_timeout_ms` (int, `5000`): per-write deadline.
- `keep_alive` (bool, `true`): TCP keep-alive on accepted connections.
- `keep_alive_period_ms` (int, `30000`): keep-alive idle period.
- `max_connections` (int, `0`): concurrent connection cap; `0` = unlimited.
- `tls` (table): listener TLS.
- `auth` (table): client authentication (`mtls` or `scram`); see
  [Security](security.md#the-auth-block).
- `acl` (table): `allow` and `deny`, addresses or CIDRs admitted and refused
  before TLS, and `proxy_protocol` with `proxy_from` for the client a PROXY
  header names; see [Security](security.md#the-acl-block).

**Behaviour**

- The sink is write-only. Each connection also runs a reader that discards
  inbound bytes; it exists to detect disconnects and to refresh session
  activity when a client sends anything. Under `scram` the client must log in
  first: a hello carrying the login, then challenge, proof and final, all
  within 10 s, after which the stream follows on the same connection. `nc` and
  `openssl s_client` cannot do this; use
  [`lw auth stream`](cli.md#lw-auth).
- A write that misses its deadline means the kernel buffer stayed full for the
  whole timeout, so the client is disconnected immediately rather than retried.
- A client whose send queue is full has that event dropped (`dropped_writes`)
  and stays connected.
- On shutdown, as with the `http` sink, each client receives what is queued,
  within `write_timeout_ms`, at most 2 s, before it is disconnected.
- With TLS enabled the handshake runs under a 10 s bound *after* the
  `max_connections` check, so concurrent handshakes are bounded too.
- With an `auth` block, authorization runs after that handshake and *before*
  registration, so an unauthorized client never enters the client map and never
  receives a broadcast. Its connection is closed, the rejection logged at WARN,
  and `rejected_conns` incremented.

**Statistics**: `write_errors`, `dropped_writes`, `rejected_conns`,
`tls_handshake_errors`, `auth`, `auth_allowed`, `auth_rejected`; under `scram`
also `auth_users`, `auth_throttled`, `auth_busy` and `auth_binding_mismatch`;
with `acl` rules or `proxy_from` also `acl`, `acl_denied` and
`acl_proxy_headers`.

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

Options, each as type and default:

- `host` (string, **required**): downstream host or address; an IPv6 one goes
  bare (`::1`).
- `port` (int, **required**): downstream port.
- `node` (string, `os.Hostname()`): origin label stamped on first-hop entries.
- `buffer_size` (int, `1000`): sink input queue depth.
- `dial_timeout_ms` (int, `5000`): TCP connect timeout.
- `write_timeout_ms` (int, `5000`): per-write deadline.
- `backoff_min_ms` (int, `500`): reconnect backoff floor.
- `backoff_max_ms` (int, `30000`): reconnect backoff ceiling.
- `keep_alive` (bool, `true`): TCP keep-alive.
- `keep_alive_period_ms` (int, `30000`): keep-alive idle period.
- `tls` (table): dialer TLS; `cert_file`/`key_file` present a client identity.
- `auth` (table): server identity pinning (`mtls`) or a login (`scram`); see
  [Security](security.md#the-auth-block).

**Behaviour**

- The connection is established lazily, so pipeline start does not depend on the
  downstream being up.
- Under `scram` the hello carries the login, and the link counts as established
  only once the server's final message proves it holds the user's verifier. The
  exchange is bounded at 10 s and cut short by shutdown. A refusal —
  `authentication failed`, `authentication not enabled`, `no challenge within
  10s` — is logged at WARN as `Chain connect refused` on every attempt; other
  connect failures log at DEBUG. Both retry under the normal backoff.
- Each entry is serialized as one canonical JSON line. Delivery holds the line
  across reconnects until it is written or the process shuts down, with
  exponential backoff plus ±20 % jitter between attempts. The delay keeps
  growing until a link outlives `backoff_min_ms`, so a source that drops every
  link right after accepting it is not retried in a tight loop.
- On shutdown (a reload too) the sink delivers what is queued, connecting
  first if it must, within `write_timeout_ms`, at most 2 s; then the link
  closes and what is left is lost.
- A source never writes once a link is up, so the sink watches each link: a
  line from the source is a refusal (a sink without `scram` facing a `scram`
  source), logged at WARN as `Chain link refused`; EOF ends the link at once
  instead of at the next failed write.
- Because delivery blocks the sink's run loop during an outage, back-pressure
  surfaces as a full input queue and is counted by the pipeline as
  `total_dropped_by_sink`.
- With TLS, dial and handshake are bounded together by
  `dial_timeout_ms` + 10 s.
- Events arriving without a structured entry are wrapped from the formatted
  payload and counted in `synthesized`.

Under `mtls` the policy pins the server's identity as part of the handshake, so
a server it rejects is refused like a failed login above.

**Statistics**: `target`, `node`, `tls`, `auth`, `connected`, `reconnects`,
`write_errors`, `synthesized`; under `scram` also `auth_username`,
`auth_failures` and `last_auth_error` (empty after a successful login).

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

Options, each as type and default:

- `host` (string, **required**): downstream host or address; an IPv6 one goes
  bare (`::1`).
- `port` (int, **required**): downstream port.
- `ingest_path` (string, `/ingest`): endpoint path; must start with `/`.
- `node` (string, `os.Hostname()`): origin label stamped on first-hop entries.
- `buffer_size` (int, `1000`): sink input queue depth.
- `max_batch_count` (int, `100`): flush after this many entries.
- `max_batch_bytes` (int, `1048576`): flush after this many bytes (1 MiB).
- `flush_interval_ms` (int, `1000`): flush after this long.
- `request_timeout_ms` (int, `10000`): covers dial, write, and response.
- `backoff_min_ms` (int, `500`): retry backoff floor.
- `backoff_max_ms` (int, `30000`): retry backoff ceiling.
- `tls` (table): dialer TLS; `cert_file`/`key_file` present a client identity.
- `auth` (table): server identity pinning (`mtls`) or a login (`scram`); see
  [Security](security.md#the-auth-block).

**Behaviour**

- Delivery is at-least-once per batch: a retried batch can be delivered twice if
  the first attempt succeeded but the response was lost.
- Retries apply to transport errors, `408`, `429`, and `5xx`. Any other
  non-2xx response is treated as permanent, and the batch is dropped and counted
  in `dropped_batches`. A retry is logged at WARN, a dropped batch at ERROR.
- Under `scram` the sink logs in at `POST /auth` whenever it holds no token and
  sends `Authorization: Bearer <token>`. A failed login is retried like a
  transport error, holding the batch. The token is renewed ahead of its expiry;
  a `401` on ingest (the source reloaded) drops it and the retry logs in again.
  A `403` is permanent. A connection presenting a certificate other than the
  one the login was bound to drops token and pin, and the retry logs in anew.
  A sink without `scram` facing a `scram` source gets `401` and drops every
  batch.
- Redirects are never followed; a `3xx` is permanent too. Following one would
  resend the batch wherever the response points, plaintext `http` included.
- HTTP/2 is off by design; batched NDJSON POSTs gain nothing from it.
- On shutdown (a reload too) the sink delivers what is queued and batched
  within `request_timeout_ms`, at most 2 s; each batch still undelivered then
  is dropped and logged at WARN.

**Statistics**: `target`, `node`, `tls`, `auth`, `batches_sent`,
`request_errors`, `dropped_batches`, `synthesized`; under `scram` also
`auth_username`, `auth_failures` and `last_auth_error`.

---

## Sink Statistics

Every sink reports: `id`, `type`, `total_processed`, `active_connections`,
`start_time`, `last_processed`, and a type-specific `details` map. The DEBUG
status report spreads `details` into each plugin's line.
