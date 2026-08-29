# Networking

Everything LogWisp does over a socket, and the knobs that shape it. For
certificates and trust see [Security](security.md); for multi-node topologies
see [Chaining](chaining.md).

## Address Family

**All listeners bind `tcp4` and all dialers dial `tcp4`.** IPv6 is not
supported, deliberately. An IPv6 client cannot connect and will simply see a
connection failure.

When testing locally use `127.0.0.1`, not `localhost` — the latter may resolve
to `::1` and appear as an unexplained connection refusal.

## Network Plugins

| Plugin | Role | Protocol | Purpose |
|--------|------|----------|---------|
| `tcp` sink | Listener | Raw stream | Broadcast formatted payloads to clients |
| `http` sink | Listener | HTTP SSE | Browser-friendly live stream plus status JSON |
| `tcp_chain` source | Listener | Chain v1 | Ingest a persistent NDJSON stream |
| `http_chain` source | Listener | Chain v1 | Ingest NDJSON batches over POST |
| `tcp_chain` sink | Dialer | Chain v1 | Forward entries over a persistent connection |
| `http_chain` sink | Dialer | Chain v1 | Forward entries as batched POSTs |

There is no port registry and no default port: `port` is required on every
network plugin. There is also no cross-pipeline conflict detection — two sinks
on the same port fail at bind time when the pipeline starts:

```
ERROR msg="Failed to start sink" error="tcp sink bind 0.0.0.0:9090: listen tcp4 0.0.0.0:9090: bind: address already in use"
```

## Timeouts

Every network plugin exposes the deadlines relevant to its role. Zero means "no
deadline" wherever the table says so.

| Plugin | Option | Default | Bounds |
|--------|--------|---------|--------|
| `tcp` sink | `write_timeout_ms` | `5000` | One write to one client; a miss disconnects that client |
| `http` sink | `write_timeout_ms` | `0` (none) | One SSE event write |
| `tcp_chain` source | `hello_timeout_ms` | `10000` | Reading the protocol preamble |
| `tcp_chain` source | `read_timeout_ms` | `0` (none) | Idle time between entries |
| `http_chain` source | `read_timeout_ms` | `30000` | Reading a whole request body |
| `tcp_chain` sink | `dial_timeout_ms` | `5000` | TCP connect |
| `tcp_chain` sink | `write_timeout_ms` | `5000` | One line write |
| `http_chain` sink | `request_timeout_ms` | `10000` | Dial plus write plus response |

Fixed, non-configurable bounds:

| Bound | Value | Applies to |
|-------|-------|------------|
| TLS handshake | 10 s | All TLS listeners and dialers |
| HTTP read-header timeout | 10 s | `http` sink, `http_chain` source |
| HTTP server shutdown grace | 2 s | `http` sink, `http_chain` source |
| Max single entry line | 1 MiB | Chain listeners |

The `http` sink deliberately leaves the server's `WriteTimeout` unset, since it
would terminate long-lived SSE streams; per-event deadlines come from
`write_timeout_ms` instead.

## Connection Limits

`max_connections` caps concurrent connections on the `tcp` sink, the `http`
sink, and the `tcp_chain` source. `0` means unlimited.

- Admission is a load-then-check, so a burst can over-admit by roughly one
  connection. This is accepted, not a bug to work around.
- On the `tcp` sink and `tcp_chain` source the count is taken at accept, so it
  bounds concurrent TLS handshakes as well as established sessions.
- Over-limit connections are closed immediately and counted in `rejected_conns`
  (TCP) or `rejected_clients` (HTTP, which first answers `503`).

The `http_chain` source has no connection cap; it bounds work with
`max_body_bytes` and `read_timeout_ms` instead.

There is **no** per-IP limiting and no IP allow/deny list. `flow.rate_limit` is
a pipeline-wide entry rate limit, not a network-level one — it cannot
distinguish or throttle an individual peer.

## Keep-Alive

TCP keep-alive is available on the `tcp` sink (for accepted connections) and the
`tcp_chain` sink (for its outbound connection):

```toml
keep_alive           = true
keep_alive_period_ms = 30000
```

This is kernel-level keep-alive; it detects a dead peer but does not keep an
application-level stream flowing. For that, use a heartbeat.

## Heartbeats

Heartbeats are a **flow-level** feature, not a per-sink one. Enabling one
injects a synthetic entry into the pipeline at a fixed interval; it reaches
every sink and traverses chain links as an ordinary structured entry.

```toml
[pipelines.flow.heartbeat]
enabled           = true
interval_ms       = 30000
include_timestamp = true
include_stats     = false
format            = "txt"      # txt | json | raw
```

Use it to keep idle SSE clients, TCP clients, and chain links from being
reaped by intermediate NAT or proxy timeouts, and to make an idle pipeline
visibly alive.

> `format = "comment"` (SSE `:` comment framing) is rejected by validation
> despite appearing in older documentation and in a still-present code branch.
> A pipeline configured with it fails to start.

## Reconnection

Chain sinks reconnect on their own. Both use exponential backoff between
`backoff_min_ms` and `backoff_max_ms` with ±20 % jitter, and both are
interruptible by shutdown.

```toml
backoff_min_ms = 500
backoff_max_ms = 30000
```

The connection is established lazily, so an edge node starts cleanly even when
its relay is down and connects as soon as the relay appears. Reconnect counts
are reported in the sink's `reconnects` statistic.

Server-side sinks (`tcp`, `http`) do not reconnect; clients are expected to
retry. Browsers reconnect SSE streams automatically.

## Protocol Details

**HTTP sink (SSE)** — HTTP/1.1 in plaintext; HTTP/2 is negotiated via ALPN when
TLS is enabled. Only `GET` is routed to the stream and status paths. Each event
is framed as one `data:` line per newline in the payload, so multi-line entries
stream intact. Response headers set `Cache-Control: no-cache`,
`X-Accel-Buffering: no`, and `Access-Control-Allow-Origin: *`.

**TCP sink** — raw payload bytes, no framing added by the sink. Whether entries
are newline-delimited depends on the formatter.

**Chain transports** — see [Chaining](chaining.md) for the hello preamble,
headers, and entry encoding.

## Troubleshooting

**Connection refused**
- Confirm the pipeline started; a bind failure is logged at ERROR.
- Confirm you are dialing IPv4. `localhost` may resolve to `::1`.
- Check the port is not already bound by another pipeline in the same process.

**TLS handshake failure**
- `client didn't provide a certificate` — the listener has `client_auth = true`
  and the dialer has no `cert_file`/`key_file`.
- `certificate signed by unknown authority` — the dialer's `ca_file` does not
  contain the issuer of the server certificate, or the listener's
  `client_ca_file` does not contain the issuer of the client certificate.
- `certificate is not valid for any names` / SAN mismatch — the dialed `host`
  is not covered by the server certificate's SANs; set `server_name`.
- `protocol version not supported` — one side is pinned to `min_version = "1.3"`
  and the other cannot negotiate it.
- Handshake failures appear as WARN with the remote address, and increment
  `tls_handshake_errors`.

**Entries not arriving over a chain link**
- Check the sink's `connected` statistic and its `reconnects` count.
- Check the source's `parse_errors` — a version skew shows up here.
- On `http_chain`, remember entries wait up to `flush_interval_ms` before a
  batch is sent.

**Clients connect but see nothing**
- The pipeline may be filtering everything out; check `flow.filters` stats.
- The rate limiter may be dropping everything; check `rate_limiter` stats.
- Nothing may be arriving from the sources; check source `total_entries`.

**Entries missing under load**
- Compare `dropped_writes` (per-client queue full — raise
  `client_buffer_size`) against `total_dropped_by_sink` (sink input queue full
  — raise `buffer_size` or reduce sink latency).
