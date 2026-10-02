# Networking

Everything LogWisp does over a socket, and the knobs that shape it. For
certificates and trust see [Security](security.md); for multi-node topologies
see [Chaining](chaining.md).

## Address Family

Every listener and dialer keeps strictly to the family of its `host`:

- IPv4 literal (`127.0.0.1`, the default `0.0.0.0`): IPv4 only (`tcp4`). An
  empty `host` is the IPv4 wildcard, as `0.0.0.0`.
- IPv6 literal (`::1`, `::`, `fe80::1%eth0`): IPv6 only (`tcp6`).
  - `::` takes no IPv4 connections, on Linux and FreeBSD alike, whatever the
    system's `bindv6only` default.
  - To serve both families, run two listeners on the same port, one on
    `0.0.0.0` and one on `::`: neither holds the other's port.
- Hostname: resolved. A listener binds one address (IPv4 when there is one),
  so name the address to be sure; a dialer tries each address in turn.

### IPv6

- Notation
  - `host` takes the bare address: `host = "::1"`. A bracketed host, one
    with a port, or an IPv4-mapped one (`::ffff:10.0.0.1`) fails at load.
  - Addresses and URLs bracket it: logs print `[::1]:8443`, and `lw auth`
    takes `-addr [::1]:8443` and `-url https://[::1]:8443`. Give `curl` `-g`,
    or it reads the brackets as a glob.
  - A link-local address carries its zone, `fe80::1%eth0`, escaped in URLs as
    `https://[fe80::1%25eth0]:8443`.
- TLS: a dialer verifies an IPv6 target against the certificate's IP SANs
  (`subjectAltName = IP:::1`), as it does an IPv4 one. The zone is not part of
  the name; `server_name` overrides as usual.
- Peers
  - Logs and sessions name an IPv6 peer by its address, a link-local one with
    its zone.
  - SCRAM throttling counts an IPv6 client by its /64, so the hosts on a link
    share one link-local budget: each can pick any `fe80::/64` address.
  - A peer with a zone never matches `auth.trusted_proxies`: put the proxy on
    loopback or a routed address.

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
| `tcp_chain` source | `hello_timeout_ms` | `10000` | Reading the protocol preamble, and under `scram` the whole login |
| `tcp_chain` source | `read_timeout_ms` | `0` (none) | Idle time between entries |
| `http_chain` source | `read_timeout_ms` | `30000` | Reading a whole request body |
| `tcp_chain` sink | `dial_timeout_ms` | `5000` | TCP connect |
| `tcp_chain` sink | `write_timeout_ms` | `5000` | One line write |
| `http_chain` sink | `request_timeout_ms` | `10000` | Dial plus write plus response, and a SCRAM login when one is due |

Fixed, non-configurable bounds:

| Bound | Value | Applies to |
|-------|-------|------------|
| TLS handshake | 10 s | All TLS listeners and dialers |
| HTTP read-header timeout | 10 s | `http` sink, `http_chain` source |
| HTTP server shutdown grace | 2 s | `http` sink, `http_chain` source |
| Max single entry line | 1 MiB | Chain listeners |
| SCRAM login | 10 s | `tcp` sink, chain sinks, `lw auth`, each `/auth` request |
| SCRAM line or `/auth` body | 4 KiB | `scram` listeners and dialers |

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

Apart from SCRAM logins, which are throttled per address (see
[Security](security.md#throttling)), there is **no** per-IP limiting and no IP
allow/deny list. `flow.rate_limit` is a pipeline-wide entry rate limit, not a
network-level one — it cannot distinguish or throttle an individual peer.

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
`X-Accel-Buffering: no`, and, without an auth policy,
`Access-Control-Allow-Origin: *`. Under `scram`, `POST /auth` serves the login
and both paths take `Authorization: Bearer <token>`.

**TCP sink** — raw payload bytes, no framing added by the sink. Whether entries
are newline-delimited depends on the formatter. Under `scram` the client's hello
and login lines come first, as on a [chain link](chaining.md#tcp-transport).

**Chain transports** — see [Chaining](chaining.md) for the hello preamble,
headers, and entry encoding.

## Troubleshooting

**Plugin fails to start with `unknown key "..."`**
- The key is misspelled or belongs to another plugin type. Every plugin rejects
  keys it does not declare, nested tables included, so a typo in `tls` or `auth`
  cannot leave a protection silently off.

**Connection refused**
- Confirm the pipeline started; a bind failure is logged at ERROR.
- Confirm the dialer uses the listener's family: `[::1]` does not reach a
  `127.0.0.1` or `0.0.0.0` listener, nor `127.0.0.1` a `::` one. `localhost`
  may resolve to either.
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

**Rejected after a successful handshake**
- `auth: identity "..." is not allowed` — the certificate is valid and chains to
  the CA, but the identity is not in `auth.allow` / `auth.allow_patterns`. On
  TCP the connection is closed; on HTTP the answer is `403`.
- `auth: peer certificate carries no <mode> identity` — `auth.identity` names a
  field the certificate does not populate, e.g. `san_dns` on a CN-only leaf.
- `auth: node_binding "assert": declared node "..." does not match identity` —
  the sender's `node` option and its certificate disagree. Fix one, or use
  `node_binding = "force"` to let the certificate win silently.
- On a `tcp_chain` sink the same message inside `Chain connect refused` means
  the *server* was refused: its certificate identity is not in the sink's
  `auth.allow`.
- Rejections appear as WARN and increment `auth_rejected`.

**SCRAM login fails**
- `authentication failed` — the dialer is not told why, by design. The
  listener's WARN line (`Connection rejected by auth policy` on TCP,
  `Login rejected` on HTTP) is: `invalid credentials` for a wrong password, an
  unknown user, or one removed or rotated on the listener (compare the
  `password_file` with the last `add-user`, and check the listener got
  `SIGHUP`); `certificate cn "…" does not match user "…"` for the `identity`
  binding.
- `the client saw another server certificate: TLS interception or a terminating
  proxy` in the listener's log, with `auth_binding_mismatch` rising — something
  between the peers terminates TLS. Pass TLS through to LogWisp; the login
  cannot work otherwise, except on an `http` sink in proxy mode
  (`auth.trusted_proxies`), where `the client bound its proof to the proxy's
  certificate` means a client that needs `lw auth token -unbound`, and
  `the client sent an unbound proof` the reverse. On an `http_chain` sink,
  `server certificate differs from the one the SCRAM login was bound to` means
  the certificate changed after the login: a rotation (the retry binds anew),
  several backends, or interception.
- `403` from an `http` sink in proxy mode, with `not a trusted proxy` or
  `X-Forwarded-Proto` in its WARN line — the request did not come from a listed
  proxy, or the proxy did not forward `X-Forwarded-Proto: https` and
  `X-Forwarded-For`.
- `too many attempts` — the address failed or abandoned logins faster than one
  per second beyond a burst of 10, or has 4 unfinished; it clears within seconds
  once the failing peer stops. Peers behind one NAT share the budget. `busy` —
  4,096 logins in flight, or the listener is stopping.
- `authentication not enabled` — the dialer has `scram`; the listener's
  `auth.type` is `none` or `mtls`.
- `no challenge within 10s (older logwisp, or not a scram listener)` — the
  server read the hello and said nothing. Over HTTP the same case reads
  `no auth endpoint at …/auth`.
- `Argon2 parameters below client minimum` — the credentials file holds a
  cheaper Argon2 profile than the defaults; recreate it with `lw auth`.
- `peer offered no credentials` (`authentication required` on the wire) in the
  listener's log — a peer without `scram` reached a `scram` listener; a client
  that sends nothing logs `read hello: … i/o timeout` after 10 s instead. A
  `tcp_chain` sink without `scram` logs WARN `Chain link refused` with that
  reason and retries under growing backoff; what it wrote before reading the
  refusal is lost. An `http_chain` sink without `scram` gets `401` and drops
  every batch.

**`401` on HTTP under `scram`**
- An `http_chain` sink renews its token before it expires, so a `401` means
  the listener reloaded (every reload revokes all tokens); the retry logs in
  again.
- Continuous `401` means the token never sticks: several LogWisp processes
  behind one address, a proxy that strips `Authorization`, or a
  `token_lifetime_ms` shorter than a request takes. A token used with `curl`
  dies with every listener reload.
- `403` is not the token: it is the `identity` binding, node binding or, in
  proxy mode, the proxy gate.

**Entries not arriving over a chain link**
- Check the sink's `connected` statistic and its `reconnects` count.
- Check the source's `auth_rejected` — an allow-list miss or a failed login
  looks exactly like a network fault from the sender's side — and the sink's
  `last_auth_error`.
- Check the source's `parse_errors` — a version skew shows up here.
- On `http_chain`, remember entries wait up to `flush_interval_ms` before a
  batch is sent.

**Entries arriving under an unexpected node label**
- `auth.node_binding` defaults to `force` with any `auth` block, which
  relabels every entry with the sender's certificate identity or username. If
  a dashboard suddenly shows a different label, that is why. Use
  `node_binding = "assert"` to keep upstream origin labels on relay-to-relay
  hops, or `"none"` to leave `trust_node` in charge.

**Clients connect but see nothing**
- The pipeline may be filtering everything out; check `flow.filters` stats.
- The rate limiter may be dropping everything; check `rate_limiter` stats.
- Nothing may be arriving from the sources; check source `total_entries`.

**Entries missing under load**
- Compare `dropped_writes` (per-client queue full — raise
  `client_buffer_size`) against `total_dropped_by_sink` (sink input queue full
  — raise `buffer_size` or reduce sink latency).
