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
- Hostname: resolved. A listener binds one address (IPv4 when there is one)
  in that address's family alone, a name for `0.0.0.0` or `::` too, so name
  the address to be sure; a dialer tries each address in turn.

### IPv6

- Notation
  - `host` takes the bare address: `host = "::1"`. A bracketed host, one
    with a port, or an IPv4-mapped one (`::ffff:10.0.0.1`) fails at load.
  - Addresses and URLs bracket it: logs print `[::1]:8443`, and `lw auth`
    takes `--addr [::1]:8443` and `--url https://[::1]:8443`. Older `curl`
    releases read the brackets as a glob; `-g` stops that and is harmless.
  - A link-local address carries its zone, `fe80::1%eth0`, escaped in URLs as
    `https://[fe80::1%25eth0]:8443`.
- TLS: a dialer verifies an IPv6 target against the certificate's IP SANs
  (`subjectAltName = IP:::1`), as it does an IPv4 one. The zone is not part of
  the name; `server_name` overrides as usual.
- Peers
  - Logs and sessions name an IPv6 peer by its address, a link-local one with
    its zone.
  - SCRAM throttling counts an IPv6 client by its /64, so the hosts on a link
    share one link-local budget per interface (zone): each can pick any
    `fe80::/64` address.
  - A peer with a zone never matches `auth.trusted_proxies`: put the proxy on
    loopback or a routed address.

## Network Plugins

Listeners:

- `tcp` sink: raw stream; broadcasts formatted payloads to clients.
- `http` sink: HTTP SSE; a browser viewer at `/`, the live stream and status
  JSON.
- `tcp_chain` source: chain v1; ingests a persistent NDJSON stream.
- `http_chain` source: chain v1; ingests NDJSON batches over POST.

Dialers:

- `tcp_chain` sink: chain v1; forwards entries over a persistent connection.
- `http_chain` sink: chain v1; forwards entries as batched POSTs.

There is no port registry and no default port: `port` is required on every
network plugin. Two sinks on the same port pass `lw --check` and fail at bind
when the service starts; lw exits 1:

```
ERROR msg "Failed to initialize service" error "failed to start service pipelines: failed to start pipeline <name>: failed to start sink <id>: tcp sink bind <host>:<port>: listen tcp4 <host>:<port>: bind: address already in use"
```

## Timeouts

Every network plugin exposes the deadlines relevant to its role. `0` means no
deadline where the default is `0` (none); elsewhere it selects the default.

- `tcp` sink
  - `write_timeout_ms`, default `5000`: one write to one client; a miss
    disconnects that client.
- `http` sink
  - `write_timeout_ms`, default `0` (none): one SSE event write.
- `tcp_chain` source
  - `hello_timeout_ms`, default `10000`: reading the protocol preamble, and
    under `scram` the whole login.
  - `read_timeout_ms`, default `0` (none): idle time between entries.
- `http_chain` source
  - `read_timeout_ms`, default `30000`: reading a whole request body.
- `tcp_chain` sink
  - `dial_timeout_ms`, default `5000`: TCP connect.
  - `write_timeout_ms`, default `5000`: one line write.
- `http_chain` sink
  - `request_timeout_ms`, default `10000`: dial plus write plus response, and
    a SCRAM login when one is due.

Fixed, non-configurable bounds:

- TLS handshake: 10 s, on all TLS listeners and dialers.
- HTTP read-header timeout: 10 s, on the `http` sink and `http_chain` source.
- HTTP server shutdown grace: 2 s on the `http_chain` source and the `http`
  sink; on the `http` sink, `write_timeout_ms` instead when set below 2 s.
- Single entry line: at most 1 MiB, on chain listeners.
- SCRAM login: 10 s, on the `tcp` sink, chain sinks, `lw auth`, and each
  `/auth` request.
- SCRAM line or `/auth` body: at most 4 KiB, on `scram` listeners and dialers.

The `http` sink deliberately leaves the server's `WriteTimeout` unset, since it
would terminate long-lived SSE streams; per-event deadlines come from
`write_timeout_ms` instead.

## Connection Limits

`max_connections` caps concurrent connections on the `tcp` sink and the
`tcp_chain` source, and concurrent streams on the `http` sink (other requests
are not counted); `0` means unlimited.

- Admission is a load-then-check, so a burst can over-admit by roughly one.
- On the `tcp` sink and `tcp_chain` source the count is taken at accept, so it
  bounds concurrent TLS handshakes as well as established sessions.
- Over the limit a TCP connection is closed and counted in `rejected_conns`;
  an `http` stream request is answered `503` and counted in
  `rejected_clients`, its connection kept.

The `http_chain` source has no connection cap; it bounds work with
`max_body_bytes` and `read_timeout_ms` instead.

Per client, the `acl` block caps connections on every listener and requests
on the HTTP ones ([Security](security.md#per-client-limits)), and SCRAM logins
are throttled ([Security](security.md#throttling)). `flow.rate_limit` is a
pipeline-wide entry rate limit: it cannot distinguish or throttle a peer.

## Keep-Alive

The `tcp` sink (accepted connections) and the `tcp_chain` sink (its outbound
connection) configure TCP keep-alive:

```toml
keep_alive           = true    # false sends no probes
keep_alive_period_ms = 30000
```

Probes start after `keep_alive_period_ms` idle. Other listeners and the
`http_chain` sink use Go's default TCP keep-alive (15 s); it is not
configurable there. Keep-alive detects a dead peer but does not keep an
application-level stream flowing: that is a heartbeat's job.

## Heartbeats

A flow heartbeat keeps idle TCP clients and chain links alive through NAT and
proxy timeouts; idle SSE streams already get a comment every 15 s. See
[Configuration](configuration.md#heartbeat).

## Reconnection

Chain sinks reconnect on their own. Both use exponential backoff between
`backoff_min_ms` and `backoff_max_ms` with ±20 % jitter, and both are
interruptible by shutdown.

```toml
backoff_min_ms = 500
backoff_max_ms = 30000
```

The connection is established lazily, so an edge node starts cleanly even when
its relay is down and connects as soon as the relay appears. The `tcp_chain`
sink reports `connected` and `reconnects`; the `http_chain` sink reports
`request_errors` and `dropped_batches`.

Server-side sinks (`tcp`, `http`) do not reconnect; clients are expected to
retry. Browsers reconnect SSE streams automatically.

## Protocol Details

**HTTP sink (SSE)**: HTTP/1.1 in plaintext, HTTP/2 via ALPN under TLS; `GET`
on the stream path, `GET` or `HEAD` on the status path. Framing and headers:
[Sinks](sinks.md#http). Under `scram`, `POST /auth` logs in and both paths
take `Authorization: Bearer <token>`.

**TCP sink**: the formatted payloads, each ending in a newline, with no other
framing; under `json` that is one entry per line, while `raw` passes a
message's own line breaks through. Under `scram` the client's hello and login
lines come first, as on a [chain link](chaining.md#tcp-transport).

**Chain transports**: see [Chaining](chaining.md#wire-protocol) for the hello
preamble, headers, and entry encoding.

## Troubleshooting

**`unknown key "..."` when the configuration loads**
- The key is misspelled or belongs to another plugin type. A plugin's keys are
  checked at load (`lw --check` too), nested tables included, so a typo in
  `tls` or `auth` cannot leave a protection silently off.

**Connection refused**
- Confirm the pipeline started; a bind failure is logged at ERROR.
- Confirm the dialer uses the listener's family: `[::1]` does not reach a
  `127.0.0.1` or `0.0.0.0` listener, nor `127.0.0.1` a `::` one. `localhost`
  may resolve to either.
- Check the port is not already bound by another pipeline in the same process.

**Closed as soon as it connects, before TLS**
- The listener's `acl` refused it: `acl_denied` or `acl_limited` rises, and
  its log has `Connection refused by acl` at WARN with a `reason`, once a
  minute at most. The dialer sees `EOF` or `connection reset by peer` (curl:
  exit 52 or 56).
  - `address rules` — `allow` or `deny` excludes the client: the one a PROXY
    header names (`remote_addr`, the proxy as `peer_addr`), else the socket
    peer. Behind the `http` sink's `auth.trusted_proxies` that is the proxy:
    allow it.
  - `max_connections_per_client` — the client holds that many already, or the
    listener tracks 65,536 clients; HTTP keep-alive connections count too.
  - `no PROXY header` — a peer in `proxy_from` sent none under
    `proxy_protocol = "required"`: the proxy lacks `proxy_protocol on` (nginx)
    or `send-proxy` (HAProxy), or the proxy's host dialed directly.
  - `PROXY header: …` — malformed, too long, or incomplete after 10 s.
  - `PROXY header from a peer outside proxy_from` — at the first read, after
    the connection opened: list the proxy in `proxy_from`.
- `acl: allow entry "...": IPv4, and the listener's host is IPv6` at startup,
  or the reverse: each family's listener takes its own.
  Behind `proxy_from` or `trusted_proxies`, `allow` and `deny` take both;
  `proxy_from` its own.

**HTTP `429 Too Many Requests` with `Retry-After`**
- `requests_per_second_per_client`: `acl_limited` rises and the log has
  `Request refused by acl`, once a minute at most. A browser's page load
  takes several requests; raise the rate rather than retry faster. From
  `/auth` with `too many attempts`, it is SCRAM throttling (below).

**TLS handshake failure**
- `client didn't provide a certificate` — the listener has `client_auth = true`
  and the dialer has no `cert_file`/`key_file`.
- `certificate signed by unknown authority` — the dialer's `ca_file` does not
  contain the issuer of the server certificate, or the listener's
  `client_ca_file` does not contain the issuer of the client certificate.
- `certificate is not valid for any names` / SAN mismatch — the dialed `host`
  is not covered by the server certificate's SANs; set `server_name`.
- `server key sha256//... matches no tls.pin_sha256` — the listener is not the
  one pinned, or a self-signed listener restarted and made a new key: take the
  pin from its startup warning, or move it to an issuer and `ca_file`.
- `protocol version not supported` — one side is pinned to `min_version = "1.3"`
  and the other cannot negotiate it.
- Listeners log handshake failures at WARN with the remote address (the `tcp`
  sink at DEBUG); the `tcp` sink and `tcp_chain` source count them in
  `tls_handshake_errors`.

**Rejected after a successful handshake**
- `auth: refused: identity "<id>" is not allowed` — the certificate is valid
  and chains to the CA, but the identity is not in `auth.allow` /
  `auth.allow_patterns`. On TCP the connection is closed; on HTTP the answer
  is `403`.
- `auth: refused: peer certificate carries no <mode> identity` —
  `auth.identity` names a field the certificate does not populate, e.g.
  `san_dns` on a CN-only leaf.
- `auth: node_binding "assert": declared node "<node>" does not match identity "<id>"`
  — the sender's `node` option and its certificate disagree. Fix one, or use
  `node_binding = "force"` to let the certificate win silently.
- On a `tcp_chain` sink the same message inside `Chain connect refused` means
  the *server* was refused: its certificate identity is not in the sink's
  `auth.allow`.
- Allow-list and login rejections log WARN and count `auth_rejected`; a
  node-binding refusal logs `Connection rejected by node binding`
  (`tcp_chain`, `rejected_conns`) or `Request rejected by node binding`
  (`http_chain`, `rejected_requests`).

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
  certificate` means a client that needs `lw auth token --unbound`, and
  `the client sent an unbound proof` the reverse. On an `http_chain` sink,
  `server certificate differs from the one the SCRAM login was bound to` means
  the certificate changed after the login: a rotation (the retry binds anew),
  several backends, or interception.
- `403` from an `http` sink in proxy mode, with `not a trusted proxy` or
  `X-Forwarded-Proto` in its WARN line — the request did not come from a listed
  proxy, or the proxy did not forward `X-Forwarded-Proto: https` and
  `X-Forwarded-For`. With `Request refused by acl` (once a minute at most) or
  none, the `acl` rules refuse the forwarded client (`acl_denied`).
- `too many attempts` — the address failed or abandoned logins faster than one
  per second beyond a burst of 10, or has 4 unfinished; it clears within seconds
  once the failing peer stops. Peers behind one NAT, or one passthrough proxy
  that sends no PROXY header, share the budget. `busy` — 4,096 logins in
  flight, or the listener is stopping.
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

**Behind an L4 proxy**
- Every connection through the proxy fails, the listener logging the proxy's
  address and `first record does not look like a TLS handshake` (the `tcp`
  sink at DEBUG): the proxy sends a PROXY header (nginx `stream` with
  `proxy_protocol on`, HAProxy `send-proxy`) to a listener without
  `acl.proxy_protocol`. Set it, with the proxy in `proxy_from`: see
  [PROXY protocol](security.md#proxy-protocol).
- All peers share one throttling budget and logs name the proxy: it sends no
  PROXY header, so every `scram` peer arrives from its address. One client
  failing logins exhausts everyone's, and a fifth login while 4 are unfinished
  (edges reconnecting together after a restart) is refused; both answer
  `too many attempts` ([Throttling](security.md#throttling)). Have the proxy
  send the header.

**Entries not arriving over a chain link**
- `tcp_chain`: check the sink's `connected` and `reconnects`; `http_chain`:
  its `request_errors` and `dropped_batches`.
- Check the source's `auth_rejected` — an allow-list miss or a failed login
  looks exactly like a network fault from the sender's side — and the sink's
  `last_auth_error`.
- A version skew: `tcp_chain` logs WARN `Rejected chain connection`
  (unsupported protocol version), counted only under `scram`, in
  `auth_rejected`; `http_chain` answers `400` and counts `rejected_requests`.
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
