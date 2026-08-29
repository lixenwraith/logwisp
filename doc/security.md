# Security

This page covers LogWisp's transport security: what it protects, how to
configure it, and — equally important — what it does not yet do.

## Current State

| Capability | Status |
|------------|--------|
| TLS 1.2 / 1.3 on all network sources and sinks | Implemented |
| Server certificate verification by dialers | Implemented |
| Mutual TLS (client certificate required and verified) | Implemented at the transport layer |
| Peer identity (certificate CN) recorded per session | Implemented |
| Authorization from peer identity (CN allow-lists, node binding) | **Not implemented** — see [mtls-auth-plan.md](mtls-auth-plan.md) |
| Password, token, or SCRAM authentication | **Removed**; not currently available |
| IP allow/deny lists, per-IP connection or request limits | **Not implemented** |
| Authentication on the `http` sink's stream and status endpoints | **Not implemented** |

Earlier releases carried basic-auth, bearer-token, and SCRAM authentication.
Those were removed during the move to the plugin/flow architecture and the
switch to standard-library networking. Only certificate-based transport
security survived that transition.

## The TLS Block

One option shape serves both roles, so the configuration reads the same
wherever it appears. Which keys matter depends on whether the plugin listens or
dials.

```toml
[pipelines.plugin_sources.config.tls]     # or plugin_sinks.config.tls
enabled              = false
cert_file            = ""
key_file             = ""
client_auth          = false
client_ca_file       = ""
ca_file              = ""
server_name          = ""
insecure_skip_verify = false
min_version          = "1.3"
```

| Option | Role | Default | Description |
|--------|------|---------|-------------|
| `enabled` | both | `false` | Master switch; when false the whole block is ignored |
| `cert_file` | both | — | Local certificate. **Required** for listeners; optional client identity for dialers |
| `key_file` | both | — | Private key for `cert_file`. Must be set together with it |
| `client_auth` | listener | `false` | Require and verify a client certificate (mTLS) |
| `client_ca_file` | listener | — | CA bundle used to verify client certificates. **Required** when `client_auth` is true |
| `ca_file` | dialer | system store | CA bundle used to verify the server certificate |
| `server_name` | dialer | the configured `host` | SNI and certificate name to verify against |
| `insecure_skip_verify` | dialer | `false` | Disable server verification |
| `min_version` | both | `"1.3"` | `"1.2"` or `"1.3"` |

**Roles by plugin:**

| Plugin | Role | Keys that apply |
|--------|------|-----------------|
| `tcp` sink, `http` sink | Listener | `cert_file`, `key_file`, `client_auth`, `client_ca_file`, `min_version` |
| `tcp_chain` source, `http_chain` source | Listener | same as above |
| `tcp_chain` sink, `http_chain` sink | Dialer | `ca_file`, `server_name`, `insecure_skip_verify`, `cert_file`, `key_file`, `min_version` |

> `min_version` takes `"1.2"` or `"1.3"`. The older `"TLS1.2"` spelling from
> pre-restructure releases is rejected. There is no `max_version` and no
> `cipher_suites` option; TLS 1.3 suites are not configurable in Go, and the
> 1.2 defaults are the standard library's.

### Validation

Misconfiguration fails at plugin construction, before the pipeline starts:

- a listener with `enabled = true` and no `cert_file`/`key_file`
- `client_auth = true` with no `client_ca_file`
- a dialer with only one of `cert_file` / `key_file`
- a certificate or key that will not load, or a CA file containing no
  certificates
- a `min_version` that is neither `"1.2"` nor `"1.3"`

## Enabling mTLS

### 1. Generate a CA and certificates

LogWisp no longer ships a certificate-generation subcommand; the `logwisp tls`
command was removed with the rest of the CLI restructure. Use `openssl`,
`cfssl`, `step-cli`, or your existing PKI.

```bash
# CA
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=LogWisp CA"

# Relay (server) certificate — SAN must match how clients address it
openssl req -newkey rsa:2048 -nodes -keyout relay.key -out relay.csr \
  -subj "/CN=relay.internal"
openssl x509 -req -in relay.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out relay.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:relay.internal\nextendedKeyUsage=serverAuth")

# Edge (client) certificate — CN identifies the node
openssl req -newkey rsa:2048 -nodes -keyout edge-01.key -out edge-01.csr \
  -subj "/CN=edge-01"
openssl x509 -req -in edge-01.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out edge-01.crt -days 825 \
  -extfile <(printf "extendedKeyUsage=clientAuth")
```

The server certificate's SAN must cover the address clients dial. Dialers seed
`ServerName` from the configured `host`, so an IP literal in `host` requires an
IP SAN, and a DNS name requires a DNS SAN. Override with `server_name` when the
dialed address and the certificate name legitimately differ.

### 2. Configure the listener

```toml
[pipelines.plugin_sources.config.tls]
enabled        = true
cert_file      = "/etc/logwisp/tls/relay.crt"
key_file       = "/etc/logwisp/tls/relay.key"
client_auth    = true
client_ca_file = "/etc/logwisp/tls/ca.crt"
min_version    = "1.3"
```

### 3. Configure the dialer

```toml
[pipelines.plugin_sinks.config.tls]
enabled   = true
ca_file   = "/etc/logwisp/tls/ca.crt"
cert_file = "/etc/logwisp/tls/edge-01.crt"
key_file  = "/etc/logwisp/tls/edge-01.key"
min_version = "1.3"
```

### 4. Verify

Startup logs report both flags:

```
INFO msg="TCP chain source initialized" ... tls=true mtls=true
INFO msg="TCP chain sink initialized"   ... tls=true mtls=true
```

A client that presents no certificate is refused during the handshake:

```
WARN msg="TLS handshake failed" component=tcp_chain_source
     remote_addr=127.0.0.1:53840 error="tls: client didn't provide a certificate"
```

Handshake failures are counted in the `tls_handshake_errors` statistic on the
`tcp` sink and the `tcp_chain` source.

## What mTLS Currently Buys You

With `client_auth = true`, the transport enforces:

- the peer holds a certificate chaining to `client_ca_file`
- the certificate is within its validity window and not structurally broken
- the peer holds the matching private key

That is a real membership check: an attacker without a CA-issued certificate
cannot connect at all.

## What It Does Not Buy You

**Any** valid certificate from the configured CA is accepted. LogWisp extracts
the peer's Common Name into session metadata (`tls_peer_cn`) but never consults
it, so within one CA there is no way to express:

- "only `edge-01` and `edge-02` may connect to this ingest port"
- "the node label `edge-01` may only be claimed by the holder of the `edge-01`
  certificate"
- "this certificate may connect but only at this rate"

Two consequences follow.

1. **A compromised edge can impersonate any other edge.** With
   `trust_node = true` (the default) a peer declares its own node label. Any
   certificate holder can claim `edge-99`, or `relay`, and downstream consumers
   will attribute its entries accordingly. Setting `trust_node = false` replaces
   the label with the remote address, which is coarse but not forgeable at the
   application layer.
2. **Revocation is CA-wide.** With no CRL or OCSP checking and no per-identity
   allow-list, withdrawing one node's access means re-issuing the CA or rotating
   the CA bundle for every peer.

Closing both gaps is the subject of the
[mTLS authentication plan](mtls-auth-plan.md).

## Unauthenticated Surfaces

These endpoints have no access control at all. Bind them to a trusted interface
or front them with an authenticating proxy.

| Surface | Exposure |
|---------|----------|
| `http` sink `stream_path` | Full log stream, with `Access-Control-Allow-Origin: *`, so any browser origin can read it |
| `http` sink `status_path` | Host, port, TLS flag, uptime, client counts, throughput counters |
| `tcp` sink | Full log stream to any client that connects |

`max_connections` bounds concurrency on all three but does not distinguish
callers.

## Operational Guidance

**Certificates**

- Use a dedicated CA for LogWisp so its trust decisions stay independent.
- Keep leaf lifetimes short (90–825 days) and automate renewal.
- Key files should be `0600` and owned by the service account.
- Rotation requires a reload (`SIGHUP`), because certificates are loaded once at
  plugin construction; there is no on-disk watch for certificate files.
- Check expiry: `openssl x509 -in relay.crt -noout -enddate`.

**Deployment**

- Prefer `min_version = "1.3"`. Drop to `"1.2"` only for a peer that genuinely
  cannot do 1.3.
- Never enable `insecure_skip_verify` outside a lab; it disables server
  verification entirely and makes the connection trivially interceptable.
- Bind listeners to specific interfaces rather than `0.0.0.0` where you can.
- Use `trust_node = false` on any ingest port reachable from a network you do
  not fully control.
- Run LogWisp as an unprivileged user with write access only to its own log and
  configuration directories.

**Log content**

Logs routinely contain secrets that were never meant to leave the host. Filters
are the available tool:

```toml
[[pipelines.flow.filters]]
type = "exclude"
patterns = ["password", "api[_-]?key", "authorization", "bearer ", "secret"]
```

Choose a sanitizer policy that matches the sink — `json` for JSON output,
`txt` for files and consoles — so control characters in log data cannot break
framing or inject terminal escapes downstream. See
[Formatters](formatters.md).
