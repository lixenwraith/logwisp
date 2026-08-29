# Security

This page covers LogWisp's transport security: what it protects, how to
configure it, and — equally important — what it does not yet do.

## Current State

| Capability | Status |
|------------|--------|
| TLS 1.2 / 1.3 on all network sources and sinks | Implemented |
| Server certificate verification by dialers | Implemented |
| Mutual TLS (client certificate required and verified) | Implemented at the transport layer |
| Peer identity recorded per session | Implemented |
| Authorization from peer identity (allow-lists, node binding) | Implemented — see [The Auth Block](#the-auth-block) |
| Authentication on the `http` sink's stream and status endpoints | Implemented, via the auth block |
| Server identity pinning by dialers | Implemented, via the auth block |
| Certificate revocation lists (CRL) or OCSP | **Not implemented** — revoke by editing the allow-list |
| Password, token, or SCRAM authentication | **Removed**; not currently available |
| IP allow/deny lists, per-IP connection or request limits | **Not implemented** |

Earlier releases carried basic-auth, bearer-token, and SCRAM authentication.
Those were removed during the move to the plugin/flow architecture and the
switch to standard-library networking. Certificates are the one credential the
transport still carries, so they are what authentication is built on: the `tls`
block establishes that a peer chains to your CA, and the `auth` block decides
which peers that CA vouches for may actually do what.

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

## The Auth Block

TLS answers "is this channel private, and does the peer chain to a CA". Auth
answers "may *this* peer do *this*". They are separate blocks because they are
separate questions, and because a later non-certificate method should be able to
reuse the second one.

```toml
[pipelines.plugin_sources.config.auth]    # or plugin_sinks.config.auth
type           = "none"                   # none | mtls
identity       = "cn"                     # cn | san_dns | san_uri | san_email
allow          = []
allow_patterns = []
node_binding   = "force"                  # chain sources only
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | `none` | `none` ignores the whole block; `mtls` authorizes by certificate identity |
| `identity` | string | `cn` | Which certificate field carries the identity |
| `allow` | []string | `[]` | Exact identities to admit |
| `allow_patterns` | []string | `[]` | RE2 patterns matched against the identity; anchor them yourself |
| `node_binding` | string | `force` under `mtls` | Chain sources only: `none`, `assert`, or `force` |

**Roles by plugin:**

| Plugin | Role | Decides |
|--------|------|---------|
| `tcp_chain` source, `http_chain` source | Listener | Which senders may ingest, and what node label their entries carry |
| `tcp` sink, `http` sink | Listener | Which clients may read the stream (and, on `http`, the status endpoint) |
| `tcp_chain` sink, `http_chain` sink | Dialer | Which server identity to accept, beyond hostname verification |

### Identity

The identity is one string pulled from the peer's verified leaf certificate.
The handshake has already checked the chain, signature, and validity window, so
this is pure field selection.

| Mode | Source | Typical use |
|------|--------|-------------|
| `cn` (default) | `Subject.CommonName` | Matches the existing `tls_peer_cn` metadata |
| `san_dns` | first DNS SAN | Host identities |
| `san_uri` | first URI SAN | SPIFFE-style IDs |
| `san_email` | first email SAN | Operator identities |

A certificate with no usable value in the chosen field is rejected. An empty
identity is a refusal, not an empty match.

### The allow list

`allow` is an exact-match set; `allow_patterns` holds RE2 patterns. An identity
passes if it appears in either.

Leaving **both** empty under `type = "mtls"` admits any identity the CA vouches
for. That is deliberate — it is how you enable node binding without enumerating
a whole fleet — but it is announced rather than silent:

```
WARN msg="Auth policy admits any identity the configured CA vouches for"
     component=tcp_chain_source instance_id=in_tcp
     hint="set auth.allow or auth.allow_patterns to authorize named peers"
```

Anchor your patterns. `allow_patterns = ["edge-\\d{2}"]` matches
`evil-edge-01-impostor`; `["^edge-\\d{2}$"]` does not.

### Node binding

`node_binding` applies only to the chain sources, and it overrides `trust_node`.

| Value | Connection label | Per-entry `node` field |
|-------|------------------|------------------------|
| `none` | `trust_node` governs | `trust_node` governs |
| `assert` | Must equal the identity; a mismatch or an omission is rejected | `trust_node` governs |
| `force` | Ignored; the identity is used | Overwritten with the identity |

Use **`force`** on an ingest boundary you do not trust. Every entry is
relabelled, so a compromised edge cannot smuggle a foreign origin through the
per-entry `node` field either. It is the default under `type = "mtls"`.

Use **`assert`** on a relay-to-relay hop. The relay must prove its own identity —
a mismatch fails loudly instead of being silently corrected — but the entries it
forwards keep the origin labels stamped at the first hop, so multi-hop
attribution survives.

When binding is active the source says so at startup:

```
INFO msg="Node labels bound to peer identity; trust_node is ignored"
     component=tcp_chain_source node_binding=force trust_node=true
```

### Dialer-side pinning

On a chain sink, the same block pins the *server's* identity. Hostname
verification already proves the server holds a certificate valid for the address
you dialed; pinning additionally requires that certificate to name an identity
you listed.

```toml
[pipelines.plugin_sinks.config.auth]
type  = "mtls"
allow = ["relay.internal"]
```

The check runs as part of the handshake, so a server the policy rejects never
receives an entry — the sink's normal backoff loop handles it like any other
connect failure. `insecure_skip_verify` is refused alongside `type = "mtls"`:
an identity read from an unverified chain is a claim, not a fact.

### Validation

Misconfiguration fails at plugin construction, before the pipeline starts:

- `type = "mtls"` on a listener without `tls.enabled` **and** `tls.client_auth`
- `type = "mtls"` on a dialer without `tls.enabled`, or with
  `tls.insecure_skip_verify`
- an `identity` that is not one of the four modes
- an `allow_patterns` entry that does not compile
- a `node_binding` that is not one of the three values, or one set on a plugin
  that has no node concept

Errors read like `auth: type "mtls" requires tls.client_auth`.

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

[pipelines.plugin_sources.config.auth]
type         = "mtls"
allow        = ["edge-01", "edge-02"]
node_binding = "force"
```

Without the `auth` block the listener accepts every certificate the CA issued.
With it, only `edge-01` and `edge-02` may ingest, and their entries are labelled
from their certificates rather than from whatever they declare.

### 3. Configure the dialer

```toml
[pipelines.plugin_sinks.config.tls]
enabled   = true
ca_file   = "/etc/logwisp/tls/ca.crt"
cert_file = "/etc/logwisp/tls/edge-01.crt"
key_file  = "/etc/logwisp/tls/edge-01.key"
min_version = "1.3"

[pipelines.plugin_sinks.config.auth]
type  = "mtls"
allow = ["relay.internal"]
```

### 4. Verify

Startup logs report the transport flags and the compiled policy:

```
INFO msg="TCP chain source initialized" ... tls=true mtls=true
     auth="mtls identity=cn allow=[2 exact, 0 pattern(s)] node_binding=force"
INFO msg="TCP chain sink initialized"   ... tls=true mtls=true
     auth="mtls identity=cn allow=[1 exact, 0 pattern(s)] node_binding=none"
```

A client that presents no certificate is refused during the handshake:

```
WARN msg="TLS handshake failed" component=tcp_chain_source
     remote_addr=127.0.0.1:53840 error="tls: client didn't provide a certificate"
```

A client whose certificate is valid but whose identity is not authorized gets
past the handshake and is refused by the policy:

```
WARN msg="Connection rejected by auth policy" component=tcp_chain_source
     remote_addr=127.0.0.1:33946 error="auth: identity \"edge-99\" is not allowed"
```

Handshake failures are counted in `tls_handshake_errors`; policy rejections in
`auth_rejected`. Both appear in the status reporter and in the `http` sink's
status endpoint. Accepted peers are recorded in session metadata as
`auth_method` and `auth_identity`.

`test/mtls-chain-test.sh` builds a throwaway PKI and exercises the whole surface
end to end — run it with `--auto` to see each guarantee asserted.

## What Each Layer Enforces

**`tls` with `client_auth = true`** — a membership check. The peer holds a
certificate chaining to `client_ca_file`, within its validity window, and holds
the matching private key. An attacker without a CA-issued certificate cannot
connect at all. What it does *not* decide is which CA-issued certificate: every
one is equivalent at this layer.

**`auth` with `type = "mtls"`** — an identity check, per listener:

- only the identities you list may connect, so one CA can serve several trust
  domains and a single peer can be withdrawn without touching the others
- the chain `node` label is bound to the certificate, so a compromised edge
  cannot attribute its entries to another host
- the `http` sink's stream and status endpoints stop being open to anyone who
  can reach the port

**Revocation** is the allow-list, not a CRL. Remove the identity from `allow` /
`allow_patterns` and send `SIGHUP`: the reload rebuilds every pipeline, so the
change takes effect on the next connection and existing ones are dropped by the
rebuild. No network call on the handshake path, and no window between revocation
and the next CRL publication. See
[mtls-auth-plan.md](mtls-auth-plan.md#not-implemented) for what CRL support
would add.

## Surfaces Without Access Control

An `auth` block closes each of these. Without one, bind them to a trusted
interface or front them with an authenticating proxy.

| Surface | Exposure when `auth.type = "none"` |
|---------|-----------------------------------|
| `http` sink `stream_path` | Full log stream, with `Access-Control-Allow-Origin: *`, so any browser origin can read it |
| `http` sink `status_path` | Host, port, TLS flag, uptime, client counts, throughput counters |
| `tcp` sink | Full log stream to any client that connects |
| `tcp_chain` / `http_chain` source | Ingest from any peer the CA vouches for, under any node label it claims |

`max_connections` bounds concurrency on all of them but does not distinguish
callers.

Note that `auth` requires `client_auth = true`, which requires TLS. There is no
way to authenticate a plaintext listener.

## Operational Guidance

**Certificates**

- Use a dedicated CA for LogWisp so its trust decisions stay independent.
- Keep leaf lifetimes short (90–825 days) and automate renewal.
- Key files should be `0600` and owned by the service account.
- Rotation requires a reload (`SIGHUP`), because certificates are loaded once at
  plugin construction; there is no on-disk watch for certificate files.
- Check expiry yourself: `openssl x509 -in relay.crt -noout -enddate`. Nothing
  warns before a certificate lapses; it surfaces as a handshake failure.
- Keep the identity field you authorize on stable across rotations. Reissuing a
  leaf with a different CN silently drops the peer out of the allow list.

**Deployment**

- Prefer `min_version = "1.3"`. Drop to `"1.2"` only for a peer that genuinely
  cannot do 1.3.
- Never enable `insecure_skip_verify` outside a lab; it disables server
  verification entirely and makes the connection trivially interceptable.
- Bind listeners to specific interfaces rather than `0.0.0.0` where you can.
- On any ingest port reachable from a network you do not fully control, set
  `auth.type = "mtls"` with an explicit `allow` list. `trust_node = false` is the
  fallback when certificates are not an option; it is unforgeable but labels
  entries by remote address, which is useless behind NAT or a load balancer.
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
