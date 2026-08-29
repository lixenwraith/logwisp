# Implementation Plan: mTLS as Authentication

**Status:** proposal, not implemented.
**Scope:** turn the existing transport-level mutual TLS into a real
authentication and authorization mechanism.

## Problem

LogWisp already does mutual TLS at the transport layer. A listener with
`client_auth = true` refuses any peer that cannot present a certificate
chaining to `client_ca_file`, and `internal/tlsx` already extracts the peer's
Common Name and stashes it in session metadata as `tls_peer_cn`.

Nothing reads it back. The result is a CA-wide membership check with no notion
of *which* peer connected:

1. **No per-identity authorization.** Every certificate the CA issues is
   equivalent. There is no way to say "only `edge-01` and `edge-02` may write to
   this ingest port", so one CA cannot serve several trust domains, and
   withdrawing one peer means rotating the CA bundle for all of them.
2. **Node labels are unauthenticated.** With `trust_node = true` (the default) a
   peer declares its own `node` label in the chain hello or the
   `X-Logwisp-Node` header. Any certificate holder can claim any label,
   including another host's, and every downstream consumer will attribute those
   entries accordingly. The only current defence, `trust_node = false`, replaces
   the label with a remote address — unforgeable, but useless for identifying a
   host behind NAT or a load balancer.
3. **The `http` sink has no authentication at all**, even with TLS on. Its
   stream and status endpoints are readable by anyone who can reach the port.

Password, token, and SCRAM authentication were removed during the plugin/flow
restructure and the move to standard-library networking. Certificates are the
one credential the current transport already carries, which makes mTLS the
cheapest path back to authenticated peers.

## Goals

- Authorize peers by certificate identity, per listener.
- Bind the chain `node` label to the authenticated identity, so origin
  attribution is trustworthy.
- Gate the `http` sink's endpoints on client certificates.
- Make identity visible in sessions, statistics, and logs.
- Change nothing for existing configurations that omit the new block.

## Non-Goals

- Reviving password, token, or SCRAM authentication. The reserved hooks
  (`chain.Hello.Auth`, the `Authorization` header comment in the `http_chain`
  sink, the "Future: password auth block" comments in the network options
  structs) stay reserved.
- IP allow/deny lists and per-peer rate limits. Related, but a separate feature
  with its own config surface.
- OCSP. See [Revocation](#revocation) for what is proposed instead.
- Authorization *within* a stream — the unit of decision is a connection (TCP)
  or a request (HTTP), never an individual entry.

## Design

### Identity

The authenticated identity is a single string derived from the peer's verified
leaf certificate. Because `tls.RequireAndVerifyClientCert` has already validated
the chain, signature, and validity window by the time we look, extraction is
pure field selection.

| `identity` mode | Source | Notes |
|-----------------|--------|-------|
| `cn` (default) | `Subject.CommonName` | Matches the existing `tls_peer_cn` metadata |
| `san_dns` | first `DNSNames` entry | Preferred for host identities |
| `san_uri` | first `URIs` entry | SPIFFE-style IDs |
| `san_email` | first `EmailAddresses` entry | Operator identities |

An empty identity is a rejection, not an empty match: a certificate with no
usable identity field cannot satisfy any policy.

Identities are not secrets, so ordinary string comparison is fine; there is no
timing side channel worth defending here.

### Configuration

A new `auth` table sits beside `tls` in every network plugin's `config`. Keeping
it separate from `tls` matters: TLS answers "is this channel private and is the
peer chained to a CA", auth answers "may *this* peer do *this*", and a later
non-certificate method should be able to reuse the block.

```toml
[pipelines.plugin_sources.config.auth]
type           = "mtls"                  # none (default) | mtls
identity       = "cn"                    # cn | san_dns | san_uri | san_email
allow          = ["edge-01", "edge-02"]  # exact identities
allow_patterns = ["^edge-\\d{2}$"]       # RE2, anchored by the author
node_binding   = "force"                 # none | assert | force
```

| Option | Type | Default | Meaning |
|--------|------|---------|---------|
| `type` | string | `none` | `none` preserves today's behaviour exactly; `mtls` enables the policy |
| `identity` | string | `cn` | Which certificate field is the identity |
| `allow` | []string | `[]` | Exact identity matches |
| `allow_patterns` | []string | `[]` | RE2 patterns matched against the identity |
| `node_binding` | string | `force` when `type = "mtls"` | See below |

Empty `allow` **and** empty `allow_patterns` under `type = "mtls"` means "any
identity the CA vouches for" — that is, today's behaviour, but with the identity
now recorded and node binding available. It is a deliberate, documented default
rather than a silent deny-all, and startup logs say so plainly.

`node_binding` applies only to the chain sources, where a `node` label is
declared:

| Value | Behaviour |
|-------|-----------|
| `none` | `trust_node` governs, as today |
| `assert` | The declared label must equal the identity; a mismatch is rejected |
| `force` | The declared label is ignored and the identity is used |

`force` is the default under `type = "mtls"` because it is the only setting
where a misconfigured or hostile edge cannot mislabel its entries. `assert`
exists for operators who want the mismatch to be loud rather than silently
corrected. `node_binding` overrides `trust_node`; when both are set, the
constructor logs that `trust_node` is being ignored.

For the `tcp` and `http` sinks, which have no node concept, `node_binding` is
ignored.

Dialer-side plugins (`tcp_chain` and `http_chain` sinks) accept the same block
to pin the *server's* identity beyond hostname verification. This is deferred to
phase 4 and does nothing before then.

### Validation

At plugin construction, before anything binds:

- `type = "mtls"` on a listener requires `tls.enabled = true` and
  `tls.client_auth = true`. Silently accepting an auth policy the transport
  cannot enforce is the failure mode worth designing out.
- `identity` must be one of the four modes.
- Every entry in `allow_patterns` must compile.
- `node_binding` must be one of the three values.

Errors follow existing style: `auth: type "mtls" requires tls.client_auth`.

### New package: `internal/authz`

```go
package authz

// Policy is the compiled form of config.AuthOptions.
type Policy struct { /* mode, identity selector, exact set, patterns, binding */ }

// New compiles a policy. Returns (nil, nil) when auth is disabled, matching
// the tlsx.Server / tlsx.Client convention so callers can nil-check.
func New(o *config.AuthOptions) (*Policy, error)

// Identity is the outcome of a successful authorization.
type Identity struct {
    Name   string // the selected certificate field
    Method string // "mtls"
}

// Authorize extracts and checks the peer identity from a completed handshake.
func (p *Policy) Authorize(cs *tls.ConnectionState) (Identity, error)

// ResolveNode applies node_binding to a declared label.
func (p *Policy) ResolveNode(declared string, id Identity) (string, error)

// Stats reports counters for the sink/source stats map.
func (p *Policy) Stats() map[string]any
```

This mirrors `internal/tlsx`: one small package that is the single seam between
declarative config and a cross-cutting concern, with `(nil, nil)` for the
disabled case so every call site is a nil check rather than a branch on config.

### Enforcement Points

Each plugin already has the right spot, and in two cases the code says so.

**`tcp_chain` source** (`internal/source/tcpchain/tcpchain.go`, `handleConn`)

Today: handshake → read hello → decode → resolve node from `trust_node` →
create session. Insert authorization between the handshake and the hello read,
so an unauthorized peer never gets a preamble parsed on its behalf, and replace
the node resolution with `Policy.ResolveNode`.

```go
if tlsState != nil && s.authPolicy != nil {
    id, err := s.authPolicy.Authorize(*tlsState)
    if err != nil {
        s.authRejected.Add(1)
        s.logger.Warn("msg", "Connection rejected by auth policy",
            "component", "tcp_chain_source", "remote_addr", remote, "error", err)
        return // deferred cleanup closes conn
    }
    ident = id
}
// ... read and decode hello ...
connNode, err = s.authPolicy.ResolveNode(hello.Node, ident)
```

**`http_chain` source** (`internal/source/httpchain/httpchain.go`, `handleIngest`)

Per request, from `r.TLS`, before the body is read — an unauthorized sender
should not get to stream 8 MiB into the process. Rejection is `403`, distinct
from the `400` used for protocol errors, so a sender can tell "you are not
allowed" from "your batch was malformed". `ResolveNode` then governs the
`X-Logwisp-Node` header exactly as it governs the TCP hello.

**`tcp` sink** (`internal/sink/tcp/tcp.go`, `handleConn`)

There is already a comment marking the place: *"Password-auth extension point:
preamble verification runs in handleConn post-handshake, pre-registration."*
Authorization goes precisely there — after the explicit handshake, before the
session is created and the client is registered — so an unauthorized peer never
appears in the client map and never receives a broadcast.

**`http` sink** (`internal/sink/http/http.go`, `Start`)

Also already marked: *"Auth extension point: wrap mux with auth middleware once
credentials land, e.g. handler = authMiddleware(cfg)(handler)."* A middleware
around the mux covers both the stream and the status endpoint with one wrapper,
and keeps the handlers themselves unaware of authorization.

```go
var handler http.Handler = mux
if h.authPolicy != nil {
    handler = authMiddleware(h.authPolicy, h.logger)(handler)
}
```

The middleware rejects with `403` and no body detail — the status endpoint
leaks host, port, and throughput counters, so a rejection should not leak policy
shape on top of it.

### Capabilities

`core.CapAuth` is currently derived from `tlsConfig.ClientAuth`. It should
reflect the auth policy instead:

```go
if s.authPolicy != nil {
    caps = append(caps, core.CapAuth)
}
```

`Pipeline.initSourceCapabilities` and `initSinkCapabilities` treat `CapAuth` as
a no-op placeholder today. They become the natural place for a cross-cutting
check: a plugin advertising `CapAuth` without `CapTLS` is a contradiction and
should fail pipeline construction rather than start.

### Observability

Every authorization decision must be visible, because a silent deny is
indistinguishable from a network fault at 3am.

- **Session metadata** gains `auth_method` and `auth_identity` alongside the
  existing `tls` and `tls_peer_cn`.
- **Statistics** gain `auth_enabled`, `auth_rejected`, and `node_binding` in the
  `details` map of every affected source and sink, so rejections show up in the
  status reporter and the `http` sink's status endpoint.
- **Logs** record a WARN per rejection with the remote address, the extracted
  identity (or the reason extraction failed), and the policy that rejected it.
  Accepted connections log the identity at INFO on the chain sources and at
  DEBUG on the sinks, matching each plugin's existing verbosity.

### Revocation

Certificate revocation is deliberately handled by the allow-list rather than by
CRL or OCSP:

1. Remove the identity from `allow` / `allow_patterns`.
2. `kill -HUP`.

The reload path already rebuilds every pipeline, so the policy takes effect on
the next connection and existing connections are dropped by the rebuild itself.
This is one moving part instead of three, it needs no network calls on the
handshake path, and it is exact — no window between revocation and the next CRL
publication.

A CRL file loaded next to `client_ca_file` and re-read on reload is a reasonable
phase-4 addition for operators with existing CRL infrastructure. OCSP stapling
is out of scope: it adds a network dependency to the handshake path for a
system whose entire design is "never block".

## Phases

### Phase 1 — Identity and policy (no enforcement)

- `internal/config`: add `AuthOptions` plus an `Auth *AuthOptions` field to the
  four listener option structs.
- `internal/tlsx`: add `PeerIdentity(cs tls.ConnectionState, mode string) string`
  beside the existing `PeerCN`.
- `internal/authz`: new package — `Policy`, `New`, `Authorize`, `ResolveNode`,
  `Stats`.
- Unit tests: identity extraction per mode, exact and pattern matching, empty
  policy, malformed patterns, node binding in all three modes.

Nothing behaves differently yet, which makes this phase safe to merge alone.

### Phase 2 — Chain sources

- Wire `authz` into `tcp_chain` and `http_chain` sources at the points above.
- Replace the `trust_node` node resolution with `ResolveNode`.
- Add validation, capabilities, statistics, and session metadata.
- Add `test/mtls-chain-test.sh`, modelled on `test/chain-test.sh`: generate a
  CA, a server certificate, and two client certificates with `openssl`; assert
  that an allowed identity delivers entries, a non-allowed identity is rejected,
  a peer with no certificate fails the handshake, and a peer declaring another
  node's label is rejected under `assert` and corrected under `force`.

This phase alone closes the node-spoofing hole, which is the sharpest of the
three problems.

### Phase 3 — Sinks

- `tcp` sink: authorize in `handleConn` before registration.
- `http` sink: `authMiddleware` around the mux, covering stream and status.
- Extend the test script to cover both.

### Phase 4 — Optional hardening

- Dialer-side server identity pinning for the chain sinks.
- CRL file support alongside `client_ca_file`, re-read on reload.
- Certificate expiry warnings at startup and on reload — a leaf expiring inside
  30 days logged at WARN, since nothing warns today.
- Surface `tls_peer_cn` / `auth_identity` in the `http` sink's status output for
  connected clients.

## Compatibility

No configuration breaks. Omitting the `auth` block, or setting
`type = "none"`, reproduces current behaviour byte for byte: `Policy` is nil,
every call site short-circuits, and `trust_node` continues to govern node
labels.

The one behavioural note for adopters: turning on `type = "mtls"` defaults
`node_binding` to `force`, so entries from a peer whose certificate identity
differs from its configured `node` label will be relabelled. That is the point
of the feature, but it will move data between labels in a dashboard, so the
release note should say it in those terms.

## Estimated Cost

| Phase | Files touched | Rough size |
|-------|--------------|-----------|
| 1 | `config/config.go`, `config/validate.go`, `tlsx/tlsx.go`, new `authz/` + tests | ~400 lines |
| 2 | Two chain sources, new test script | ~200 lines |
| 3 | `sink/tcp`, `sink/http`, test script extension | ~150 lines |
| 4 | `tlsx`, both chain sinks, `sink/http` status | ~250 lines |

Phases 1–2 are the security-relevant core; phase 3 closes the read-side
exposure; phase 4 is discretionary.

## Open Questions

1. **Should an empty allow-list deny instead of allow?** Deny-by-default is the
   safer instinct, but it makes `type = "mtls"` with no list a footgun that
   silently drops all traffic. The proposal is allow-with-a-loud-startup-log;
   the alternative is requiring a non-empty list and erroring at construction,
   which is arguably better and costs one line.
2. **Should `identity` accept a list of modes** (try `san_uri`, fall back to
   `cn`)? Simpler as a single mode; heterogeneous PKI is the argument against.
3. **Per-identity rate limits.** The natural follow-on once identity exists, and
   the natural home for the per-IP limiting that was also removed. Deliberately
   out of scope here so this feature stays reviewable.
4. **Whether `assert` should reject or warn-and-correct.** As proposed it
   rejects, which is unambiguous but turns a certificate/config mismatch into an
   outage. `force` is the forgiving option, and it is the default.
