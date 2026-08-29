# mTLS as Authentication

**Status:** implemented. Phases 1–3 of the original proposal, plus dialer-side
server identity pinning from phase 4, are in the tree and covered by
`test/mtls-chain-test.sh`. The remaining phase-4 items are listed under
[Not Implemented](#not-implemented).

**Scope:** turn transport-level mutual TLS into an authentication and
authorization mechanism.

## Problem

LogWisp already did mutual TLS at the transport layer. A listener with
`client_auth = true` refused any peer that could not present a certificate
chaining to `client_ca_file`, and `internal/tlsx` extracted the peer's Common
Name into session metadata as `tls_peer_cn`.

Nothing read it back. The result was a CA-wide membership check with no notion
of *which* peer connected:

1. **No per-identity authorization.** Every certificate the CA issued was
   equivalent. There was no way to say "only `edge-01` and `edge-02` may write
   to this ingest port", so one CA could not serve several trust domains, and
   withdrawing one peer meant rotating the CA bundle for all of them.
2. **Node labels were unauthenticated.** With `trust_node = true` (the default)
   a peer declares its own `node` label in the chain hello or the
   `X-Logwisp-Node` header. Any certificate holder could claim any label,
   including another host's, and every downstream consumer would attribute
   those entries accordingly. The only defence, `trust_node = false`, replaced
   the label with a remote address — unforgeable, but useless for identifying a
   host behind NAT or a load balancer.
3. **The `http` sink had no authentication at all**, even with TLS on. Its
   stream and status endpoints were readable by anyone who could reach the port.

Password, token, and SCRAM authentication were removed during the plugin/flow
restructure and the move to standard-library networking. Certificates are the
one credential the transport already carries, which made mTLS the cheapest path
back to authenticated peers.

## Goals

- Authorize peers by certificate identity, per listener. ✅
- Bind the chain `node` label to the authenticated identity, so origin
  attribution is trustworthy. ✅
- Gate the `http` sink's endpoints on client certificates. ✅
- Make identity visible in sessions, statistics, and logs. ✅
- Change nothing for existing configurations that omit the new block. ✅

## Non-Goals

- Reviving password, token, or SCRAM authentication. The reserved hooks
  (`chain.Hello.Auth`, the `Authorization` header comment in the `http_chain`
  sink, the "Future: password auth block" comments in the network options
  structs) stay reserved.
- IP allow/deny lists and per-peer rate limits. Related, but a separate feature
  with its own config surface.
- OCSP. See [Revocation](#revocation) for what is done instead.
- Authorization *within* a stream — the unit of decision is a connection (TCP)
  or a request (HTTP), never an individual entry.

## Design

### Identity

The authenticated identity is a single string derived from the peer's verified
leaf certificate. Because `tls.RequireAndVerifyClientCert` has already validated
the chain, signature, and validity window by the time we look, extraction is
pure field selection — `tlsx.PeerIdentity`.

| `identity` mode | Source | Notes |
|-----------------|--------|-------|
| `cn` (default) | `Subject.CommonName` | Matches the existing `tls_peer_cn` metadata |
| `san_dns` | first `DNSNames` entry | Preferred for host identities |
| `san_uri` | first `URIs` entry | SPIFFE-style IDs |
| `san_email` | first `EmailAddresses` entry | Operator identities |

An empty identity is a rejection, not an empty match: a certificate with no
usable identity field cannot satisfy any policy.

Identities are not secrets, so ordinary string comparison is used; there is no
timing side channel worth defending here.

### Configuration

An `auth` table sits beside `tls` in every network plugin's `config`. Keeping it
separate from `tls` matters: TLS answers "is this channel private and does the
peer chain to a CA", auth answers "may *this* peer do *this*", and a later
non-certificate method can reuse the block.

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
| `type` | string | `none` | `none` preserves pre-auth behaviour exactly; `mtls` enables the policy |
| `identity` | string | `cn` | Which certificate field is the identity |
| `allow` | []string | `[]` | Exact identity matches |
| `allow_patterns` | []string | `[]` | RE2 patterns matched against the identity |
| `node_binding` | string | `force` when `type = "mtls"` | Chain sources only; see below |

Empty `allow` **and** empty `allow_patterns` under `type = "mtls"` means "any
identity the CA vouches for" — that is, the pre-auth behaviour, but with the
identity now recorded and node binding available. It is a deliberate, documented
default rather than a silent deny-all, and the plugin logs a WARN at startup
saying so.

`node_binding` applies only to the chain sources, where a `node` label is
declared. Setting it on any other plugin is a configuration error.

| Value | Connection label | Per-entry `node` field |
|-------|------------------|------------------------|
| `none` | `trust_node` governs, as before | `trust_node` governs |
| `assert` | Must equal the identity; a mismatch or an omission is rejected | `trust_node` governs |
| `force` | The declared label is ignored and the identity is used | Overwritten with the identity |

The split between `assert` and `force` is what makes both worth having:

- **`force`** is for an ingest boundary that does not trust its peer. Every
  entry is relabeled, so a compromised edge cannot smuggle a foreign origin
  through the per-entry `node` field either. It is the default under
  `type = "mtls"` because it is the only setting where a misconfigured or
  hostile edge cannot mislabel its entries.
- **`assert`** is for a relay-to-relay hop. The relay must prove *its own*
  identity — a mismatch is loud rather than silently corrected — but the entries
  it forwards keep the origin labels stamped at the first hop, so multi-hop
  attribution survives.

`node_binding` overrides `trust_node`; when binding is active the constructor
logs that `trust_node` is being ignored.

Dialer-side plugins (`tcp_chain` and `http_chain` sinks) accept the same block
to pin the *server's* identity beyond hostname verification. There
`node_binding` does not apply, and `tls.insecure_skip_verify` is rejected:
identity read from an unverified chain is a claim, not a fact.

### Validation

At plugin construction, before anything binds:

- `type = "mtls"` on a listener requires `tls.enabled = true` and
  `tls.client_auth = true`; on a dialer it requires `tls.enabled = true` and
  forbids `tls.insecure_skip_verify`. Silently accepting an auth policy the
  transport cannot enforce is the failure mode worth designing out.
- `identity` must be one of the four modes.
- Every entry in `allow_patterns` must compile.
- `node_binding` must be one of the three values, and must be absent or `none`
  outside the chain sources.

Errors follow existing style: `auth: type "mtls" requires tls.client_auth`.

### The `internal/authz` package

```go
package authz

// Policy is the compiled form of config.AuthOptions.
type Policy struct { /* role, identity mode, exact set, patterns, binding, counters */ }

// Role selects the validation and behavior appropriate to the call site.
const ( RoleListener Role = iota; RoleChainListener; RoleDialer )

// New compiles a policy. Returns (nil, nil) when auth is disabled, matching
// the tlsx.Server / tlsx.Client convention. tlsOpts is the sibling `tls`
// block, so an unenforceable policy fails here rather than at run time.
func New(o *config.AuthOptions, tlsOpts *config.TLSOptions, role Role) (*Policy, error)

// Identity is the outcome of a successful authorization.
type Identity struct {
    Name   string // the selected certificate field
    Method string // "mtls"
}

// Apply stamps an identity onto session metadata.
func (id Identity) Apply(meta map[string]any)

// Authorize extracts and checks the peer identity from a completed handshake.
func (p *Policy) Authorize(cs *tls.ConnectionState) (Identity, error)

// VerifyConnection is assignable to tls.Config.VerifyConnection on a dialer.
func (p *Policy) VerifyConnection(cs tls.ConnectionState) error

// ResolveNode applies node_binding to the label a peer declared.
func (p *Policy) ResolveNode(declared, fallback string, trustNode bool, id Identity) (string, error)

// TrustsEntryNode reports whether per-entry node labels survive the policy.
func (p *Policy) TrustsEntryNode(trustNode bool) bool

// Stats reports counters for the sink/source stats map.
func (p *Policy) Stats() map[string]any
```

This mirrors `internal/tlsx`: one small package that is the single seam between
declarative config and a cross-cutting concern. `New` returns `(nil, nil)` for
the disabled case and **every method tolerates a nil receiver**, so a call site
reads identically whether or not auth is configured — no nil checks, no branch
on config:

```go
id, err := s.auth.Authorize(tlsState)   // nil policy: (zero Identity, nil)
if err != nil { /* reject */ }
```

### Enforcement Points

**`tcp_chain` source** (`internal/source/tcpchain/tcpchain.go`, `handleConn`)

Handshake → **authorize** → read hello → `ResolveNode` → create session. The
authorization sits between the handshake and the hello read, so an unauthorized
peer never gets a preamble parsed on its behalf. `chain.DecodeEntry` is then
called with `auth.TrustsEntryNode(trust_node)` rather than `trust_node` itself.

**`http_chain` source** (`internal/source/httpchain/httpchain.go`, `handleIngest`)

Per request, from `r.TLS`, before the body is read — an unauthorized sender does
not get to stream `max_body_bytes` into the process. Rejection is `403`,
distinct from the `400` used for protocol errors, so a sender can tell "you are
not allowed" from "your batch was malformed". `ResolveNode` then governs the
`X-Logwisp-Node` header exactly as it governs the TCP hello. The session cache
key includes the identity, so two peers sharing a remote address never share a
session.

**`tcp` sink** (`internal/sink/tcp/tcp.go`, `handleConn`)

After the explicit handshake, before the session is created and the client is
registered — so an unauthorized peer never appears in the client map and never
receives a broadcast.

**`http` sink** (`internal/sink/http/http.go`, `authMiddleware`)

A middleware around the mux covers both the stream and the status endpoint with
one wrapper and keeps the handlers themselves unaware of authorization. The
authorized identity is passed down through the request context for session
metadata. Rejections are `403` with no body detail — the status endpoint leaks
host, port, and throughput counters, so a rejection should not leak policy shape
on top of that.

**`tcp_chain` / `http_chain` sinks** (dialers)

The policy is installed as `tls.Config.VerifyConnection`, which runs after the
standard chain and hostname checks. A server whose identity the policy rejects
fails the handshake itself rather than the first write, and the chain sink's
existing backoff loop handles it as any other connect failure.

### Capabilities

`core.CapAuth` now means "this plugin authorizes peers" — it is derived from the
policy, not from `tlsConfig.ClientAuth`. Transport-level mTLS without a policy
still reports `CapTLS`, the `mtls=true` field on the startup log line, and the
`tls` statistic.

`Pipeline.initSourceCapabilities` and `initSinkCapabilities` treat this as a
cross-cutting check: a plugin advertising `CapAuth` without `CapTLS` is a
contradiction and fails pipeline construction rather than starting.

### Observability

Every authorization decision is visible, because a silent deny is
indistinguishable from a network fault at 3am.

- **Session metadata** gains `auth_method` and `auth_identity` alongside the
  existing `tls` and `tls_peer_cn`.
- **Statistics** gain `auth`, `auth_identity` (the mode), `auth_unrestricted`,
  `auth_allowed`, `auth_rejected`, and — on chain sources — `node_binding`, in
  the `details` map of every affected source and sink. They surface in the
  status reporter and in the `http` sink's status endpoint.
- **Logs** record a WARN per rejection with the remote address and the reason.
  The startup line carries a rendered policy summary
  (`auth="mtls identity=cn allow=[1 exact, 0 pattern(s)] node_binding=force"`),
  a WARN when the allow list is empty, and an INFO when node binding overrides
  `trust_node`.

### Revocation

Certificate revocation is handled by the allow-list rather than by CRL or OCSP:

1. Remove the identity from `allow` / `allow_patterns`.
2. `kill -HUP`.

The reload path rebuilds every pipeline, so the policy takes effect on the next
connection and existing connections are dropped by the rebuild itself. This is
one moving part instead of three, it needs no network calls on the handshake
path, and it is exact — no window between revocation and the next CRL
publication.

## Compatibility

No configuration breaks. Omitting the `auth` block, or setting `type = "none"`,
reproduces the previous behaviour exactly: `Policy` is nil, every call site
short-circuits, and `trust_node` continues to govern node labels.

The one behavioural note for adopters: turning on `type = "mtls"` defaults
`node_binding` to `force`, so entries from a peer whose certificate identity
differs from its configured `node` label will be relabelled. That is the point
of the feature, but it moves data between labels in a dashboard, so plan for it.
Use `node_binding = "assert"` on relay-to-relay hops where upstream origin
labels must survive.

## Verification

`test/mtls-chain-test.sh` builds a full PKI with `openssl` and exercises both
target topologies end to end:

```
./test/mtls-chain-test.sh --auto
```

Scenario 1 — chained instances, client authenticating with mTLS:

- an authorized edge (`edge-01`) delivers entries through both the `tcp_chain`
  and `http_chain` ingest ports into a file sink
- `node_binding = "force"` overrides the label the sender configured
- an identity outside the allow list (`edge-99`) is refused, even while claiming
  to be `edge-01`
- a peer presenting no certificate fails the handshake
- a dialer that pins a server identity the relay does not hold refuses to
  connect, even though the server certificate chains to the trusted CA

Scenario 2 — a viewer client reading a streaming sink over mTLS:

- an authorized viewer streams from the `tcp` sink and from the `http` sink's
  SSE endpoint, and reads `/status`
- a CA-valid but unauthorized viewer gets nothing from the `tcp` sink and `403`
  from both `http` sink endpoints
- a client with no certificate fails the handshake
- the status endpoint reports the policy and its rejection count

`test/chain-test.sh` and `test/chain-aggregate-test.sh` continue to pass
unchanged, which is the regression check for the auth-disabled path.

## Not Implemented

The remaining phase-4 items, in rough order of value:

1. **CRL file support** alongside `client_ca_file`, re-read on reload, for
   operators with existing CRL infrastructure. The allow-list covers the same
   ground with fewer moving parts, so this is only worth doing for a fleet whose
   revocation already flows through a CRL.
2. **Certificate expiry warnings** at startup and on reload — a leaf expiring
   inside 30 days logged at WARN. Nothing warns today; expiry shows up as a
   handshake failure.
3. **Per-identity rate limits.** The natural follow-on now that identity exists,
   and the natural home for the per-IP limiting that was also removed. Kept out
   of scope here so this feature stayed reviewable.
4. **Per-client identity in the `http` sink's status output.** The endpoint
   reports the policy and counters, but not which identities are currently
   connected; session metadata has the data.
5. **A list of `identity` modes** (try `san_uri`, fall back to `cn`) for
   heterogeneous PKI. A single mode is simpler and covers a uniform CA.

## Decisions Taken

Four questions were left open by the proposal. What was chosen, and why:

1. **An empty allow-list allows rather than denies.** Deny-by-default is the
   safer instinct, but `type = "mtls"` with no list is a legitimate
   configuration — "any peer this CA issued, but bind the node labels" — and
   node binding alone is worth enabling without enumerating every node.
   Erroring on it would force operators to list their whole fleet to get
   trustworthy attribution. The compromise is a WARN at startup naming the
   condition and the fix.
2. **`identity` takes a single mode.** Simpler, and a uniform CA is the common
   case. Listed above as a possible extension.
3. **Per-identity rate limits are out of scope**, as proposed.
4. **`assert` rejects rather than warns and corrects.** A certificate/config
   mismatch under `assert` is an outage, which is the point: `force` is the
   forgiving option and it is the default, so an operator reaches for `assert`
   precisely when they want the mismatch to be loud.
