# Security

This page covers LogWisp's transport security: what it protects, how to
configure it, and — equally important — what it does not yet do.

## Current State

**Implemented:**

- TLS 1.2 / 1.3 on all network sources and sinks.
- Server certificate verification by dialers, by a CA or by the pin of the
  server's key (`pin_sha256`).
- Certificates without files: listeners make theirs at startup, self-signed
  or from an issuer CA, and `lw tls` makes a CA and certificates: see
  [Certificates made at startup](#certificates-made-at-startup).
- Mutual TLS (client certificate required and verified), at the transport
  layer.
- Peer identity recorded per session.
- Authorization from certificate identity (allow-lists, node binding): see
  [The Auth Block](#the-auth-block).
- Password (Argon2id-SCRAM) authentication, bound to the TLS channel: see
  [Password Authentication](#password-authentication-scram).
- Authentication on the `http` sink's stream and status endpoints: client
  certificate or bearer token.
- Browser logins behind a site's TLS-terminating proxy: see
  [Browsers behind a TLS-terminating proxy](#browsers-behind-a-tls-terminating-proxy).
- Server pinning by dialers: certificate identity (`mtls`), bound certificate
  (`scram`).
- Address rules and per-client connection and request limits on every
  listener, applied before TLS to the client a PROXY header (v1 or v2) from a
  listed L4 proxy names, and per request to the client an L7 proxy forwards:
  see [The ACL Block](#the-acl-block).
- Startup warnings for expiring certificates and risky settings: see
  [Startup Warnings](#startup-warnings).
- Unknown configuration keys rejected: a typo in `tls`, `auth`, `acl` or a
  table path fails startup.
- Configuration input hardened (lixenwraith/config v0.2.2 and
  lixenwraith/toml v0.1.3, reviewed with adversarial tests and fuzzing like
  `auth`):
  - a document creates at most 65536 tables, so a small file cannot exhaust
    memory, and unescaped control characters are refused in strings and
    comments;
  - a string in the file is one list entry, so a filter pattern holding a
    comma is not split into patterns that match nothing;
  - the file is opened without blocking, so a FIFO swapped in for it cannot
    hang the watcher or a `SIGHUP` reload;
  - a permission change on the file is reported once and does not stop
    auto-reload;
  - parse and conversion errors name the key, never the value, so a secret
    placed in the wrong key does not reach the log.

**Not implemented:**

- Certificate revocation lists (CRL) or OCSP: revoke by editing the allow-list
  or credentials file.
- Per-identity limits: the per-client limits count addresses, not the
  identities `auth` proves.
- Per-client stream caps: under HTTP/2 `max_connections_per_client` bounds a
  client's connections, not the streams each carries; the request rate only
  slows how fast it opens them.

Two credentials are supported. Certificates (`mtls`) are the one the transport
already carries: the `tls` block establishes that a peer chains to your CA, and
the `auth` block decides which of those peers may do what. Passwords (`scram`)
need no client PKI: the listener holds verifiers, never passwords, and every
login is bound to the listener's certificate.

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
pin_sha256           = ""
self_signed          = false
issuer_cert_file     = ""
issuer_key_file      = ""
hosts                = []
min_version          = "1.3"
```

Options by role, each with its default:

- Both roles
  - `enabled` (`false`): master switch; when false the whole block is ignored.
  - `cert_file`: local certificate; a listener needs it, `self_signed` or the
    issuer files, a dialer may present it as its client identity.
  - `key_file`: private key for `cert_file`; set the two together.
  - `min_version` (`"1.3"`): `"1.2"` or `"1.3"`.
- Listeners
  - `self_signed` (`false`): make a self-signed certificate at startup.
  - `issuer_cert_file`, `issuer_key_file`: make one at startup, signed by this
    CA (`lw tls ca`).
  - `hosts` (`[]`): names and addresses a made certificate carries, beyond the
    listener's `host`, `os.Hostname()`, `localhost`, `127.0.0.1` and `::1`.
  - `client_auth` (`false`): require and verify a client certificate (mTLS).
  - `client_ca_file`: CA bundle that verifies client certificates; **required**
    when `client_auth` is true.
- Dialers
  - `ca_file` (system store): CA bundle that verifies the server certificate.
  - `server_name` (the configured `host`): SNI and certificate name to verify
    against.
  - `insecure_skip_verify` (`false`): disable server verification.
  - `pin_sha256`: `sha256//BASE64` of the server's public key, curl's
    `--pinnedpubkey` form, `;` between several; it replaces the CA and name
    checks.

Listeners are the `tcp` and `http` sinks and the `tcp_chain` and `http_chain`
sources; dialers are the `tcp_chain` and `http_chain` sinks.

> `min_version` takes `"1.2"` or `"1.3"`. The older `"TLS1.2"` spelling from
> pre-restructure releases is rejected. There is no `max_version` and no
> `cipher_suites` option; TLS 1.3 suites are not configurable in Go, and the
> 1.2 defaults are the standard library's.

### Validation

Misconfiguration fails at plugin construction, before the pipeline starts:

- a listener with `enabled = true` and none of `cert_file`/`key_file`,
  `self_signed`, `issuer_cert_file`/`issuer_key_file`, or more than one; an
  issuer that is no CA (`lw tls ca` makes one)
- `pin_sha256` with `ca_file` or `insecure_skip_verify`, or not of the
  `sha256//BASE64` form; a listener key on a dialer, or `pin_sha256` on a
  listener
- `client_auth = true` with no `client_ca_file`
- a dialer with only one of `cert_file` / `key_file`
- a certificate or key that will not load, or a CA file containing no
  certificates
- a `min_version` that is neither `"1.2"` nor `"1.3"`
- a key the plugin does not know, at any depth: `unknown key "tls.enabeld"`. A
  misspelled option must not silently leave a protection switched off

## The Auth Block

TLS answers "is this channel private, and does the peer chain to a CA". Auth
answers "may *this* peer do *this*". They are separate blocks because they are
separate questions.

```toml
[pipelines.plugin_sources.config.auth]    # or plugin_sinks.config.auth
type              = "none"                # none | mtls | scram
identity          = "cn"                  # cn | san_dns | san_uri | san_email
allow             = []                    # mtls
allow_patterns    = []                    # mtls
node_binding      = "force"               # chain sources only
credentials_file  = ""                    # scram listeners
token_lifetime_ms = 0                     # scram, HTTP listeners; 10 s to 24 h, 0 = 15 minutes
username          = ""                    # scram dialers
password_file     = ""                    # scram dialers
trusted_proxies   = []                    # scram http sink behind a TLS-terminating proxy
```

Options by where they apply, each with its default:

- Every plugin
  - `type` (`none`): `none` ignores the block; `mtls` authorizes by
    certificate identity, `scram` by password.
- Chain sources
  - `node_binding` (`force`): `none`, `assert` or `force`.
- `mtls`, and `scram` listeners
  - `identity`: the certificate field carrying the identity; `cn` under
    `mtls`, unset under `scram`, where it binds the client certificate to the
    user.
- `mtls`
  - `allow` (`[]`): exact identities to admit.
  - `allow_patterns` (`[]`): RE2 patterns matched against the identity; anchor
    them yourself.
- `scram` listeners
  - `credentials_file`: verifiers written by
    [`lw auth add-user`](cli.md#lw-auth).
  - `token_lifetime_ms` (15 minutes): bearer token lifetime, 10 s to 24 h; the
    `http` sink and `http_chain` source only.
  - `trusted_proxies` (`[]`): addresses or CIDRs of the reverse proxies that
    end the browsers' TLS; the `http` sink only, see
    [Browsers behind a TLS-terminating proxy](#browsers-behind-a-tls-terminating-proxy).
- `scram` dialers
  - `username`: user to log in as.
  - `password_file`: file holding the password; one trailing line break is
    trimmed.

**Roles by plugin**, and what the block decides:

- Listeners
  - `tcp_chain` and `http_chain` sources: which senders may ingest, and what
    node label their entries carry.
  - `tcp` and `http` sinks: which clients may read the stream (and, on
    `http`, the status endpoint).
- Dialers: the `tcp_chain` and `http_chain` sinks.
  - `mtls`: which server identity to accept, beyond hostname verification.
  - `scram`: which user to log in as.

### Identity

Under `mtls` the identity is one string pulled from the peer's verified leaf
certificate; under `scram` it is the username. The handshake has already
checked the chain, signature, and validity window, so this is pure field
selection.

Modes, each with the field it reads and its typical use:

- `cn` (default): `Subject.CommonName`; matches the existing `tls_peer_cn`
  metadata.
- `san_dns`: the first DNS SAN; host identities.
- `san_uri`: the first URI SAN; SPIFFE-style IDs.
- `san_email`: the first email SAN; operator identities.

A certificate with no usable value in the chosen field is rejected. An empty
identity is a refusal, not an empty match.

### The allow list

`allow` is an exact-match set; `allow_patterns` holds RE2 patterns. An identity
passes if it appears in either. Under `scram` the credentials file is the allow
list, and both keys are refused.

Leaving **both** empty under `type = "mtls"` admits any identity the CA vouches
for. That is deliberate — it is how you enable node binding without enumerating
a whole fleet — but it is announced rather than silent:

```
WARN msg="Auth policy admits any identity the configured CA vouches for"
     component=tcp_chain_source instance_id=in_tcp
     hint="set auth.allow or auth.allow_patterns to authorize named peers"
```

Anchor your patterns. `allow_patterns = ["edge-\\d{2}"]` matches
`evil-edge-01-impostor`; `["^edge-\\d{2}$"]` does not. An unanchored pattern is
reported at startup.

### Node binding

`node_binding` applies only to the chain sources. `assert` and `force` take the
connection label over from `trust_node`; only `force` also overrides the
per-entry labels.

- `none`: `trust_node` governs both the connection label and the per-entry
  `node` field.
- `assert`
  - Connection label: must equal the identity; a mismatch or an omission is
    rejected.
  - Per-entry `node` field: `trust_node` governs.
- `force`
  - Connection label: ignored; the identity is used.
  - Per-entry `node` field: overwritten with the identity.

Use **`force`** on an ingest boundary you do not trust. Every entry is
relabelled, so a compromised edge cannot smuggle a foreign origin through the
per-entry `node` field either. It is the default whenever `type` is `mtls` or
`scram`.

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

Under `mtls`, the block on a chain sink pins the *server's* identity. Hostname
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
connect failure. Under `scram` the dialer binds its login to the certificate it
was shown instead; see [Channel binding](#channel-binding).

### Validation

Misconfiguration fails at plugin construction, before the pipeline starts:

- `type` `mtls` or `scram` without `tls.enabled` (proxy mode aside), or on a
  dialer with `tls.insecure_skip_verify`: an identity read from an unverified
  chain is a claim, and an unverified server could relay a login
- `type = "mtls"` on a listener without `tls.client_auth`
- a block naming peers or credentials (`allow`, `allow_patterns`,
  `credentials_file`, `token_lifetime_ms`, `username`, `password_file`,
  `trusted_proxies`) whose `type` is `none` or unset: auth was intended and the
  type forgotten
- a key of the other method: `allow` or `allow_patterns` under `scram`, a
  `scram` key under `mtls`
- a `scram` listener without a loadable `credentials_file` (see
  [Credentials file](#credentials-file)), with `username` or `password_file`,
  with a `token_lifetime_ms` outside 10 s to 24 h or on a TCP listener, or with
  `identity` but no `tls.client_auth`
- a `scram` dialer without `username` and `password_file`, with
  `credentials_file`, `token_lifetime_ms`, `trusted_proxies` or `identity`
  (server pinning is `mtls` only), or with a password file that is empty or
  over 1024 bytes
- `trusted_proxies` on anything but the `http` sink, with `identity`, or with
  an entry that is neither an address nor a CIDR; `login_page` or
  `viewer_page` without `trusted_proxies`, `viewer_page` without `login_page`
- an `identity` that is not one of the four modes
- an `allow_patterns` entry that does not compile
- a `node_binding` that is not one of the three values, or one set on a plugin
  that has no node concept
- an HTTP path (`stream_path`, `status_path`, `ingest_path`) equal to `/auth`,
  which is reserved for logins

Errors read like `auth: type "mtls" requires tls.client_auth`.

## The ACL Block

`acl`, beside `tls` and `auth` on the four listeners (`tcp` and `http` sinks,
`tcp_chain` and `http_chain` sources), refuses peers by address as the socket
is accepted: before the TLS handshake or a byte of the protocol, so a refused
peer costs no handshake and never reaches `auth`.

```toml
[pipelines.plugin_sources.config.acl]
allow = ["192.0.2.0/24", "198.51.100.7"] # addresses or CIDRs; empty: all
deny  = ["192.0.2.66"]                   # refused, listed in allow or not
proxy_protocol = "required"              # off (default), optional, required
proxy_from = ["10.0.0.5"]                # L4 proxies sending PROXY headers
max_connections_per_client = 4           # at once; 0 (default): no cap
requests_per_second_per_client = 10      # HTTP listeners; 0 (default): none
```

- `deny` wins; then a non-empty `allow` admits only its entries, an empty one
  every address `deny` does not list.
- Entries are of the listener's [family](networking.md#address-family): IPv4
  on an IPv4 listener, IPv6 on an IPv6 one, either behind a hostname (only the
  family it binds ever matches). Behind `proxy_from` or the `http` sink's
  `trusted_proxies` they take either, as the proxy may name a client of
  either. An entry of the other family, an
  IPv4-mapped address, one with a zone, or anything but an address or CIDR
  fails construction. A link-local peer matches without its zone.
- A refused connection is closed at once and counted in `acl_denied`, or
  `acl_limited` past a [limit](#per-client-limits) (plugin stats, the `http`
  sink's status). A WARN names the client, the reason and the counts, at most
  once a minute per listener; the refusals in between are only counted.
- The rules see the client: the socket peer, or the client a PROXY header
  names. Behind the `http` sink's `trusted_proxies` they judge the L7 proxy
  as the peer, then each request's forwarded client (`403` when refused,
  counted in `acl_denied`): allow both.
- The `serve` and `aggregator` presets take `allow` and `deny` list keys.
- Dialers have no `acl`: on a `tcp_chain` or `http_chain` sink it is an
  unknown key.

### Per-client limits

- `max_connections_per_client` caps the connections a client holds at once,
  on every listener; past it a connection is closed like a refused one.
  - HTTP keep-alive connections count, idle ones too, and a browser opens up
    to six; under HTTP/2 one connection carries a client's many requests.
  - Behind `trusted_proxies` every connection is the proxy's, so the key
    fails construction: cap clients at the proxy.
- `requests_per_second_per_client`, on the `http` sink and the `http_chain`
  source, admits a second's worth of requests at once (at least one),
  refilled at that rate; past it a request gets `429`, with `Retry-After` the
  seconds until its next (1 at a rate of 1 or more).
  - Every request counts but the SCRAM exchange (`POST /auth`), which
    [throttling](#throttling) limits: stream, status, ingest and the viewer's
    files, about six for a viewer's first load.
- A client is the address the rules see, an IPv6 one by its /64 and a
  link-local one per link, so the hosts of one /64 (a SLAAC LAN) share a
  budget; behind `trusted_proxies` the request rate counts the forwarded
  client.
- Each limit tracks up to 65,536 clients, a client until its budget is whole
  again, and refuses new ones when full, failing closed. SCRAM throttling
  keeps its budgets the same way.

### PROXY protocol

Behind an L4 proxy that passes TLS through (nginx `stream`, HAProxy
`mode tcp`) every peer comes from the proxy's address. With `proxy_protocol`
the proxy names the client in a PROXY header, v1 (text) or v2 (binary), sent
before the TLS ClientHello; LogWisp still ends TLS, so channel binding and
client certificates are unchanged.

- `proxy_protocol` and `proxy_from` come together; `proxy_from` holds the
  proxies' addresses or CIDRs, of the listener's family. A peer with a zone
  (link-local IPv6) is never a proxy.
- A peer in `proxy_from`:
  - sends its header within `tlsx.HandshakeTimeout` (10 s); a malformed,
    oversized (v1 over 107 bytes, a v2 block over 2048) or late one is
    refused;
  - under `required` is refused without a header; under `optional` it keeps
    its socket address, after up to 10 s if it sends nothing at first. A
    client the proxy forwards without a header then passes as the proxy, so
    `optional` (which warns at startup) suits only a rollout; set `required`
    once every route from `proxy_from` sends the header;
  - keeps its socket address for `LOCAL` (v2) and `UNKNOWN` (v1), the proxies'
    health checks, and for v2 families other than TCP over IPv4 and IPv6. TLVs
    are skipped.
- Headers are read off the accept loop: a slow proxy holds only its own
  connection.
- A peer not in `proxy_from` connects as itself; one that sends a header is
  refused at its first read, as any peer can write one.
- The connection then reports the client (an IPv4-mapped one as IPv4) to the
  rules, SCRAM [throttling](#throttling), sessions and logs. Session metadata
  keeps the proxy as `peer_addr`, and a refusal's WARN names it.
- `acl_proxy_headers` counts the headers read.
- The `http` sink's proxy mode is the L7 counterpart: `trusted_proxies` trusts
  `X-Forwarded-For` from a proxy that ends TLS, `proxy_from` a PROXY header
  from one that passes it through.

## Startup Warnings

Some settings work but are usually mistakes. Each plugin reports them at WARN
when it is constructed, so startup and every reload repeat them:

- a certificate in `cert_file`, `ca_file`, `client_ca_file` or
  `issuer_cert_file` that has expired, is not yet valid, or expires within 30
  days
- a self-signed listener, with the `pin_sha256` its dialers need
- `insecure_skip_verify` on a dialer
- an `allow_patterns` entry not anchored at both ends of every alternative
  (`^a|b$` admits `a…` and `…b`)
- a `key_file`, `issuer_key_file`, `credentials_file` or `password_file` every
  local user can read
  (once per path per process)
- an `acl` entry with host bits set (`10.0.0.1/8`), naming the network it
  matches; an `acl.allow` entry of a whole family (`0.0.0.0/0`, `::/0`); a
  wildcard listener whose `acl` has `deny` but no `allow`; an `acl.proxy_from`
  entry reaching beyond private, loopback and link-local addresses;
  `acl.proxy_protocol = "optional"`

## Certificates made at startup

A listener needs no certificate files. With `self_signed = true`, or with
`issuer_cert_file` and `issuer_key_file`, it makes an ECDSA P-256 key once per
process and, at startup and every reload, a certificate for it valid 397 days
(never past the issuer), for `hosts`, its `host` (unless a wildcard),
`os.Hostname()`, `localhost`, `127.0.0.1` and `::1`. Every such listener of
one process shares that key, self-signed or issued, so one pin matches them
all; a dialer that must tell two apart verifies by name with `ca_file`, or
the listeners use `cert_file`.

- **Self-signed.** No CA can vouch for it, so dialers pin its key:
  `pin_sha256`, which the listener logs at WARN on every start. A reload
  keeps the key and so the pin; a restart changes both, and every dialer must
  be given the new pin. Suits one aggregator and a few edges, a test, or a
  stream read by `curl --pinnedpubkey`.
- **Issuer.** `lw tls ca` makes a CA once; the listener signs its own
  certificate with it, and dialers verify it with `ca_file = ca.crt`, by name,
  across restarts. The CA key then lives on the listener's host: give each
  listener group its own CA, or issue certificates elsewhere with
  `lw tls cert` and use `cert_file`.
- **Pins.** A pin is the SHA-256 of the server's public key, not of its
  certificate, so it survives reissue. `pin_sha256` accepts several, `;`
  between them, for a rotation. It replaces chain, name and validity checks:
  whoever holds the key is the server. A pinned dialer never resumes a TLS
  session, so every connection checks the pins, and a pin a reload drops
  holds at once. `scram` dialers still bind every login to that certificate.

```bash
lw tls ca --dir /etc/logwisp/pki                       # ca.crt, ca.key (0600)
lw tls cert --ca-dir /etc/logwisp/pki --name agg.example.org --server
lw tls cert --ca-dir /etc/logwisp/pki --name edge-01 --client
```

## Enabling mTLS

### 1. Generate a CA and certificates

`lw tls` makes them ([above](#certificates-made-at-startup)); with `openssl`,
`cfssl`, `step-cli` or an existing PKI:

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

A client that presents no certificate is refused during the handshake
(`tls: client didn't provide a certificate`, counted in `tls_handshake_errors`).
A client whose certificate is valid but whose identity is not authorized gets
past the handshake and is refused by the policy:

```
WARN msg="Connection rejected by auth policy" component=tcp_chain_source
     remote_addr=<addr> error="auth: refused: identity \"edge-99\" is not allowed"
```

Policy rejections are counted in the plugin's `auth_rejected` statistic; the
`http` sink's status endpoint reports its own. Accepted peers are recorded in
session metadata as `auth_method` and `auth_identity`.

`test/mtls-chain-test.sh` builds a throwaway PKI and exercises the whole surface
end to end — run it with `--auto` to see each guarantee asserted.

## Password Authentication (SCRAM)

`type = "scram"` authenticates peers by username and password with
Argon2id-SCRAM from `lixenwraith/auth`. It needs TLS but no client
certificates, works on all six network plugins, and is LogWisp's own protocol,
not standard SASL: viewers use the [`lw auth`](cli.md#lw-auth) CLI or,
behind a TLS-terminating proxy, the shipped browser client.

```toml
# Listener: tcp_chain/http_chain source, tcp/http sink
[pipelines.plugin_sources.config.tls]
enabled   = true
cert_file = "/etc/logwisp/tls/relay.crt"
key_file  = "/etc/logwisp/tls/relay.key"
[pipelines.plugin_sources.config.auth]
type             = "scram"
credentials_file = "/etc/logwisp/users.toml"

# Dialer: tcp_chain/http_chain sink
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "/etc/logwisp/tls/ca.crt"
[pipelines.plugin_sinks.config.auth]
type          = "scram"
username      = "edge-01"
password_file = "/etc/logwisp/edge-01.pass"
```

Startup reports `auth="scram users=2 certificate=independent node_binding=force"`
on such a chain source, and `auth="scram user=edge-01"` on the dialer.

### Mechanism

For each user the listener keeps a salt, the Argon2id cost, and two keys derived
from `K = Argon2id(password, salt)`: `StoredKey = SHA-256(HMAC(K, "Client
Key"))` and `ServerKey = HMAC(K, "Server Key")`. Neither logs anyone in, but
each password guess against them costs one Argon2id, so keep the file private.
Checking a login is HMAC work only; Argon2id (3 passes, 64 MiB, 4 threads) runs
on the dialer or the CLI. The proof is mutual: the dialer accepts the server's
final message only when it is signed with this user's `ServerKey`, and it
refuses a challenge asking for less Argon2 work than those defaults, so a rogue
server cannot request a cheaply crackable proof. An unknown user gets a stable
decoy challenge and fails exactly like a wrong password: `authentication
failed`.

### Channel binding

Both sides bind the proof to the SHA-256 of the listener's leaf certificate:
the listener hashes the certificate it serves, the dialer the one it was shown.
A TLS-terminating proxy or interceptor shows another certificate — CA-valid or
not — so the proof fails and the relay never obtains a link or a token. The
dialer is told `authentication failed` either way; the listener compares the
hash the dialer reports, logs `the client saw another server certificate: TLS
interception or a terminating proxy`, and counts `auth_binding_mismatch`.

An HTTP login takes two requests, and every later request may open a new pooled
connection. After the challenge the dialer pins the certificate it was bound to:
the proof and every ingest request must meet the same certificate, or the TLS
handshake fails before anything is sent. The `http_chain` sink then drops token
and pin and logs in again, which also covers a rotated server certificate. A
token printed by `lw auth token` is not pinned.

### Certificates and users

`tls.client_auth` is optional under `scram`, and on its own independent of the
password: a peer needs *some* certificate the CA issued and *some* valid
password, like PostgreSQL's `clientcert=verify-ca`. Setting `identity` (which
requires `tls.client_auth`) binds the two: the certificate's identity field must
equal the username, so every peer needs its own certificate *and* its own
password, like `clientcert=verify-full`. A mismatch fails the login; an HTTP
request whose certificate does not match its token's user gets `403`. Startup
shows the mode as `certificate=independent` or `certificate=cn=username`.

### Tokens

The `http` sink and `http_chain` source answer a login at `POST /auth` with a
bearer token: an HS256 JWT valid for `token_lifetime_ms` (default 15 minutes)
and signed with a key drawn when the plugin is built, so **every reload revokes
every token** (a rejected reload keeps the running service and its tokens). A
missing, invalid or expired token gets `401` with `WWW-Authenticate: Bearer
realm="logwisp"`. An SSE stream is checked when it connects and then outlives
its token; a reload ends it. TCP has no tokens: each connection runs its own
exchange.

### Throttling

Logins are throttled per client (an IPv6 client per /64): the socket peer, the
client a [PROXY header](#proxy-protocol) names, or on an `http` sink in proxy
mode the forwarded client; forwarded headers are read only from
`trusted_proxies`. Each exchange takes a token from a bucket of 10
that refills at one per second, and a successful login gives it back, so only
failed or abandoned attempts drain it. At most 4 exchanges per address may be
unfinished: an HTTP challenge never answered holds its slot for up to 30 s, a
TCP connection that ends mid-exchange frees it at once. A refused start answers
`too many attempts` (HTTP `429`) and counts `auth_throttled`; the table holds
65,536 addresses and refuses new ones when full. Separately, at most 4,096
exchanges may be in flight per listener; beyond that, or while the plugin
stops, a login gets `busy` (HTTP `503`) and counts `auth_busy`. Peers behind
one NAT, or one passthrough proxy that sends no PROXY header, share a bucket:
there, one client can exhaust every other client's logins.

### Credentials file

```toml
# logwisp SCRAM verifiers, written by `lw auth add-user`. Keep it private.
decoy_key = "<base64, 32 random bytes>"

[[users]]
argon_memory = 65536
argon_threads = 4
argon_time = 3
salt = "<base64>"
server_key = "<base64>"
stored_key = "<base64>"
username = "edge-01"
```

Write it with [`lw auth add-user`](cli.md#lw-auth) rather than by
hand. The whole file is validated when the plugin is built: a `decoy_key` of at
least 32 bytes, at least one user, unique names, no unknown keys, and one Argon2
profile and salt length for every user, since mixed profiles would tell a prober
which users exist. `decoy_key` keeps unknown-user challenges stable across
restarts and edits; the CLI creates it once and preserves it. A single probe
cannot tell a real user from an unknown one, but a prober polling a name sees
its salt change when the user is added, rotated or removed. The file is read
only when the plugin is built and `auto_reload` does not watch it: send
`SIGHUP` after every change. Use one file per listener when listeners admit
different users.

### Rollout, rotation and revocation

- **Rollout.** Turning `scram` on cuts off every dialer of that listener that
  has no credentials. Upgrade every binary first, then add a second listener
  with `scram` on another port, move the dialers to it, and remove the old one.
- **Password rotation.** `lw auth add-user --generate` with the user's
  `--password-file` replaces verifier and password together. `SIGHUP` the
  listener, deploy the password file, `SIGHUP` the dialer. Logins fail in
  between and the dialer retries under backoff, holding its current entry or
  batch while its input queue fills. To avoid the gap, add a second user, move
  the dialer to it, then remove the first; under `node_binding = "force"` the
  node label follows the username.
- **Revocation.** `lw auth remove-user`, then `SIGHUP`. The reload drops
  every connection and revokes every token; other dialers log in again on
  their own.

### Limits

- TLS must terminate at LogWisp, except on an `http` sink in proxy mode. Behind
  any other terminating proxy or load balancer every login fails by design;
  pass TLS through instead (TCP or SNI routing), with a
  [PROXY header](#proxy-protocol) so each client keeps its own throttling
  budget.
- One process per HTTP address. Handshake state and the token key live in one
  instance, so behind a balancer the proof or the token can reach an instance
  that never saw the login.
- Browsers log in only to an `http` sink in proxy mode, below; elsewhere use
  `mtls` for browsers.
- `nc` and `openssl s_client` cannot read a `scram` `tcp` sink; use
  `lw auth stream`.

`test/scram-chain-test.sh --auto` exercises these guarantees end to end.

### Browsers behind a TLS-terminating proxy

A site that serves the log stream inside its own pages ends TLS at its reverse
proxy and need not give LogWisp a private key. `trusted_proxies` puts the `http`
sink in proxy mode, where browsers log in with the client LogWisp ships; the
password reaches neither the proxy nor LogWisp.

```toml
[pipelines.plugin_sinks.config]
host        = "127.0.0.1"
port        = 8081
login_page  = true                     # GET /auth/login
viewer_page = true                     # GET /auth/view, needs login_page
[pipelines.plugin_sinks.config.auth]
type             = "scram"
credentials_file = "/etc/logwisp/users.toml"
trusted_proxies  = ["127.0.0.1"]       # addresses or CIDRs
```

```nginx
location /logs/ {
    proxy_pass       http://127.0.0.1:8081/;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

- **Trust.** Every other peer gets `403` on every path. `X-Forwarded-Proto`
  must be `https` on every hop, so a site accidentally served in plaintext fails
  closed. The client is the rightmost `X-Forwarded-For` hop that is not a
  proxy; throttling, sessions and logs use it. List only the proxies: a client
  inside a listed range is trusted to name its own hops.
- **Unbound logins.** The browser cannot see a certificate LogWisp could bind
  to, so proofs are unbound and a party on the hop between proxy and LogWisp
  could relay a login. Keep that hop on loopback or a trusted network, or
  enable `tls` on the sink; a plaintext hop to a proxy off this host is
  warned about at startup. `identity` cannot be combined with proxy mode.
- **Sessions.** The login page asks for a cookie: `logwisp_session`,
  `HttpOnly`, `Secure`, `SameSite=Strict`, `Max-Age` the token lifetime, and no
  `Path`, so it scopes itself to the mount (`/logs` above). Stream and status
  accept it or a bearer token, so `new EventSource("/logs/stream")` works on any
  page of the site, beside the site's own Basic auth too, and `lw auth token
  --unbound` keeps working. `POST /auth` with `{"logout": true}` clears the
  cookie and revokes the token until it expires. `/auth` takes only
  `application/json`, which a cross-origin page cannot send without a preflight.
- **Private windows.** Private or incognito windows keep cookies in memory,
  apart from normal windows: they sign in on their own, and the session ends at
  the token lifetime or when the last private window closes.
- **Cookies disabled.** The viewer runs in token mode when the browser keeps no
  cookie for the site.
  - It notices from `navigator.cookieEnabled`, from a throwaway cookie with the
    session's attributes that does not come back (Chromium blocking every cookie
    still reports `cookieEnabled`), or from a `401` right after a cookie login,
    and shows its own sign-in form.
  - The token lives in a page variable only, never in storage or the URL. It
    lasts as long as the page and at most the token lifetime: a reload, another
    tab, or a reconnect after expiry asks again; sign out revokes it.
  - The login page says that cookies are unavailable and links to the viewer.
    A page not served over HTTPS keeps no `Secure` cookie either: both pages
    name HTTPS instead and offer no sign-in.
- **Integrating `scram.js`.** A site with its own CSP can copy `scram.js` from
  `internal/sink/http/web/` into its bundle: one dependency-free ES module,
  where `base` is the mount URL ending in `/`. It needs a secure context for
  WebCrypto and takes about 2 s of Argon2 per login on a desktop.
  - Cookie mode, the default: `login(base, username, password, {onProgress})`,
    then `EventSource` and `fetch` as for any same-origin resource;
    `logout(base)`.
  - Token mode: `login(..., {session: "token"})` resolves to `{username,
    expiresIn, token}`. Keep the token in memory; `stream(url, {token, signal,
    onEvent})` reads the event stream through `fetch` with the bearer, status
    takes `Authorization: Bearer`, and `logout(base, {token})` revokes it. The
    bearer replaces the Basic credentials a browser would send, so token mode
    cannot pass a proxy that asks for its own Basic auth.
  - `cookiesUsable()` tells which applies: false when the session cookie would
    not stick. `loginUnavailable()`, asked first, names why neither can run
    (no secure context), or is empty.
- **Pages.** Under `/auth/` the sink serves `scram.js` and `style.css` always,
  and with `login_page` / `viewer_page` the login page and a minimal live
  viewer with their scripts; `GET /` leads to the viewer, else the login page.
  All are served under `default-src 'none'; script-src 'self';
  connect-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors
  'none'; base-uri 'none'`.

`test/scram-proxy-test.sh --auto` logs in from headless Chromium through such a
proxy, with cookies and with every cookie blocked.

### Behind nginx or another proxy

A proxy in front of LogWisp works at one of two layers:

- **L7, ending TLS** (nginx `http` block, HAProxy `mode http`): the `http` sink
  in [proxy mode](#browsers-behind-a-tls-terminating-proxy).
  - `trusted_proxies` lists the proxy's address.
  - The proxy sends `X-Forwarded-Proto: https` and `X-Forwarded-For`. It may
    overwrite `X-Forwarded-For` with the real client: the rightmost hop that is
    not a proxy is the client either way.
- **L4, passing TLS through to LogWisp's own TLS** (nginx `stream` with
  `ssl_preread`, HAProxy `mode tcp`), with a [PROXY header](#proxy-protocol):
  whatever needs TLS to end at LogWisp.
  - Chain links (`tcp_chain`, `http_chain`).
  - `lw auth stream` viewers of a `tcp` sink.
  - An `http` sink that keeps its own TLS, and with it SCRAM channel binding
    or client certificates.

A common shape serves both from port 443:

```
:443              nginx stream: ssl_preread routes by SNI, proxy_protocol on
  logs.example.org    -> 127.0.0.1:8443   nginx http
  relay.example.org   -> a LogWisp TLS listener, which reads the header (below)
127.0.0.1:8443    nginx http: listens with proxy_protocol, ends TLS
  /logs/              -> 127.0.0.1:8081   LogWisp http sink, proxy mode
```

**The `http` sink behind the `http` block** works in proxy mode as is:
`trusted_proxies` is the `http` block's address, usually `127.0.0.1`, and the
block names the client from the PROXY header.

```nginx
server {
    listen      127.0.0.1:8443 ssl proxy_protocol;
    server_name logs.example.org;
    # ssl_certificate, ssl_certificate_key: the site's own
    location /logs/ {
        proxy_pass       http://127.0.0.1:8081/;
        proxy_set_header X-Real-IP         $proxy_protocol_addr;
        proxy_set_header X-Forwarded-For   $proxy_protocol_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

`$proxy_add_x_forwarded_for` does not fit this shape: it appends the stream
server's address, not the client's. LogWisp would name that address as every
client or, when it is trusted (both on `127.0.0.1`), the hop to its left: one
the client wrote, so the client picks its own throttling address. LogWisp
ignores `X-Real-IP`.

**LogWisp's own TLS listeners read the header** when their `acl` sets
`proxy_protocol` and lists the stream server in `proxy_from`; one stream
`server` with `proxy_protocol on` then routes every name:

```nginx
stream {
    map $ssl_preread_server_name $route {
        relay.example.org  127.0.0.1:9001;    # tcp_chain source
        tail.example.org   127.0.0.1:9002;    # tcp sink, for lw auth stream
        default            127.0.0.1:8443;    # the http block, logs.example.org
    }
    server {
        listen 443;
        ssl_preread    on;
        proxy_protocol on;
        proxy_pass     $route;
    }
}
```

```toml
[pipelines.plugin_sources.config.acl] # tcp_chain source; tcp sink alike
proxy_protocol = "required"
proxy_from     = ["127.0.0.1"]          # the stream server
```

- HAProxy: `send-proxy` or `send-proxy-v2` on the LogWisp backends.
- A listener without `proxy_protocol` behind such a route fails every
  connection: the header lands in front of its TLS handshake.
- Dialers must send the name: a `host` that is one, or `tls.server_name`
  (`--server-name` for `lw auth`); an IP literal sends no SNI.
- `test/acl-test.sh --auto` runs each listener kind behind a stub proxy
  sending a v1 or v2 header, and the `tcp` sink behind nginx when installed.

**Passthrough without PROXY** brings every peer from the proxy's address:

- All peers share one SCRAM [throttling](#throttling) budget: 10 failed or
  abandoned logins, then one per second, and 4 unfinished at once. One client
  that keeps failing logins makes every other client's logins answer
  `too many attempts` until it stops.
- Established `tcp_chain` links and open streams keep flowing; a reconnect
  waits for the budget. An `http_chain` sink whose early renewal is put off
  (`too many attempts` or `busy`) keeps sending on its token to the server it
  pinned, retrying every few seconds, and holds its batches only once that
  token has expired; any other refusal ends the token at once.
- Logs and sessions name the proxy, and `acl` rules see only the proxy: allow
  it, not the clients.

## What Each Layer Enforces

**`tls` with `client_auth = true`** — a membership check. The peer holds a
certificate chaining to `client_ca_file`, within its validity window, and holds
the matching private key. Every CA-issued certificate is equivalent at this
layer.

**`auth` with `type = "mtls"`** — an identity check, per listener: only the
identities you list may connect, so one CA can serve several trust domains and
a single peer can be withdrawn without touching the others.

**`auth` with `type = "scram"`** — a password check, per listener: only the
users in its credentials file may connect, the login cannot be relayed through
another certificate (proxy mode, where TLS ends at the site's proxy, aside),
and with `identity` each user is tied to its own certificate.

Under either method the chain `node` label can be bound to the identity, so a
compromised edge cannot attribute its entries to another host, and the `http`
sink's stream and status endpoints stop being open to anyone who can reach the
port.

**`acl`** — an address check, per listener, before TLS: it narrows who can
reach the other layers and how much each address may take, never proves who a
peer is.

**Revocation** is the allow-list or the credentials file, not a CRL. Remove the
identity or user and send `SIGHUP`: the reload rebuilds every pipeline, so the
change takes effect on the next connection and existing ones are dropped by the
rebuild. No network call on the handshake path, and no window between revocation
and the next CRL publication. See
[mtls-auth-plan.md](mtls-auth-plan.md#not-implemented) for what CRL support
would add.

## Surfaces Without Access Control

An `auth` block (`mtls` or `scram`) closes each of these. Without one, bind them
to a trusted interface, front them with an authenticating proxy, or narrow them
to known networks with `acl.allow`.

What each exposes when `auth.type = "none"`:

- `http` sink `stream_path`: the full log stream, with
  `Access-Control-Allow-Origin: *`, so any browser origin can read it (the
  header is omitted once an auth policy is set).
- `http` sink `status_path`: host, port, TLS flag, uptime, client counts,
  throughput counters.
- `http` sink `GET /` (`303` to `/auth/view`) and the viewer's files: static
  pages that read the two endpoints above under the CSP and expose nothing
  beyond them. Under `mtls` they are served before the allow list, while the
  stream and status stay gated.
- `tcp` sink: the full log stream to any client that connects.
- `tcp_chain` and `http_chain` sources: ingest from any peer that can connect
  (with `client_auth`, any the CA vouches for), under any node label it
  claims.

`max_connections` bounds concurrency on all but the `http_chain` source; the
`acl` block's [per-client limits](#per-client-limits) bound each caller's
share.

Both methods require TLS on the listener, except an `http` sink in proxy mode,
where TLS ends at the trusted proxy; `mtls` also requires `client_auth`.

## Operational Guidance

**Certificates and secrets**

- Use a dedicated CA for LogWisp so its trust decisions stay independent.
- Keep leaf lifetimes short (90–825 days) and automate renewal.
- Key, credentials and password files should be `0600` and owned by the service
  account; a world-readable one is reported at startup. `lw auth` creates
  them `0600` and keeps the mode of an existing file.
- Rotation requires a reload (`SIGHUP`), because certificates and credentials
  are loaded once at plugin construction; there is no on-disk watch for them.
- Startup and every reload warn 30 days before a certificate lapses. Still
  automate renewal; the warning only reaches someone reading the log.
- Keep the identity field you authorize on stable across rotations. Reissuing a
  leaf with a different CN silently drops the peer out of the allow list.

**Deployment**

- Prefer `min_version = "1.3"`. Drop to `"1.2"` only for a peer that genuinely
  cannot do 1.3.
- Never enable `insecure_skip_verify` outside a lab; it disables server
  verification entirely and makes the connection trivially interceptable. It is
  reported at startup.
- Bind listeners to specific interfaces rather than `0.0.0.0` where you can.
- On any ingest port reachable from a network you do not fully control, set an
  `auth` block: `mtls` with an explicit `allow` list, or `scram`.
  `trust_node = false` is the fallback when neither is an option; it is
  unforgeable but labels entries by remote address, which is useless behind NAT
  or a load balancer.
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

The `raw` format passes control characters through. A console sink writing to
a terminal escapes them itself (`escape = "auto"`), so a log line cannot move
the cursor, retitle the window, write the clipboard (OSC 52) or reorder text
with bidi controls; pipes and files get the bytes unchanged. See
[Sinks](sinks.md#console).
