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
| Authorization from certificate identity (allow-lists, node binding) | Implemented — see [The Auth Block](#the-auth-block) |
| Password (Argon2id-SCRAM) authentication, bound to the TLS channel | Implemented — see [Password Authentication](#password-authentication-scram) |
| Authentication on the `http` sink's stream and status endpoints | Implemented: client certificate or bearer token |
| Browser logins behind a site's TLS-terminating proxy | Implemented — see [Browsers behind a TLS-terminating proxy](#browsers-behind-a-tls-terminating-proxy) |
| Server pinning by dialers | Implemented: certificate identity (`mtls`), bound certificate (`scram`) |
| Startup warnings for expiring certificates and risky settings | Implemented — see [Startup Warnings](#startup-warnings) |
| Unknown configuration keys rejected | Implemented — a typo in `tls`, `auth` or a table path fails startup |
| Certificate revocation lists (CRL) or OCSP | **Not implemented** — revoke by editing the allow-list or credentials file |
| IP allow/deny lists, per-IP connection or request limits | **Not implemented** — only SCRAM logins are throttled per address |

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

Listeners are the `tcp` and `http` sinks and the `tcp_chain` and `http_chain`
sources; dialers are the `tcp_chain` and `http_chain` sinks.

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

| Option | Applies to | Default | Description |
|--------|------------|---------|-------------|
| `type` | all | `none` | `none` ignores the block; `mtls` authorizes by certificate identity; `scram` by password |
| `identity` | `mtls`; `scram` listeners | `cn` (`mtls`), unset (`scram`) | Certificate field carrying the identity. Under `scram` it binds the client certificate to the user |
| `allow` | `mtls` | `[]` | Exact identities to admit |
| `allow_patterns` | `mtls` | `[]` | RE2 patterns matched against the identity; anchor them yourself |
| `node_binding` | chain sources | `force` | `none`, `assert`, or `force` |
| `credentials_file` | `scram` listeners | — | Verifiers written by [`logwisp auth add-user`](cli.md#logwisp-auth) |
| `token_lifetime_ms` | `scram` on the `http` sink and `http_chain` source | 15 minutes | Bearer token lifetime, 10 s to 24 h |
| `username` | `scram` dialers | — | User to log in as |
| `password_file` | `scram` dialers | — | File holding the password; one trailing line break is trimmed |
| `trusted_proxies` | `scram` on the `http` sink | `[]` | Addresses or CIDRs of the reverse proxies that end the browsers' TLS; see [Browsers behind a TLS-terminating proxy](#browsers-behind-a-tls-terminating-proxy) |

**Roles by plugin:**

| Plugin | Role | Decides |
|--------|------|---------|
| `tcp_chain` source, `http_chain` source | Listener | Which senders may ingest, and what node label their entries carry |
| `tcp` sink, `http` sink | Listener | Which clients may read the stream (and, on `http`, the status endpoint) |
| `tcp_chain` sink, `http_chain` sink | Dialer | `mtls`: which server identity to accept, beyond hostname verification. `scram`: which user to log in as |

### Identity

Under `mtls` the identity is one string pulled from the peer's verified leaf
certificate; under `scram` it is the username. The handshake has already
checked the chain, signature, and validity window, so this is pure field
selection.

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

`node_binding` applies only to the chain sources, and it overrides `trust_node`.

| Value | Connection label | Per-entry `node` field |
|-------|------------------|------------------------|
| `none` | `trust_node` governs | `trust_node` governs |
| `assert` | Must equal the identity; a mismatch or an omission is rejected | `trust_node` governs |
| `force` | Ignored; the identity is used | Overwritten with the identity |

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

- `type` `mtls` or `scram` without `tls.enabled` (proxy mode aside), or on a dialer with
  `tls.insecure_skip_verify`: an identity read from an unverified chain is a
  claim, and an unverified server could relay a login
- `type = "mtls"` on a listener without `tls.client_auth`
- a block naming peers or credentials (`allow`, `allow_patterns`,
  `credentials_file`, `token_lifetime_ms`, `username`, `password_file`,
  `trusted_proxies`) whose
  `type` is `none` or unset: auth was intended and the type forgotten
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

## Startup Warnings

Some settings work but are usually mistakes. Each plugin reports them at WARN
when it is constructed, so startup and every reload repeat them:

- a certificate in `cert_file`, `ca_file` or `client_ca_file` that has expired,
  is not yet valid, or expires within 30 days
- `insecure_skip_verify` on a dialer
- an `allow_patterns` entry not anchored at both ends of every alternative
  (`^a|b$` admits `a…` and `…b`)
- a `key_file`, `credentials_file` or `password_file` every local user can read
  (once per path per process)

## Enabling mTLS

### 1. Generate a CA and certificates

LogWisp does not generate certificates; use `openssl`, `cfssl`, `step-cli`, or
your existing PKI.

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
not standard SASL: viewers use the [`logwisp auth`](cli.md#logwisp-auth) CLI or,
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
token printed by `logwisp auth token` is not pinned.

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

Logins are throttled per remote socket address; forwarded headers are never
read. Each exchange takes a token from a bucket of 10 that refills at one per
second, and a successful login gives it back, so only failed or abandoned
attempts drain it. At most 4 exchanges per address may be unfinished: an HTTP
challenge never answered holds its slot for up to 30 s, a TCP connection that
ends mid-exchange frees it at once. A refused start answers `too many attempts`
(HTTP `429`) and counts `auth_throttled`; the table holds 65,536 addresses and
refuses new ones when full. Separately, at most 4,096 exchanges may be in flight
per listener; beyond that, or while the plugin stops, a login gets `busy` (HTTP
`503`) and counts `auth_busy`. Peers behind one NAT or one passthrough proxy
share a bucket: there, one client can exhaust every other client's logins.

### Credentials file

```toml
# logwisp SCRAM verifiers, written by `logwisp auth add-user`. Keep it private.
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

Write it with [`logwisp auth add-user`](cli.md#logwisp-auth) rather than by
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
- **Password rotation.** `logwisp auth add-user -generate` with the user's
  `-password-file` replaces verifier and password together. `SIGHUP` the
  listener, deploy the password file, `SIGHUP` the dialer. Logins fail in
  between and the dialer retries under backoff, holding its current entry or
  batch while its input queue fills. To avoid the gap, add a second user, move
  the dialer to it, then remove the first; under `node_binding = "force"` the
  node label follows the username.
- **Revocation.** `logwisp auth remove-user`, then `SIGHUP`. The reload drops
  every connection and revokes every token; other dialers log in again on
  their own.

### Limits

- TLS must terminate at LogWisp, except on an `http` sink in proxy mode. Behind
  any other terminating proxy or load balancer every login fails by design;
  pass TLS through instead (TCP or SNI routing). All clients then share the
  proxy's address, and so one throttling budget.
- One process per HTTP address. Handshake state and the token key live in one
  instance, so behind a balancer the proof or the token can reach an instance
  that never saw the login.
- Browsers log in only to an `http` sink in proxy mode, below; elsewhere use
  `mtls` for browsers.
- `nc` and `openssl s_client` cannot read a `scram` `tcp` sink; use
  `logwisp auth stream`.

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
  proxy; throttling, sessions and logs use it.
- **Unbound logins.** The browser cannot see a certificate LogWisp could bind
  to, so proofs are unbound and a party on the hop between proxy and LogWisp
  could relay a login. Keep that hop on loopback or a trusted network, or
  enable `tls` on the sink; a plaintext hop to a proxy off this host is
  warned about at startup. `identity` cannot be combined with proxy mode.
- **Sessions.** The page asks for a cookie: `logwisp_session`, `HttpOnly`,
  `Secure`, `SameSite=Strict`, `Max-Age` the token lifetime, and no `Path`, so
  it scopes itself to the mount (`/logs` above). Stream and status accept it or
  a bearer token, so `new EventSource("stream")` works on any page of the site
  and `logwisp auth token -unbound` keeps working. `POST /auth` with
  `{"logout": true}` clears the cookie and revokes the token until it expires.
  `/auth` takes only `application/json`, which a cross-origin page cannot send
  without a preflight.
- **Pages.** Under `/auth/` the sink serves `scram.js` always, and with
  `login_page` / `viewer_page` the login page and a minimal live viewer with
  their script and style, under `default-src 'none'; script-src 'self';
  connect-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors
  'none'; base-uri 'none'`. A site with its own CSP can copy `scram.js` from
  `internal/sink/http/web/` into its bundle: one dependency-free ES module
  exporting `login(base, username, password, {onProgress})` and
  `logout(base)`, where `base` is the mount URL ending in `/`. It needs a
  secure context for WebCrypto and takes about 2 s of Argon2 per login on a
  desktop.

`test/scram-proxy-test.sh --auto` logs in from headless Chromium through such a
proxy.

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
another certificate, and with `identity` each user is tied to its own
certificate.

Under either method the chain `node` label can be bound to the identity, so a
compromised edge cannot attribute its entries to another host, and the `http`
sink's stream and status endpoints stop being open to anyone who can reach the
port.

**Revocation** is the allow-list or the credentials file, not a CRL. Remove the
identity or user and send `SIGHUP`: the reload rebuilds every pipeline, so the
change takes effect on the next connection and existing ones are dropped by the
rebuild. No network call on the handshake path, and no window between revocation
and the next CRL publication. See
[mtls-auth-plan.md](mtls-auth-plan.md#not-implemented) for what CRL support
would add.

## Surfaces Without Access Control

An `auth` block (`mtls` or `scram`) closes each of these. Without one, bind them
to a trusted interface or front them with an authenticating proxy.

| Surface | Exposure when `auth.type = "none"` |
|---------|-----------------------------------|
| `http` sink `stream_path` | Full log stream, with `Access-Control-Allow-Origin: *`, so any browser origin can read it (the header is omitted once an auth policy is set) |
| `http` sink `status_path` | Host, port, TLS flag, uptime, client counts, throughput counters |
| `tcp` sink | Full log stream to any client that connects |
| `tcp_chain` / `http_chain` source | Ingest from any peer that can connect (with `client_auth`, any the CA vouches for), under any node label it claims |

`max_connections` bounds concurrency on all of them but does not distinguish
callers.

Both methods require TLS, so there is no way to authenticate a plaintext
listener; `mtls` also requires `client_auth`.

## Operational Guidance

**Certificates and secrets**

- Use a dedicated CA for LogWisp so its trust decisions stay independent.
- Keep leaf lifetimes short (90–825 days) and automate renewal.
- Key, credentials and password files should be `0600` and owned by the service
  account; a world-readable one is reported at startup. `logwisp auth` creates
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
