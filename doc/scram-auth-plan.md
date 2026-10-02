# Password Authentication (Argon2id-SCRAM)

**Status:** implemented, in three batches: `lixenwraith/auth` gained SCRAM
channel binding and the mTLS layer was hardened (see
[mTLS Hardening](#mtls-hardening)); then the SCRAM integration described here,
on the `auth` release that carries channel binding; then browser logins behind
a TLS-terminating proxy. Operator documentation lives in
[Security](security.md#password-authentication-scram) and
[`lw auth`](cli.md#logwisp-auth).

**Scope:** optional username/password authentication on every network plugin,
next to the existing certificate method, without weakening what mTLS gives.

## Goals

- Password authentication for chain links (`tcp_chain`, `http_chain`: sources
  verify, sinks present) and for viewers of the `tcp` and `http` sinks.
- No password or password-equivalent on the wire, no KDF work on listeners, and
  no credential relay through a TLS-terminating MITM.
- Default stays `auth.type = "none"`; existing configurations are unaffected.
- Config in TOML, credential management and viewer clients in a `lw auth`
  CLI.

## Non-Goals

- Standard SASL SCRAM-SHA-256 interoperability. The `auth` exchange is
  logwisp-to-logwisp (or logwisp CLI) only.
- Browser viewers of a logwisp that terminates TLS itself: a browser cannot see
  the server certificate, so its proof cannot be channel-bound. Browsers log in
  through [proxy mode](#browser-viewers-behind-a-tls-terminating-proxy), or use
  mTLS.
- Multiple backends behind a non-sticky L7 balancer: handshake state and the
  token key live in one process.

## Mechanism

`lixenwraith/auth` Argon2id-SCRAM. The listener stores a verifier per user:
`StoredKey = SHA-256(HMAC(K, "Client Key"))`, `ServerKey = HMAC(K, "Server Key")`,
`K = Argon2id(password, salt)`. The Argon2id digest itself is never stored: it is
the salted password, from which both keys derive. Verifying a proof is HMAC only;
Argon2 runs on the dialer or CLI (t=3, 64 MiB, 4 threads, the `auth` defaults).
The dialer refuses a challenge below that cost, so a rogue server cannot ask for
a cheaply guessable proof, and trusts the link only after the server's final
signature proves it holds the user's `ServerKey`.

**Channel binding.** Both peers pass `auth.WithChannelBinding(SHA-256(server leaf
DER))` at the proof step. The server hashes its configured certificate; the
client hashes the certificate it saw. A relay presenting any other certificate,
even one the CA trusts, makes the server reject the proof, so it never obtains a
link or a token. A mismatch is indistinguishable from a wrong password on the
wire by design; the client also sends its hash as a diagnostic field, so the
listener logs "TLS interception or a terminating proxy" and counts it. TLS must
terminate at logwisp, except in [proxy mode](#browser-viewers-behind-a-tls-terminating-proxy).

**HTTP pinning.** HTTP auth takes two requests and every later request may use a
new pooled connection, so binding the exchange is not enough. Once the challenge
arrives the dialer pins the certificate that answered on its `VerifyConnection`:
the proof and every ingest request must present the same leaf, or the handshake
fails before anything is sent. The `http_chain` sink then clears token and pin
and logs in again, which also covers certificate rotation. A token handed to
curl by the CLI is unpinned.

## Configuration

```toml
# listener (tcp_chain/http_chain source, tcp/http sink)
[pipelines.plugin_sources.config.auth]
type              = "scram"
credentials_file  = "/etc/logwisp/users.toml"
token_lifetime_ms = 900000          # http sink and http_chain source only
node_binding      = "force"         # chain sources; binds to the username

# dialer (tcp_chain/http_chain sink)
[pipelines.plugin_sinks.config.auth]
type          = "scram"
username      = "edge-01"
password_file = "/etc/logwisp/edge-01.pass"
```

Validation at construction:

- `scram` requires TLS, except on an `http` sink in proxy mode; a dialer also
  forbids `insecure_skip_verify`.
- Listeners require `credentials_file` and reject `allow`/`allow_patterns` (the
  credentials file is the allow list), `username` and `password_file`. Use one
  file per listener when listeners admit different users.
- Dialers require `username` + `password_file` (1–1024 bytes after trimming one
  line break), and reject `credentials_file`, `token_lifetime_ms`, `allow*` and
  `identity` (server pinning stays an mTLS feature).
- `identity` on a listener requires `tls.client_auth` and **binds the certificate
  to the user**: the certificate's identity field must equal the SCRAM username,
  so a peer needs its own certificate and its own password (PostgreSQL's
  `clientcert=verify-full`). Without it the factors are independent: any
  CA-issued certificate plus any valid password (`clientcert=verify-ca`).
- `token_lifetime_ms` only on HTTP listeners; default 15 minutes.
- `/auth` and every path under it are reserved.
- `mtls` rejects the four SCRAM keys. A block that names peers or credentials
  with `type = "none"` is refused: the type was forgotten, not the block.

**Credentials file** (TOML, written by the CLI, mode 0600):

```toml
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

`decoy_key` keeps unknown-user challenges stable across restarts and edits, so
a single probe cannot tell a real user from an unknown one (a real user's salt
changes when it is added, rotated or removed). It is created by the first `add-user` and
preserved by every rewrite. An empty user set, a duplicate user, a missing or
short `decoy_key`, an unknown key, or users differing in KDF profile or salt
length are configuration errors. The file is read at construction; the SCRAM
server starts in the plugin's `Start` and stops in `Stop`, so a rejected reload
leaks nothing.

## Wire Protocol

`chain.Hello` gains `scram` (raw JSON, decoded by `authz`); the protocol version
stays 1 because the field is additive. Every message after the hello is one
`authStep`: `error`, `challenge`, `proof` (+ `binding`), `final` (+ `token`,
`expires_in` on HTTP). Pre-auth lines and `/auth` bodies are capped at 4 KiB.

**TCP** (`tcp_chain`, `tcp` sink): hello carrying the client-first message,
challenge, proof, final — all under one deadline (`hello_timeout_ms` on the
`tcp_chain` source, 10 s on the `tcp` sink and every dialer, with the dialer's
context able to cut it short). The final is written only after every admission
check (certificate binding, node binding); a later refusal is an `error` line
instead. The stream then continues on the same buffered reader. A listener
without SCRAM that reads a hello (the `tcp_chain` source) answers one carrying
credentials with `error: authentication not enabled`; an old binary stays
silent, and the dialer gives up after its deadline with "no challenge within
10s".

**HTTP** (`http_chain` source, `http` sink): `POST /auth`, outside the auth
middleware, with its own 10 s read/write deadline. It answers `404` unless the
policy is `scram`.

| Step | Request body | Success | Failure |
|------|--------------|---------|---------|
| 1 | hello | `200` challenge | `429` throttled, `503` busy, `400` malformed, `413` oversized |
| 2 | proof | `200` final, token, expires_in | `401 {"error":"authentication failed"}`, `503` if the server stopped |

Protected endpoints take `Authorization: Bearer <token>`: missing or invalid is
`401` with `WWW-Authenticate: Bearer realm="logwisp"`, a certificate-binding miss
is `403`. Tokens are HS256 JWTs from `auth.NewJWT` (issuer `logwisp`, no leeway)
with a random per-instance key, so every reload revokes them. An SSE stream is
checked at connect and outlives its token; a reload ends it.

**Dialer outcomes** (`http_chain` sink): every `/auth` failure is transient (the
batch is held under backoff); `404`/`405` from `/auth` reads "no auth endpoint
at <url> (older logwisp, or not a scram listener)"; an ingest `401` clears the
token and is retried (tokens are renewed ahead of expiry, so this follows a
listener reload); `403` drops
the batch; a pin mismatch clears token and pin. Refusals are logged at WARN on
every attempt, paced by the backoff (`Chain connect refused` on `tcp_chain`,
`Chain batch delivery failed` on `http_chain`), and failed logins are counted
in `auth_failures` / `last_auth_error`.

## Throttling

Per remote IP (the socket address; in proxy mode the forwarded client, an IPv6
one per /64), on handshake
starts: a token bucket (burst 10, 1/s) refunded on success, and at most 4
unfinished exchanges. An unanswered HTTP challenge holds its slot for the
`auth` handshake timeout (30 s); abandoned TCP exchanges release their slot,
and their entry in the `auth` handshake table, immediately. The address table
holds 65,536 entries, drops one idle for a minute once its challenges have
expired, and fails closed when full; the SCRAM server itself caps in-flight
handshakes at 4,096 (`busy`).

Counters: `auth_allowed` counts logins; `auth_rejected` every refusal — failed
proofs, malformed requests, missing credentials and, on HTTP, refused tokens;
`auth_binding_mismatch` is the subset of failed proofs whose client saw another
certificate. `auth_throttled` and `auth_busy` count starts refused before a
challenge and are not in `auth_rejected`.

## The `authz` Seam

Listeners never call `Authorize` directly any more; one entry point per transport
decides, and `Authorize` itself refuses under `scram` so a missed call site fails
closed.

- `Admit(conn, cs, wantHello, timeout)` returns an admission (identity, hello,
  reader) whose `Accept` or `Reject` writes the final message.
- `AuthorizeRequest(r)` covers mTLS certificates and bearer tokens, returning
  the refusal status for `Refuse`; `ServeAuth(w, r)` serves `/auth`.
- Dialers: `Greet(ctx, conn, node)` writes the hello and, under SCRAM, runs the
  TCP exchange. Over HTTP `Prepare` logs in when no token is held and sets the
  bearer header, `Invalidate` drops the token after a `401` or a pin mismatch,
  `Token` is the login itself (behind `Prepare`, and for the CLI), and
  `VerifyConnection` pins.
- `Start`/`Close` bracket the SCRAM server and are nil-safe like everything else.

## CLI

```
lw auth add-user    -credentials F -user U [-password-file P] [-generate]
lw auth remove-user -credentials F -user U
lw auth token  -url https://host:port[/path] -user U -password-file P [-unbound] [TLS flags]
lw auth stream -addr host:port        -user U -password-file P [TLS flags]
```

- `add-user` takes the password from `-password-file` when it exists (at least
  8 bytes); a new user without one gets a generated 130-bit password, written to
  that file (0600) or printed once. Rotating an existing user needs the file or
  `-generate`, so a mistyped path cannot replace a password. The file's KDF
  profile and decoy key are reused, the result is validated with the daemon's
  own parser, and the rewrite (temp file beside the file or a symlink's target,
  rename) keeps the existing mode and owner, or fails.
- `remove-user` refuses to remove the last user.
- Both print that changes apply on `SIGHUP`: `auto_reload` does not watch the
  credentials file.
- `token` prints a bearer token for curl (`-H @<(...)` keeps it out of argv);
  `stream` authenticates to a `tcp` sink and copies the stream to stdout until
  interrupted. `-url` takes a path only with `-unbound`, and redirects are not
  followed.
- TLS flags: `-ca-file`, `-server-name`, `-cert-file`, `-key-file`. There is no
  insecure flag.
- Exit status: 0 success, 1 failure, 2 usage error.

## Rollout and Rotation

- Turning SCRAM on is per listener and cuts off unconfigured dialers. To migrate
  without a gap, upgrade binaries, add a second SCRAM listener, move dialers,
  then remove the old listener.
- Password rotation: `add-user -generate`, `SIGHUP` the listener, deploy the new
  password file, `SIGHUP` the dialer. The dialer retries under backoff in
  between.
- Revocation: `remove-user`, `SIGHUP`. All tokens die with the reload.

## Browser Viewers Behind a TLS-Terminating Proxy

The deployer serves the log stream inside a website whose TLS ends at its
reverse proxy; LogWisp holds no private key and listens on a trusted hop.
Viewers log in from a browser with the client LogWisp ships, and the password
reaches neither the proxy nor LogWisp. Operator view and example:
[Security](security.md#browsers-behind-a-tls-terminating-proxy).

**Trust model.** `auth.trusted_proxies` (addresses or CIDRs) switches the `http`
sink into proxy mode; it is refused on every other plugin and with `identity`.
- Only listed peers may connect: `403` on every path, the pages included.
- `X-Forwarded-Proto` must be `https` on every hop, so a site served in
  plaintext by mistake fails closed instead of exposing sessions.
- The client is the rightmost `X-Forwarded-For` hop that is not a proxy (hops to
  its left are the client's own claims), or the leftmost when every hop is
  inside a proxy range; throttling (an IPv6 client per /64, as one host holds
  it whole), sessions and logs use it. Outside proxy mode forwarded headers
  stay ignored.
- SCRAM runs unbound: a browser cannot read the site's certificate, and LogWisp
  sees none. The proof and the session ride on the site's TLS; a party on the
  proxy-to-LogWisp hop could relay a login, hence the address restriction and a
  startup warning for a plaintext hop to a proxy off this host. `tls` may stay
  off. Outside proxy mode nothing changes: proofs stay bound, and a bound proof
  in proxy mode fails with a hint naming `-unbound`.

**Session.** The proof step may ask for a cookie (`"session": "cookie"`, proxy
mode only). The answer sets `logwisp_session` (`HttpOnly; Secure;
SameSite=Strict; Max-Age=<lifetime>`) and carries no token in the body. It has
no `Path`: RFC 6265 defaults it to the directory of `POST <mount>/auth`, which
is the mount behind any proxy prefix. Stream and status accept the cookie or
`Authorization: Bearer`; another `Authorization` scheme, such as the site's own
Basic auth, leaves the cookie in charge. Logout is `{"logout": true}` on `POST /auth` itself,
because a clearing cookie set from `/auth/logout` would default to another path
and miss the login cookie. It clears the cookie and revokes a valid token until
it expires (a set of at most 65,536 hashes, gone on reload like every token). An
open stream outlives its token; a reconnect after expiry gets `401`. `/auth`
takes only `application/json`, which a cross-origin page cannot send without a
preflight nobody answers.

**Endpoints.** `/auth` and every path under it are reserved; every URL in the
pages is relative, so a proxy prefix works unchanged.

| Path | Purpose |
|------|---------|
| `POST /auth` | SCRAM hello, proof, or logout; unbound in proxy mode |
| `GET /auth/scram.js` | the client library, always in proxy mode |
| `GET /auth/login`, `login.js`, `style.css` | login page (`login_page`) |
| `GET /auth/view`, `view.js` | minimal live viewer (`viewer_page`, needs `login_page`) |

Files carry `default-src 'none'; script-src 'self'; connect-src 'self';
style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
`nosniff` and `no-referrer`; nothing is inline. The viewer learns a custom
`status_path` from a meta tag the sink fills in, renders entries as text, and
sends a signed-out visitor to `login?next=view`; the login page follows `next`
only within its origin. The `proxy_tls` capability satisfies the pipeline's
"auth needs TLS" check.

**Client library.** `internal/sink/http/web/scram.js`, embedded with `go:embed`,
is one dependency-free ES module, so a site with its own CSP can copy it into
its bundle. It exports `login(base, username, password, {onProgress})` and
`logout(base)`. BLAKE2b and Argon2id are plain JS (no WebAssembly, which would
need `'wasm-unsafe-eval'`), yielding to the page every 50 ms; SHA-256 and HMAC
come from WebCrypto, so it needs a secure context. It checks the challenge as
the Go client does (nonce, salt, cost limits and the dialer's Argon2 floor),
refuses redirects, and reports success only after verifying the server's
signature. A 64 MiB login takes about 2 s on a desktop. The wire protocol above
is the contract: a site may implement its own client.

**CLI.** `lw auth token -unbound` logs in through the proxy, still pinning
its certificate across the two requests; only then may `-url` carry the mount
path.

## Verification

Go tests, one per rule: binding (match, mismatch, one-sided, length) in `auth`.
In `authz`: the validation table (each row valid but for its rule, the error
naming it) and credentials file validation; the TCP exchange over `net.Pipe`
(admission with the first entry in the same read, wrong password
indistinguishable from an unknown user, another certificate refused and counted,
hello and policy disagreeing either way, a dialer cut short by its context, an
abandoned exchange freeing its handshake and limiter slots, a refusal after the
exchange sent as a reason rather than a final, certificate-to-user binding for
logins and tokens); only failed attempts throttled, the limiter bounds
(reservation under concurrency, the sweep of abandoned challenges); pre-auth
input capped at 4 KiB; the decoy salt stable across restarts; a dialer refusing
a challenge below its Argon2 floor; the HTTP exchange on a TLS test server
(token accepted, garbage and foreign tokens `401`, forged final yields no token,
a different certificate after the challenge refused before the proof is sent,
renewal ahead of expiry); `Authorize` failing closed under SCRAM; password
trimming; refused hellos freeing their slot; unbound logins pinned too. Proxy
mode: trusted peers, https and the client hop; throttling on the forwarded
client and IPv6 /64; an unbound browser login with the cookie's attributes, the
cookie opening endpoints (beside Basic auth) until logout revokes it, cookie
sessions refused elsewhere; only unbound logins behind a proxy; `/auth` taking
only JSON. In the `http` sink, every SSE line break framed as data.
In the plugins: `/auth` outside the `http` sink's gate, the pages served with
their types and CSP, direct peers refused, pages only in proxy mode, and the
`http_chain` sink logging in again after a `401` and delivering once. In the
CLI: private files with a matching verifier, no password replaced without a
source, mode, decoy key and symlink kept across rewrites, an empty file filled,
last-user refusal. Under node, `scram.js` against the RFC 9106 vector, Go's
`argon2.IDKey`, and `auth`'s known-answer proof.

`test/scram-chain-test.sh --auto` (ports 15821-15825): a relay with SCRAM on all
four listener types plus one `client_auth` + SCRAM port; authorized edges over
both chain transports; node labels forced to usernames; wrong password, unknown
user and no-auth edges deliver nothing; a `tcp` sink viewer through `lw auth
stream` held past the exchange deadline; a raw TLS client without a hello gets
nothing; the `http` sink through `lw auth token` and curl; missing and bad
tokens get `401`; `remove-user` + `SIGHUP` revokes token and login; throttling
last. `test/scram-proxy-test.sh --auto` (ports 15831-15832): a Go reverse proxy
ending TLS in front of a plaintext `http` sink mounted at `/logs/`; headless
Chromium sent to the login page, refused a wrong password, streaming events
after login, with the cookie scoped to `/logs` and hidden from scripts, cleared
by sign-out, and no CSP violations; `token -unbound` and curl through the
proxy; direct peers and plaintext-forwarded requests `403`. The existing
scripts keep passing.

## Not Implemented

1. **PROXY protocol behind TLS passthrough.** Every client then shares the
   proxy's address, and so one throttling budget that a single client can
   exhaust. Accepting PROXY v2 from listed proxies would restore per-client
   throttling on the TCP listeners and on HTTP listeners outside proxy mode.

## mTLS Hardening

Shipped with this plan, independent of SCRAM:

- The `http_chain` sink no longer follows redirects. Go's client resends the
  body on a 307/308, including from `https` to plaintext `http`.
- Its response drain is bounded (64 KiB).
- The `tcp` sink tracks connections from accept, so `Stop` and reloads no longer
  wait out the 10 s handshake timeout of a silent peer.
- Unknown keys in any plugin's config, at any depth, fail construction: a typo
  such as `[...tls] enabeld = true` used to switch protection off silently. The
  configuration file itself is checked the same way, so a misspelled table path
  above a plugin's config fails too.
- Startup and every reload warn about certificates that expired, are not yet
  valid, or expire within 30 days; about `insecure_skip_verify`; about
  `allow_patterns` that are not anchored at both ends of every alternative; and,
  once per path, about key, credentials and password files every local user can
  read.
- An `http` sink with an auth policy no longer sends
  `Access-Control-Allow-Origin: *`.
