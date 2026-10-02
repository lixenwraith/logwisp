# Password Authentication (Argon2id-SCRAM)

**Status:** planned. Ships in two batches:

1. **Done:** `lixenwraith/auth` gained SCRAM channel binding, and the mTLS layer
   was hardened (see [mTLS Hardening](#mtls-hardening)).
2. **Next:** the SCRAM integration described here, pinned to the tagged `auth`
   release that carries channel binding.

**Scope:** optional username/password authentication on every network plugin,
next to the existing certificate method, without weakening what mTLS gives.

## Goals

- Password authentication for chain links (`tcp_chain`, `http_chain`: sources
  verify, sinks present) and for viewers of the `tcp` and `http` sinks.
- No password or password-equivalent on the wire, no KDF work on listeners, and
  no credential relay through a TLS-terminating MITM.
- Default stays `auth.type = "none"`; existing configurations are unaffected.
- Config in TOML, credential management and viewer clients in a `logwisp auth`
  CLI.

## Non-Goals

- Standard SASL SCRAM-SHA-256 interoperability. The `auth` exchange is
  logwisp-to-logwisp (or logwisp CLI) only.
- Browser `EventSource` viewers under SCRAM: they cannot set `Authorization` or
  run Argon2. mTLS remains the browser path.
- Multiple backends behind a non-sticky L7 balancer: handshake state and the
  token key live in one process.

## Mechanism

`lixenwraith/auth` Argon2id-SCRAM. The listener stores a verifier per user:
`StoredKey = SHA-256(HMAC(K, "Client Key"))`, `ServerKey = HMAC(K, "Server Key")`,
`K = Argon2id(password, salt)`. The Argon2id digest itself is never stored: it is
the salted password, from which both keys derive. Verifying a proof is HMAC only;
Argon2 runs on the dialer or CLI (64 MiB, t=3, the `auth` defaults).

**Channel binding.** Both peers pass `auth.WithChannelBinding(SHA-256(server leaf
DER))` at the proof step. The server hashes its configured certificate; the
client hashes the certificate it saw. A relay presenting any other certificate,
even one the CA trusts, makes the server reject the proof, so it never obtains a
link or a token. A mismatch is indistinguishable from a wrong password by design;
the client also sends its hash as a diagnostic field so the listener can log
"TLS interception or terminating proxy" and count it. TLS must terminate at
logwisp.

**HTTP pinning.** HTTP auth takes two requests and every later request may use a
new pooled connection, so binding the exchange is not enough. After step 1 the
dialer pins the bound hash on its `VerifyConnection`: step 2 and every ingest
request must present the same leaf. A mismatch clears token and pin and
re-authenticates, which also covers certificate rotation. A token handed to curl
by the CLI is unpinned.

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

- `scram` requires TLS; a dialer also forbids `insecure_skip_verify`.
- Listeners require `credentials_file` and reject `allow`/`allow_patterns`: the
  credentials file is the allow list. Use one file per listener when listeners
  admit different users.
- Dialers require `username` + `password_file`, and reject `credentials_file`,
  `allow*` and `identity` (server pinning stays an mTLS feature).
- `identity` on a listener requires `tls.client_auth` and **binds the certificate
  to the user**: the certificate's identity field must equal the SCRAM username,
  so a peer needs its own certificate and its own password (PostgreSQL's
  `clientcert=verify-full`). Without it the factors are independent: any
  CA-issued certificate plus any valid password (`clientcert=verify-ca`).
- `token_lifetime_ms` only on HTTP listeners; default 15 minutes.
- `/auth` is reserved; no configured path may equal it.

**Credentials file** (TOML, written by the CLI, mode 0600):

```toml
decoy_key = "<base64, 32 random bytes>"
[[users]]
username = "edge-01"
salt = "<base64>"
argon_time = 3
argon_memory = 65536
argon_threads = 4
stored_key = "<base64>"
server_key = "<base64>"
```

`decoy_key` keeps unknown-user challenges stable across restarts and edits, so
probing usernames reveals nothing. It is created by the first `add-user` and
preserved by every rewrite. An empty user set, a duplicate user, a missing
`decoy_key` or mixed KDF profiles are configuration errors. The file is read at
construction; the SCRAM server starts in the plugin's `Start` and stops in `Stop`,
so a rejected reload leaks nothing.

## Wire Protocol

`chain.Hello` gains `scram` (raw JSON, decoded by `authz`); the protocol version
stays 1 because the field is additive. Every message after the hello is one
`authStep`: `error`, `challenge`, `proof` (+ `binding`), `final` (+ `token`,
`expires_in` on HTTP). Pre-auth lines are capped at 4 KiB.

**TCP** (`tcp_chain`, `tcp` sink): hello carrying the client-first message,
challenge, proof, final — all under one deadline (`hello_timeout_ms` on the
`tcp_chain` source, 10 s on the `tcp` sink and every dialer, with the dialer's
context able to cut it short). The final is written only after every admission
check (certificate binding, node binding); the stream then continues on the same
buffered reader. A source without SCRAM answers a hello carrying credentials with
`error: authentication not enabled`; only an old binary stays silent, and the
dialer's deadline covers that.

**HTTP** (`http_chain` source, `http` sink): `POST /auth`, outside the auth
middleware, with its own 10 s read/write deadline and a 4 KiB body limit.

| Step | Request body | Success | Failure |
|------|--------------|---------|---------|
| 1 | hello | `200` challenge | `429` throttled, `503` handshake table full, `400` malformed |
| 2 | proof | `200` final, token, expires_in | `401 {"error":"authentication failed"}` |

Protected endpoints take `Authorization: Bearer <token>`: missing or invalid is
`401` with `WWW-Authenticate: Bearer realm="logwisp"`, a certificate-binding miss
is `403`. Tokens are HS256 JWTs from `auth.NewJWT` with a random per-instance key,
so every reload revokes them. An SSE stream is checked at connect and outlives its
token; a reload ends it.

**Dialer outcomes** (`http_chain` sink): every `/auth` failure is transient (the
batch is held under backoff); `404`/`405` from `/auth` logs "no auth endpoint:
older logwisp or auth.type is not scram"; an ingest `401` clears the token and is
retried; `403` drops the batch; a pin mismatch clears token and pin. Rejections
are logged at WARN once per change of state and counted in `auth_failures` /
`last_auth_error`.

## Throttling

Per remote IP (the socket address, never a forwarded header), on handshake
starts: a token bucket (burst 10, 1/s) refunded on success, and at most 4
unfinished exchanges. The table is bounded and fails closed when full. Abandoned
TCP exchanges release their slot in the `auth` handshake table immediately.
Counters: `auth_allowed` and `auth_rejected` once per exchange outcome;
`auth_throttled`, `auth_busy` and `auth_binding_mismatch` separately.

## The `authz` Seam

Listeners never call `Authorize` directly any more; one entry point per transport
decides, and `Authorize` itself refuses under `scram` so a missed call site fails
closed.

- `Admit(conn, cs, wantHello, timeout)` returns an admission (identity, hello,
  reader) whose `Accept` or `Reject` writes the final message.
- `AuthorizeRequest(r)` covers mTLS certificates and bearer tokens;
  `ServeAuth(w, r)` serves `/auth`.
- Dialers: `Greet(ctx, conn, node)` writes the hello (plain or SCRAM);
  `Authenticate`, `SetAuthorization`, `ClearToken` and `VerifyConnection` serve
  HTTP.
- `Start`/`Close` bracket the SCRAM server and are nil-safe like everything else.

## CLI

```
logwisp auth add-user    -credentials F -user U [-password-file P] [-generate]
logwisp auth remove-user -credentials F -user U
logwisp auth token  -url https://host:port -user U -password-file P [TLS flags]
logwisp auth stream -addr host:port        -user U -password-file P [TLS flags]
```

- `add-user` takes the password from `-password-file` when it exists; a new user
  without one gets a generated 130-bit password, written to that file (0600) or
  printed once. Rotating an existing user needs the file or `-generate`, so a
  mistyped path cannot replace a password. The file's KDF profile and decoy key
  are reused, the result is validated with the daemon's own loader, and the
  rewrite (temp file in the same directory, rename) keeps the existing mode and
  owner.
- `remove-user` refuses to remove the last user.
- Both print that changes apply on `SIGHUP`: `auto_reload` does not watch the
  credentials file.
- `token` prints a bearer token for curl (`-H @<(...)` keeps it out of argv);
  `stream` authenticates to a `tcp` sink and copies the stream to stdout.
- TLS flags: `-ca-file`, `-server-name`, `-cert-file`, `-key-file`. There is no
  insecure flag.

## Rollout and Rotation

- Turning SCRAM on is per listener and cuts off unconfigured dialers. To migrate
  without a gap, upgrade binaries, add a second SCRAM listener, move dialers,
  then remove the old listener.
- Password rotation: `add-user -generate`, `SIGHUP` the listener, deploy the new
  password file, `SIGHUP` the dialer. The dialer retries under backoff in
  between.
- Revocation: `remove-user`, `SIGHUP`. All tokens die with the reload.

## Verification

Go tests, one per rule: binding (match, mismatch, one-sided, length) in `auth`;
in `authz` the validation table, credential loading, decoy stability across
edits, TCP exchange over `net.Pipe` (success, wrong password equals unknown
user, binding mismatch, missing hello, silent peer within the deadline,
abandoned exchange frees its slot, final and first entry in one write, assert
mismatch gets an error rather than a final), HTTP exchange on a TLS test server
(token accepted, garbage and foreign tokens `401`, forged final yields no token,
a different certificate after step 1 refused before the body is sent), the
limiter bound; `http_chain` sink re-authentication and outcome table; CLI
add/remove/rotate, mode preservation, last-user refusal, password trimming.

`test/scram-chain-test.sh --auto` (ports 15821-15825): a relay with SCRAM on all
four listener types plus one `client_auth` + SCRAM port; authorized edges over
both chain transports; node labels forced to usernames; wrong password, unknown
user and no-auth edges deliver nothing; a `tcp` sink viewer through `logwisp auth
stream` held past the exchange deadline; a raw TLS client without a hello gets
nothing; the `http` sink through `logwisp auth token` and curl; missing and bad
tokens get `401`; `remove-user` + `SIGHUP` revokes token and login; throttling
last. The existing scripts keep passing.

## mTLS Hardening

Shipped with this plan, independent of SCRAM:

- The `http_chain` sink no longer follows redirects. Go's client resends the
  body on a 307/308, including from `https` to plaintext `http`.
- Its response drain is bounded (64 KiB).
- The `tcp` sink tracks connections from accept, so `Stop` and reloads no longer
  wait out the 10 s handshake timeout of a silent peer.
- Unknown keys in any plugin's config, at any depth, fail construction: a typo
  such as `[...tls] enabeld = true` used to switch protection off silently.
- Startup and every reload warn about certificates that expired, are not yet
  valid, or expire within 30 days; about `insecure_skip_verify`; about
  `allow_patterns` that are not anchored at both ends of every alternative; and,
  once per path, about key files every local user can read.
- An `http` sink with an auth policy no longer sends
  `Access-Control-Allow-Origin: *`.
