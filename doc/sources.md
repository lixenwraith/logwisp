# Input Sources

Sources produce `core.LogEntry` values for a pipeline. Every source is declared
as a `[[pipelines.plugin_sources]]` entry with an `id`, a `type`, and a
type-specific `config` table.

```toml
[[pipelines.plugin_sources]]
id   = "app_logs"
type = "file"
[pipelines.plugin_sources.config]
directory = "/var/log/myapp"
```

Registered types: `file`, `console`, `random`, `null`, `tcp_chain`,
`http_chain`.

Publication from any source is non-blocking. When a subscriber channel is full
the entry is dropped and counted in `dropped_entries`.

---

## file

Tails every file in a directory whose name matches a glob.

```toml
[[pipelines.plugin_sources]]
id   = "app_logs"
type = "file"
[pipelines.plugin_sources.config]
directory         = "/var/log/myapp"
pattern           = "*.log"
check_interval_ms = 100
raw               = false
from              = "end"
```

Options, each as type and default:

- `directory` (string, required): directory to scan; not recursive.
- `pattern` (string, `*`): glob over filenames; `*` and `?` only.
- `check_interval_ms` (int, `100`): directory rescan interval; minimum `10`.
- `raw` (bool, `false`): never parse a line: the whole line is the message.
- `from` (string, `end`): where a new watcher starts, `end` or `start` of the
  file.

**Behaviour**

- `check_interval_ms` governs how often the directory is rescanned for new or
  removed files. Tailing an already-open file polls on a **fixed 100 ms**
  interval that this option does not change.
- Each matched file gets its own watcher. Watchers for files that disappear are
  stopped and removed on the next scan.
- A new watcher seeks to end-of-file. Positions live in memory only, so a
  restart resumes from the current end of each file and content written while
  LogWisp was down is not read. `from = "start"` reads each file whole when its
  watcher is created instead — what a process writing beside LogWisp needs, at
  the cost of replaying a file already on disk at every restart.
- Rotation is detected from size decrease, modification-time reset, a position
  beyond end-of-file, or an inode change. An inode change where the new file is
  already larger than the recorded position is treated as an atomic save, not a
  rotation, and the position is preserved.
- A rotation that renames in place — what a size-capped writer does — puts the
  same inode back under a name `pattern` also matches. Its watcher resumes at
  the position the original reached, so `from = "start"` reads the tail an
  unfinished read left behind rather than the whole archive a second time.
- A line is parsed as JSON only when it is an object whose top-level keys are
  all drawn from `time`, `level`, `msg` and `fields` — the four an entry can
  carry. `time` is read as RFC3339Nano. Any other key, and any non-object line,
  is kept whole as text, because parsing it would drop the rest.
- A text line's level is its first whole word, in any case, naming one:
  `TRACE`; `DEBUG`, `DBG`; `INFO`, `INF`; `WARN`, `WARNING`; `ERROR`, `ERR`,
  `FATAL`. `warning: disk full` is WARN, `INFO retry after error` INFO. The
  console sink paints that word and the http sink's viewer filters on it.
- `raw = true` skips the JSON branch entirely. The line, plus its newline,
  becomes the message; `fields` stays empty, the time is the read time, and the
  level is inferred from the text as for any unparsed line. Paired with
  `format.type = "raw"` this is byte-exact transport for records LogWisp's
  envelope cannot hold — see [Formatters](formatters.md#raw).
- `Source` is set to the file's base name.

**Statistics**: per-watcher size, position, entries read, rotation count, and
last read time, plus `active_watchers`.

---

## console

Reads newline-delimited entries from standard input. It is the source of the
built-in `pipe` pipeline, and of every spec pipeline given no `--source`.

```toml
[[pipelines.plugin_sources]]
id   = "stdin"
type = "console"
[pipelines.plugin_sources.config]
buffer_size = 1000
```

Option, as type and default:

- `buffer_size` (int, `1000`): subscriber channel depth.

Lines:
- Each line is one entry, its terminator (`\n` or `\r\n`) removed; the
  formatter writes one back. An unterminated last line is kept.
- Blank lines are skipped.
- A line over 1 MiB continues in the next entry; no byte is lost.
- The level is inferred from the line text, and `Source` is set to `console`.

Delivery and lifetime:
- Nothing is dropped: the source waits for its pipeline, so a slow pipeline
  slows the reading of stdin.
- One reader serves the process. A reload's new source continues where the old
  one stopped; no line is read twice. Hence at most **one** console source in
  the whole configuration, checked at validation.
- At the end of input the source ends, and with it a pipeline whose sources
  have all ended; lw exits once every pipeline has
  ([CLI](cli.md#built-in-defaults)). Under a supervisor whose stdin is
  `/dev/null` that is at once.

---

## random

Synthetic entry generator for development, smoke tests, and sanitizer testing.

```toml
[[pipelines.plugin_sources]]
id   = "generator"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 500
jitter_ms   = 0
format      = "txt"
length      = 20
special     = false
```

Options, each as type and default:

- `interval_ms` (int, `500`): emission period.
- `jitter_ms` (int, `0`): symmetric jitter; must be non-negative, clamped to
  `interval_ms`.
- `format` (string, `txt`): `raw` (message only), `txt` (bracketed line) or
  `json` (JSON object as the message).
- `length` (int, `20`): message length in characters.
- `special` (bool, `false`): inject control and non-ASCII characters.

`special = true` is the intended way to exercise sanitizer policies: it inserts
control bytes and multi-byte Unicode into otherwise ordinary messages. Levels
are chosen at random from DEBUG, INFO, WARN, ERROR.

---

## null

Produces nothing. Useful as a placeholder so a sink-only pipeline satisfies the
"at least one source" requirement.

```toml
[[pipelines.plugin_sources]]
id   = "void"
type = "null"
```

No options.

---

## tcp_chain

Listens for persistent NDJSON streams from upstream LogWisp `tcp_chain` sinks.
See [Chaining](chaining.md) for the protocol.

```toml
[[pipelines.plugin_sources]]
id   = "ingest_tcp"
type = "tcp_chain"
[pipelines.plugin_sources.config]
host             = "0.0.0.0"
port             = 15801
buffer_size      = 1000
max_connections  = 0
read_timeout_ms  = 0
hello_timeout_ms = 10000
trust_node       = true

[pipelines.plugin_sources.config.tls]
enabled        = true
cert_file      = "/etc/logwisp/tls/server.crt"
key_file       = "/etc/logwisp/tls/server.key"
client_auth    = true
client_ca_file = "/etc/logwisp/tls/client-ca.crt"
min_version    = "1.3"

[pipelines.plugin_sources.config.auth]
type         = "mtls"
allow        = ["edge-01", "edge-02"]
node_binding = "force"
```

Options, each as type and default:

- `host` (string, `0.0.0.0`): bind address, IPv4 or IPv6 (`::`); the
  listener keeps to its family ([Networking](networking.md#address-family)).
- `port` (int, required): listen port, 1–65535.
- `buffer_size` (int, `1000`): subscriber channel depth.
- `max_connections` (int, `0`): concurrent connection cap; `0` = unlimited.
- `read_timeout_ms` (int, `0`): per-connection idle read deadline; `0` = none.
- `hello_timeout_ms` (int, `10000`): deadline for the hello preamble.
- `trust_node` (bool, `true`): `false` overrides the sender's node label with
  its remote address. `auth.node_binding` `assert` or `force` takes over the
  connection label; only `force` also overrides the per-entry labels; `none`
  leaves both to `trust_node`.
- `tls` (table): listener TLS; see [Security](security.md).
- `auth` (table): peer authentication (`mtls` or `scram`) and node binding;
  see [Security](security.md#the-auth-block).
- `acl` (table): `allow` and `deny`, addresses or CIDRs admitted and refused
  before TLS, `proxy_protocol` with `proxy_from` for the client a PROXY header
  names, and `max_connections_per_client`; see
  [Security](security.md#the-acl-block).

For passwords instead of certificates, the `auth` block takes `type = "scram"`
and a `credentials_file`, and `client_auth` becomes optional; see
[Password Authentication](security.md#password-authentication-scram).

**Behaviour**

- TLS handshakes run explicitly with a 10 s bound before the preamble is read,
  after the `max_connections` admission check.
- A connection is rejected if the first line is not a valid hello with a
  matching protocol version.
- Under `mtls` the certificate is checked before the hello is read, so an
  unauthorized peer never gets a preamble parsed on its behalf. Under `scram`
  the hello opens the login: challenge, proof and final follow on the same
  connection, the whole exchange within `hello_timeout_ms`, and the final is
  sent only once node binding agrees. A source without `scram` answers a hello
  offering credentials with `authentication not enabled`. A rejection is logged
  at WARN and counted in `rejected_conns`.
- The node label is then resolved: under `auth.node_binding` it comes from the
  peer's certificate identity or username, otherwise `trust_node` governs.
  `force` also overrides the `node` field on every individual entry; `assert`
  leaves per-entry labels to `trust_node`, so a relay can forward other nodes'
  entries while proving its own identity.
- Each accepted connection gets a session recording the remote address, node
  label, — under TLS — `tls` and `tls_peer_cn`, — under auth —
  `auth_method` and `auth_identity`, and behind a PROXY header the proxy as
  `peer_addr`.
- A malformed entry line increments `parse_errors` and is skipped; the
  connection survives. A line over 1 MiB is a protocol violation and terminates
  the connection.

**Statistics**: `active_connections`, `rejected_conns`, `parse_errors`,
`tls_handshake_errors`, `trust_node`, `auth`, `auth_allowed`, `auth_rejected`,
`node_binding`; under `scram` also `auth_users`, `auth_throttled`, `auth_busy`
and `auth_binding_mismatch`; with a non-empty `acl` block also `acl`,
`acl_denied`, `acl_limited` and `acl_proxy_headers`.

---

## http_chain

Accepts NDJSON batches POSTed by upstream LogWisp `http_chain` sinks.

```toml
[[pipelines.plugin_sources]]
id   = "ingest_http"
type = "http_chain"
[pipelines.plugin_sources.config]
host            = "0.0.0.0"
port            = 15802
ingest_path     = "/ingest"
buffer_size     = 1000
max_body_bytes  = 8388608
read_timeout_ms = 30000
trust_node      = true

[pipelines.plugin_sources.config.tls]
enabled        = true
cert_file      = "/etc/logwisp/tls/server.crt"
key_file       = "/etc/logwisp/tls/server.key"
client_auth    = true
client_ca_file = "/etc/logwisp/tls/client-ca.crt"

[pipelines.plugin_sources.config.auth]
type         = "mtls"
allow        = ["edge-01", "edge-02"]
node_binding = "force"
```

Options, each as type and default:

- `host` (string, `0.0.0.0`): bind address, IPv4 or IPv6 (`::`); the
  listener keeps to its family ([Networking](networking.md#address-family)).
- `port` (int, required): listen port, 1–65535.
- `ingest_path` (string, `/ingest`): endpoint path; must start with `/`, and
  `/auth` is reserved for the login.
- `buffer_size` (int, `1000`): subscriber channel depth.
- `max_body_bytes` (int, `8388608`): per-request body cap (8 MiB).
- `read_timeout_ms` (int, `30000`): full request read deadline.
- `trust_node` (bool, `true`): `false` overrides the sender's node label with
  its remote address. `auth.node_binding` `assert` or `force` takes over the
  connection label; only `force` also overrides the per-entry labels; `none`
  leaves both to `trust_node`.
- `tls` (table): listener TLS; see [Security](security.md).
- `auth` (table): peer authentication (`mtls` or `scram`) and node binding;
  see [Security](security.md#the-auth-block).
- `acl` (table): `allow` and `deny`, addresses or CIDRs admitted and refused
  before TLS, `proxy_protocol` with `proxy_from` for the client a PROXY header
  names, and the per-client `max_connections_per_client` and
  `requests_per_second_per_client`; see [Security](security.md#the-acl-block).

**Behaviour**

- Only `POST` to `ingest_path` and to `/auth` is routed; other methods get `405`
  with an `Allow` header, and other paths get `404`. `/auth` is the SCRAM login
  and answers `404` unless `auth.type = "scram"`.
- Authorization runs before the body is read, so an unauthorized sender does not
  get to stream `max_body_bytes` into the process. A missing, invalid or expired
  bearer token (`scram`) answers `401`, so the sender logs in again; a refused
  certificate, a certificate that does not match the token's user, and a
  node-binding failure answer `403`. Both are distinct from the `400` used for
  protocol errors, so a sender can tell "not allowed" from "malformed batch".
- A missing or mismatched `X-Logwisp-Protocol` header is rejected with `400`.
- Batch acceptance is atomic: entries are published only after the body reads
  cleanly end to end. A transfer error rejects the whole batch (`400`, or `413`
  when the body cap is hit) so the sender retries it. A malformed *line* inside
  an otherwise clean transfer is skipped and counted in `parse_errors`.
- Success is `204 No Content` with `X-Logwisp-Accepted` set to the number of
  entries ingested.
- Sessions are cached per remote host + node + authenticated identity, and
  recreated after idle expiry. Including the identity in the key means two peers
  sharing a remote address never share a session.

**Statistics**: `total_requests`, `rejected_requests`, `parse_errors`,
`cached_sessions`, `trust_node`, `auth`, `auth_allowed`, `auth_rejected`,
`node_binding`; under `scram` also `auth_users`, `auth_throttled`, `auth_busy`,
`auth_binding_mismatch` and `auth_token_lifetime_ms`; with a non-empty `acl`
block also `acl`, `acl_denied`, `acl_limited` and `acl_proxy_headers`.

---

## Source Statistics

Every source reports: `id`, `type`, `total_entries`, `dropped_entries`,
`start_time`, `last_entry_time`, and a type-specific `details` map. The DEBUG
status report spreads `details` into each plugin's line.
