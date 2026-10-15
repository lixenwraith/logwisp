# Input Sources

Sources produce `core.LogEntry` values for a pipeline. Every source is declared
as a `[[pipelines.plugin_sources]]` entry with an `id`, a `type`, and a
type-specific `config` table. Registered types: `file`, `console`, `random`,
`null`, `tcp_chain`, `http_chain`.

Publication is non-blocking for every source but `console`: a full subscriber
channel drops the entry and counts it in `dropped_entries`. That channel holds
`buffer_size` entries, or 1000 on a source without that option. The `console`
source waits instead (see [console](#console)).

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

- `directory` (string, required): directory to scan; not recursive. A leading
  `~/`, here as in every file or directory option, is the home directory; a
  relative path starts at lw's working directory.
- `pattern` (string, `*`): glob over filenames; `*` and `?` only.
- `check_interval_ms` (int, `100`): directory rescan interval; minimum `10`.
  An open file is polled every 100 ms whatever this is.
- `raw` (bool, `false`): never parse a line: the whole line is the message.
- `from` (string, `end`): where a new watcher starts, `end` or `start` of the
  file.

**Behaviour**

- Each matched file gets its own watcher, and its entries the file's base
  name as `Source`. Watchers for files that disappear are stopped and removed
  on the next scan.
- A missing directory is waited for: INFO `Waiting for directory`, then
  `Directory readable` once a scan reads it. A directory or file that cannot be
  read is retried at each scan or poll, with WARN `Cannot read directory` or
  `Cannot read file` when the failure starts or changes, not at each retry.
- The file lw's stdout or stderr is redirected to is never followed, with a
  warning: `lw > out.log` in the directory would read its own output back.
- A line longer than 1 MiB continues in the next entry, as on the console
  source; so does the rest of a line a poll reads while it is still being
  written.
- A new watcher seeks to end-of-file. Positions live in memory only, so a
  restart or a reload resumes from the current end of each file, and content
  written meanwhile is not read. `from = "start"` instead reads each file whole
  when its watcher is created, which a process writing beside LogWisp needs, at
  the cost of replaying files already on disk at every restart and reload.
- A file is known by its first 256 bytes, not its inode or size. While it
  starts as before, reading resumes after the line read last, found again
  where an edit moved it, or at the file's end where the edit deleted it, so a
  save from an editor, in place or by rename, replays nothing.
- A file that starts anew is a rotation (logrotate's `create` or
  `copytruncate`, a file emptied and written again) and is read from its
  start; an emptied file, or one cut within its first 256 bytes, waits for what
  is written next to say which. Each rotation also publishes an INFO entry
  `Log rotation detected (#N): the file starts anew` with the file's name as
  `Source`; it reaches every sink, so exclude it with a filter
  (`Log rotation detected`) where unwanted.
  - An edit within the first 256 bytes makes the file start anew, so it is
    read again whole; files that share their first 256 bytes (a long fixed
    header) are taken for one another, so a rotation skips the new file's
    lines up to the next poll; and a rewrite in place that a poll catches
    partway can re-read what it writes after that poll.
- A rotation that renames in place — what a size-capped writer does — puts the
  same inode back under a name `pattern` also matches. Its watcher resumes at
  the position the original reached, so `from = "start"` reads the tail an
  unfinished read left behind rather than the whole archive a second time.
- A line is parsed as JSON only when it is a non-empty object whose top-level
  keys are all drawn from `time`, `level`, `msg` and `fields` (the four an
  entry can carry), with any `level` or `msg` a string. `time` is read as
  RFC3339Nano; the read time stands in when it is missing or does not parse.
  Any other line is kept whole as text, so nothing in it is dropped. `level` is
  kept as written (a filter sees `Error` or `fatal` as is), and a line without
  `level` has none; only text lines get the inference below.
- A text line's level is its first whole word, in any case, naming one:
  `TRACE`; `DEBUG`, `DBG`; `INFO`, `INF`; `WARN`, `WARNING`; `ERROR`, `ERR`,
  `FATAL`. `warning: disk full` is WARN, `INFO retry after error` INFO. The
  console sink paints that word and the http sink's viewer filters on it.
- `raw = true` skips the JSON branch. The line, with its terminator (`\n` or
  `\r\n`) removed, becomes the message. `fields` stays empty, the time is the
  read time, and the level is inferred from the text. Empty lines are skipped.
  With `format.type = "raw"` each line is written back with one `\n`, which
  carries records the envelope cannot hold but is not byte-exact; see
  [Formatters](formatters.md#raw).

**Statistics**: `active_watchers`, and `watchers`, one map per followed file:
`directory` (the file's path), `size`, `position`, `entries_read`,
`rotations`, `last_read`. The status report shows that list only as
`watchers_count`.

---

## console

Reads newline-delimited entries from standard input. It is the source of the
built-in `pipe` pipeline, and of every pipeline from flags or variables left
without one: no `--source`, and no preset that brings one.

```toml
[[pipelines.plugin_sources]]
id   = "console"
type = "console"
[pipelines.plugin_sources.config]
buffer_size = 1000
```

Option, as type and default:

- `buffer_size` (int, `1000`): subscriber channel depth.

Lines:
- Each line is one entry, its terminator (`\n` or `\r\n`) removed; the
  formatter writes one back. An unterminated last line is kept.
- Empty lines are skipped; a line of spaces is an entry.
- A line over 1 MiB continues in the next entry; no byte is lost.
- The level is inferred from the line text, and `Source` is set to `console`.

Delivery and lifetime:
- The source drops nothing while its pipeline runs: it waits, so a slow
  pipeline slows the reading of stdin.
- One reader serves the process. A reload's new source continues where the old
  one stopped, and no line is read twice, but lines the old pipeline still
  holds at the reload can be lost. Hence at most **one** console source in the
  whole configuration, checked at validation.
- At the end of input the source ends, and with it a pipeline whose sources
  have all ended; lw exits once every pipeline has
  ([CLI](cli.md#built-in-defaults)). Under a supervisor whose stdin is
  `/dev/null` that is at once.

**Statistics**: `ended`, true once standard input has ended.

---

## random

Generated entries, to check a deployment before real logs are wired: paths,
permissions, sinks, chains, and sanitizer policies with `special = true`.

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
- `jitter_ms` (int, `0`): each interval varies by up to ±`jitter_ms`/2;
  non-negative, capped at `interval_ms`.
- `format` (string, `txt`): `raw` (message only), `txt` (bracketed line) or
  `json` (JSON object as the message).
- `length` (int, `20`): bytes of random text; `txt` and `json` wrap it in a
  longer message.
- `special` (bool, `false`): with `length` ≥ 3, mix in up to one control byte
  (`\n` and `\r` among them) and a few non-ASCII bytes, often invalid UTF-8.
  `raw` and `txt` carry them as they are; `json` escapes the control byte and
  replaces each invalid byte with U+FFFD.

Levels (`txt` and `json` only) are random among DEBUG, INFO, WARN, ERROR.
`Source` is `random_ID`, ID being the source's `id`.

**Statistics**: `format`, `interval_ms`, `jitter_ms`, `length`, `special`.

---

## null

Nothing; holds a source's place until one is chosen, so a pipeline can be set
up, sinks first, before its source is.

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
  connection label, and `force` the per-entry labels too
  ([Chaining](chaining.md#node-identity)).
- `tls` (table): listener TLS; see [Security](security.md).
- `auth` (table): peer authentication (`mtls` or `scram`) and node binding;
  see [Security](security.md#the-auth-block).
- `acl` (table): `allow` and `deny`, addresses or CIDRs admitted and refused
  before TLS, `proxy_protocol` with `proxy_from` for the client a PROXY header
  names, and `max_connections_per_client`; see
  [Security](security.md#the-acl-block).

For passwords instead of certificates, the `auth` block takes `type = "scram"`
and a `credentials_file`, or one `username` with its `password_file`, and
`client_auth` becomes optional; see
[Password Authentication](security.md#password-authentication-scram).

**Behaviour**

- TLS handshakes run explicitly with a 10 s bound before the preamble is read,
  after the `max_connections` admission check.
- Under `mtls` the certificate is checked before the hello is read, so an
  unauthorized peer never gets a preamble parsed on its behalf. Under `scram`
  the hello opens the login: challenge, proof and final follow on the same
  connection, the whole exchange within `hello_timeout_ms`, and the final is
  sent only once node binding agrees. A source without `scram` answers a hello
  offering credentials with `authentication not enabled`.
- An auth or node-binding refusal is logged at WARN and counted in
  `rejected_conns`. A missing, malformed or wrong-version hello is logged at
  WARN (`Rejected chain connection`) and not counted in `rejected_conns`;
  under `scram` a malformed or wrong-version one counts in `auth_rejected`. A
  connection over `max_connections` is closed and counted without a log.
- The node label is then resolved by `trust_node` and `auth.node_binding` (see
  [Chaining](chaining.md#node-identity)).
- Each accepted connection gets a session recording its remote address and:
  - `node`, the resolved label
  - under TLS: `tls`, `tls_peer_cn`
  - under auth: `auth_method`, `auth_identity`
  - behind a PROXY header: the proxy as `peer_addr`
- A malformed entry line increments `parse_errors` and is skipped; the
  connection survives. A line over 1 MiB is a protocol violation and terminates
  the connection.

**Statistics**: `host`, `port`, `tls`, `active_connections`, `rejected_conns`,
`parse_errors`, `tls_handshake_errors`, `trust_node`, and the
[auth and acl keys](#source-statistics).

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

- `host`, `port`, `trust_node`, `tls`: as on [tcp_chain](#tcp_chain).
- `auth` (table): as on `tcp_chain`, plus `token_lifetime_ms`, the `scram`
  bearer token lifetime: 10 s to 24 h, `0` = 15 minutes.
- `ingest_path` (string, `/ingest`): endpoint path; must start with `/`, and
  `/auth` is reserved for the login.
- `buffer_size` (int, `1000`): subscriber channel depth.
- `max_body_bytes` (int, `8388608`): per-request body cap (8 MiB).
- `read_timeout_ms` (int, `30000`): full request read deadline.
- `acl` (table): as on `tcp_chain`, plus `requests_per_second_per_client`.

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
- With `acl.requests_per_second_per_client`, a request over the rate gets `429`
  with `Retry-After`; the sink retries it.
- Batch acceptance is atomic: entries are published only after the body reads
  cleanly end to end. A transfer error, a line over 1 MiB included, rejects the
  whole batch with `400`, or `413` when the body cap is hit; an `http_chain`
  sink drops such a batch (`dropped_batches`) rather than retry it. A malformed
  *line* inside an otherwise clean transfer is skipped and counted in
  `parse_errors`.
- Success is `204 No Content` with `X-Logwisp-Accepted` set to the number of
  entries ingested.
- Sessions are cached per remote host + node + authenticated identity, and
  recreated after idle expiry. Including the identity in the key means two peers
  sharing a remote address never share a session.

**Statistics**: `host`, `port`, `ingest_path`, `tls`, `total_requests`,
`rejected_requests`, `parse_errors`, `cached_sessions`, `trust_node`, and the
[auth and acl keys](#source-statistics).

---

## Source Statistics

Every source reports: `id`, `type`, `total_entries`, `dropped_entries`,
`start_time`, `last_entry_time`, and a type-specific `details` map. The DEBUG
status report spreads `details` into each plugin's line.

Network sources and sinks add the auth and acl keys to `details`:

- `auth`: the method, `none` without an `auth` block; with one also
  - `auth_allowed`, `auth_rejected`; chain sources `node_binding`
  - `mtls`: `auth_identity`, `auth_unrestricted`
  - `scram` listeners: `auth_users`, `auth_throttled`, `auth_busy`,
    `auth_binding_mismatch`, `auth_identity` when bound; on HTTP
    `auth_token_lifetime_ms`; in proxy mode `auth_trusted_proxies`
  - `scram` dialers: `auth_username`, `auth_failures`, `last_auth_error`
- with a non-empty `acl` block: `acl`, `acl_denied`, `acl_limited`,
  `acl_proxy_headers`

