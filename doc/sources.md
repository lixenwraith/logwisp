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
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `directory` | string | **required** | Directory to scan; not recursive |
| `pattern` | string | `*` | Glob over filenames; `*` and `?` only |
| `check_interval_ms` | int | `100` | Directory rescan interval; minimum `10` |

**Behaviour**

- `check_interval_ms` governs how often the directory is rescanned for new or
  removed files. Tailing an already-open file polls on a **fixed 100 ms**
  interval that this option does not change.
- Each matched file gets its own watcher. Watchers for files that disappear are
  stopped and removed on the next scan.
- A new watcher seeks to end-of-file. Positions live in memory only, so a
  restart resumes from the current end of each file and content written while
  LogWisp was down is not read.
- Rotation is detected from size decrease, modification-time reset, a position
  beyond end-of-file, or an inode change. An inode change where the new file is
  already larger than the recorded position is treated as an atomic save, not a
  rotation, and the position is preserved.
- Lines are parsed as JSON when they contain `time`, `level`, `msg`, and
  `fields` keys; `time` is read as RFC3339Nano. Anything else is kept as plain
  text with the level inferred from common markers (`[ERROR]`, `WARN:`, and so
  on).
- `Source` is set to the file's base name.

**Statistics**: per-watcher size, position, entries read, rotation count, and
last read time, plus `active_watchers`.

---

## console

Reads newline-delimited entries from standard input.

```toml
[[pipelines.plugin_sources]]
id   = "stdin"
type = "console"
[pipelines.plugin_sources.config]
buffer_size = 1000
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `buffer_size` | int | `1000` | Subscriber channel depth |

At most **one** instance per pipeline: the type is registered with
`MaxInstances: 1`, and a second instance is rejected at pipeline construction.
The level is inferred from the line text, and `Source` is set to `console`.

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

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `interval_ms` | int | `500` | Emission period |
| `jitter_ms` | int | `0` | Symmetric jitter; clamped to `interval_ms`, must be non-negative |
| `format` | string | `txt` | `raw` (message only), `txt` (bracketed line), `json` (JSON object as the message) |
| `length` | int | `20` | Message length in characters |
| `special` | bool | `false` | Inject control and non-ASCII characters |

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

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `0.0.0.0` | Bind address; IPv4 only |
| `port` | int | **required** | Listen port, 1–65535 |
| `buffer_size` | int | `1000` | Subscriber channel depth |
| `max_connections` | int | `0` | Concurrent connection cap; `0` = unlimited |
| `read_timeout_ms` | int | `0` | Per-connection idle read deadline; `0` = none |
| `hello_timeout_ms` | int | `10000` | Deadline for the hello preamble |
| `trust_node` | bool | `true` | `false` overrides the sender's node label with its remote address. Ignored when `auth.node_binding` is active |
| `tls` | table | — | Listener TLS; see [Security](security.md) |
| `auth` | table | — | Peer authorization and node binding; see [Security](security.md#the-auth-block) |

**Behaviour**

- TLS handshakes run explicitly with a 10 s bound before the preamble is read,
  after the `max_connections` admission check.
- Authorization runs between the handshake and the hello read, so an
  unauthorized peer never gets a preamble parsed on its behalf. A rejection is
  logged at WARN and counted in `rejected_conns`.
- A connection is rejected if the first line is not a valid hello with a
  matching protocol version.
- The node label is then resolved: under `auth.node_binding` it comes from the
  peer's certificate, otherwise `trust_node` governs. `force` also overrides the
  `node` field on every individual entry; `assert` leaves per-entry labels to
  `trust_node`, so a relay can forward other nodes' entries while proving its
  own identity.
- Each accepted connection gets a session recording the remote address, node
  label, — under TLS — `tls` and `tls_peer_cn`, and — under auth —
  `auth_method` and `auth_identity`.
- A malformed entry line increments `parse_errors` and is skipped; the
  connection survives. A line over 1 MiB is a protocol violation and terminates
  the connection.

**Statistics**: `active_connections`, `rejected_conns`, `parse_errors`,
`tls_handshake_errors`, `trust_node`, `auth`, `auth_allowed`, `auth_rejected`,
`node_binding`.

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

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `0.0.0.0` | Bind address; IPv4 only |
| `port` | int | **required** | Listen port |
| `ingest_path` | string | `/ingest` | Endpoint path; must start with `/` |
| `buffer_size` | int | `1000` | Subscriber channel depth |
| `max_body_bytes` | int | `8388608` | Per-request body cap (8 MiB) |
| `read_timeout_ms` | int | `30000` | Full request read deadline |
| `trust_node` | bool | `true` | `false` overrides the sender's node label with its remote address. Ignored when `auth.node_binding` is active |
| `tls` | table | — | Listener TLS |
| `auth` | table | — | Peer authorization and node binding; see [Security](security.md#the-auth-block) |

**Behaviour**

- Only `POST` to `ingest_path` is routed; other methods get `405` with an
  `Allow` header, and other paths get `404`.
- Authorization runs before the body is read, so an unauthorized sender does not
  get to stream `max_body_bytes` into the process. Both a policy rejection and a
  node-binding failure answer `403`, distinct from the `400` used for protocol
  errors, so a sender can tell "not allowed" from "malformed batch".
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
`node_binding`.

---

## Source Statistics

Every source reports: `id`, `type`, `total_entries`, `dropped_entries`,
`start_time`, `last_entry_time`, and a type-specific `details` map. These appear
in the status reporter output and in the `http` sink's status endpoint.
