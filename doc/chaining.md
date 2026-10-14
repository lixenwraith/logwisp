# Chaining

Chaining links LogWisp nodes together. An edge node forwards its entries to a
relay or collector, which can filter, reformat, fan out, or forward them again.
Unlike the `tcp` and `http` sinks — which emit *formatted text* for humans and
generic clients — chain links carry the **structured entry**, so downstream
nodes can filter and reformat as if the entries were local.

## Topology

```
  edge-01                       relay                        consumers
  ┌───────────────┐             ┌────────────────────┐       ┌──────────────┐
  │ file source   │             │ tcp_chain source   │       │ browser (SSE)│
  │      ↓        │  TCP/TLS    │        ↓           │  ───► │ nc / telnet  │
  │ tcp_chain sink├────────────►│      flow          │       │ archive file │
  └───────────────┘   :15801    │        ↓           │       └──────────────┘
                                │ http sink, tcp sink│
  edge-02                       │ file sink          │
  ┌───────────────┐             │ http_chain sink ───┼──►  upstream collector
  │ file source   │  HTTP/TLS   │                    │
  │      ↓        ├────────────►│ http_chain source  │
  │http_chain sink│   :15802    └────────────────────┘
  └───────────────┘
```

Both chain sources can feed a single pipeline (fan-in) whose sinks then fan the
merged stream out. `test/chain-test.sh` builds the two-independent-pipelines
variant; `test/chain-aggregate-test.sh` builds the fan-in variant. The `edge`
and `aggregator` [presets](cli.md#presets) build an authenticated TLS link of
either transport from a few keys.

## Node Identity

Chained entries carry a `node` label identifying where they originated.

- A chain **sink** stamps `node` on any entry that does not already have one.
  The label comes from the `node` option, defaulting to `os.Hostname()`.
- A chain **source** either honours the sender's label or overrides it,
  according to `trust_node`:
  - `true` (default): keep the label the sender declared; fall back to the
    remote address when absent.
  - `false`: always overwrite with the sender's remote address.

Relays preserve `node`, so a label survives any number of hops and identifies
the original producer, unless a hop's source overwrites it: `trust_node =
false`, or `node_binding = "force"` (the default under `mtls` or `scram`).
Formatters write the label as a prefix on the source
([Formatters](formatters.md#node-identity-in-output)).

With an `auth` block the source can instead bind the label to the sender's
authenticated identity: its certificate identity under `mtls`, its username
under `scram`. `auth.node_binding`:

- `none`: `trust_node` governs the connection label and the per-entry `node`
  field.
- `assert`: the connection label must equal the identity, or the peer is
  rejected; `trust_node` governs the per-entry `node` field, the label standing
  in wherever it would put the remote address.
- `force` (default under `mtls` or `scram`): the identity is the connection
  label and overwrites every per-entry `node` field.

Pick `force` at an ingest boundary you do not trust — it is the only setting
where a compromised edge cannot mislabel its entries, including through the
per-entry `node` field. Pick `assert` on a relay-to-relay hop, where the relay
should prove its own identity but the origin labels it forwards must survive.
See [Security](security.md#node-binding).

> `trust_node = true` with no `auth` block means any peer that can connect can
> claim **any** node label, including one belonging to another host. On an
> untrusted network set an `auth` block (`mtls` or `scram`) and keep
> `node_binding = "force"`; `trust_node = false` is the fallback when neither is
> an option.

## Wire Protocol

Protocol version: **1**. Both transports carry the same canonical entry
encoding, and differ only in how the preamble and framing are expressed.

### TCP transport

A persistent connection carrying newline-delimited JSON.

1. The dialer connects and, under TLS, completes the handshake.
2. The dialer immediately writes the hello preamble as one JSON line:

   ```json
   {"logwisp":1,"node":"edge-01"}
   ```

3. The listener reads that line, at most 4 KiB, within `hello_timeout_ms` and
   rejects the connection if it is malformed or declares a different protocol
   version.
4. Every subsequent line is one JSON-encoded `LogEntry`.

Line size is bounded at 1 MiB. An oversized line is a protocol violation and
terminates the connection, because the scanner cannot resynchronize afterwards.
The cap applies to the encoded line, envelope and JSON escapes included, so a
message near 1 MiB exceeds it (the console and file sources cut lines at
1 MiB). On `tcp_chain` such an entry ends the link. If the socket took the
whole line, the entry is lost, together with any line the sink writes before it
notices the close. If the line overruns the cap by more than the socket buffers
hold, as a message of control characters can (most escape to six bytes), the
write fails and the sink resends the line on every reconnect: the link stalls
until a stop or reload, and later entries count in `total_dropped_by_sink`. The
sink does not yet drop a line the source must refuse. On `http_chain` such an
entry fails its whole batch with `400`, which the sink drops.

Under `auth.type = "scram"` the hello also carries the SCRAM client-first
message, and three more lines precede the entries, each one JSON object of at
most 4 KiB:

```
dialer   {"logwisp":1,"node":"edge-01","scram":{"username":"edge-01","client_nonce":"…"}}
listener {"challenge":{"full_nonce":"…","salt":"…","argon_time":3,"argon_memory":65536,"argon_threads":4}}
dialer   {"proof":{"full_nonce":"…","client_proof":"…"},"binding":"<base64 SHA-256 of the server certificate>"}
listener {"final":{"server_signature":"…","username":"edge-01"}}
```

The whole exchange runs within `hello_timeout_ms`; the listener sends the final
line only after node binding agrees, and a refusal at any step is one
`{"error":"…"}` line before the connection closes. The field is additive, so
the protocol version stays `1`: a listener without `scram` answers a hello
carrying it with `{"error":"authentication not enabled"}`, while an older
binary ignores it and the dialer gives up after 10 s.

### HTTP transport

Batches of NDJSON delivered by `POST` to `ingest_path` (default `/ingest`), with
the preamble expressed as headers.

- Request headers
  - `X-Logwisp-Protocol`: the protocol version; must be `1`.
  - `X-Logwisp-Node`: the sending sink's `node`, the connection label, as in the
    TCP hello.
  - `Content-Type`: `application/x-ndjson`.
  - `Authorization`: `Bearer <token>`, under `scram`.
- Response header
  - `X-Logwisp-Accepted`: the number of entries ingested.

Responses: `204` on success; `400` for a bad protocol version or a transfer
error, a line over 1 MiB included; `413` past `max_body_bytes`; `404` for
another path; `405` for a non-`POST` method; `429` (with `Retry-After`) past
`acl.requests_per_second_per_client`; `401` for a missing, invalid or expired
token; `403` for a refused certificate or node label.

Under `scram` the sink first logs in with two `POST /auth` requests, each
`Content-Type: application/json` and carrying the same JSON as the TCP lines:
the hello (`200` and the challenge), then the proof (`200` with the final
message, `token` and `expires_in` in seconds). A refusal is `{"error":"…"}`:
`401` for a failed proof, `429` when throttled, `503` when the listener is
busy, `415` without the JSON content type, `400` or `413` for a malformed or
oversized body.

### Entry encoding

```json
{
  "time": "2026-01-02T15:04:05.123456789Z",
  "node": "edge-01",
  "source": "app.log",
  "level": "ERROR",
  "message": "connection refused",
  "fields": {"attempt": 3}
}
```

`node`, `level`, and `fields` are omitted when empty. A missing `time` is filled
in at ingest. A line that does not decode is skipped and counted in
`parse_errors`; the connection or batch stands.

## Delivery Semantics

- `tcp_chain`: per line, held across reconnects until the socket accepts it,
  with exponential backoff plus ±20 % jitter. There is no acknowledgement:
  lines in flight when a link breaks are lost (at most once).
- `http_chain`: at least once per batch. It retries transport errors, `408`,
  `429`, `5xx` and, under `scram`, failed logins and `401`. It drops the batch
  on any other non-2xx, counted in `dropped_batches`. A batch can arrive twice
  when a successful request's response is lost; there is no de-duplication
  downstream.
- Both: while a link is down or a batch retries, the sink's input queue fills
  and the pipeline counts drops in `total_dropped_by_sink`.

Neither transport persists anything to disk. Entries buffered in memory during
an outage are lost if the process exits.

## Worked Example

**Edge node** — tail files, forward over mTLS:

```toml
[[pipelines]]
name = "edge"

[[pipelines.plugin_sources]]
id = "app"
type = "file"
[pipelines.plugin_sources.config]
directory = "/var/log/myapp"
pattern = "*.log"

[[pipelines.plugin_sinks]]
id = "forward"
type = "tcp_chain"
[pipelines.plugin_sinks.config]
host = "relay.example.org"
port = 15801
node = "edge-01"
[pipelines.plugin_sinks.config.tls]
enabled   = true
ca_file   = "/etc/logwisp/tls/ca.crt"
cert_file = "/etc/logwisp/tls/edge-01.crt"
key_file  = "/etc/logwisp/tls/edge-01.key"
[pipelines.plugin_sinks.config.auth]
type  = "mtls"
allow = ["relay.example.org"]   # pin the relay, not just its hostname
```

**Relay** — ingest, keep errors only, archive and stream:

```toml
[[pipelines]]
name = "relay"

[[pipelines.flow.filters]]
type = "include"
patterns = ["ERROR", "FATAL"]

[pipelines.flow.format]
type = "json"
sanitizer_policy = "json"

[[pipelines.plugin_sources]]
id = "ingest"
type = "tcp_chain"
[pipelines.plugin_sources.config]
host = "0.0.0.0"
port = 15801
[pipelines.plugin_sources.config.tls]
enabled        = true
cert_file      = "/etc/logwisp/tls/relay.crt"
key_file       = "/etc/logwisp/tls/relay.key"
client_auth    = true
client_ca_file = "/etc/logwisp/tls/ca.crt"
[pipelines.plugin_sources.config.auth]
type         = "mtls"
allow        = ["edge-01", "edge-02"]
node_binding = "force"          # entries are labelled from the certificate

[[pipelines.plugin_sinks]]
id = "archive"
type = "file"
[pipelines.plugin_sinks.config]
directory = "/var/log/logwisp"
name = "errors"

[[pipelines.plugin_sinks]]
id = "live"
type = "http"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = 8080
```

Entries arriving on this relay are labelled `edge-01` or `edge-02` because that
is what their certificates say, regardless of the `node` each edge configured.
`test/mtls-chain-test.sh` runs a relay of this kind (mTLS ingest with
`node_binding = "force"`) against a throwaway PKI.

To use passwords instead of client certificates, replace both `auth` blocks:
`type = "scram"` with `username` and `password_file` on the edge, and on the
relay a `credentials_file`, or one `username` with its `password_file`.
`client_auth` and the edge's certificate become optional, and entries are
labelled with the username. See
[Password Authentication](security.md#password-authentication-scram).

## Operational Notes

- **Filtering early saves bandwidth.** A filter on the edge drops entries before
  they cross the network; a filter on the relay is easier to change centrally.
- **Rate limits are per pipeline.** An edge limit protects the link; a relay
  limit protects the relay from a noisy edge.
- **Heartbeats traverse chain links** as ordinary structured entries and keep
  otherwise-idle links and their sessions warm.
- **Dial the listener's own literal** when testing locally: a listener on
  `127.0.0.1` takes IPv4 only, and `localhost` may resolve to `::1`.
