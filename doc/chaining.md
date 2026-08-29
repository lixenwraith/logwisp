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
  │ http_chain sink│   :15802   └────────────────────┘
  └───────────────┘
```

Both chain sources can feed a single pipeline (fan-in) whose sinks then fan the
merged stream out. `test/chain-test.sh` builds the two-independent-pipelines
variant; `test/chain-aggregate-test.sh` builds the fan-in variant.

## Node Identity

Chained entries carry a `node` label identifying where they originated.

- A chain **sink** stamps `node` on any entry that does not already have one.
  The label comes from the `node` option, defaulting to `os.Hostname()`.
- A chain **source** either honours the sender's label or overrides it,
  according to `trust_node`:

| `trust_node` | Behaviour |
|--------------|-----------|
| `true` (default) | Keep the label the sender declared; fall back to the remote address when absent |
| `false` | Always overwrite with the sender's remote address |

Relays preserve `node`, so a label survives any number of hops and identifies
the original producer rather than the last relay.

Under mTLS the source can instead bind the label to the sender's certificate,
which overrides `trust_node` entirely:

| `auth.node_binding` | Connection label | Per-entry `node` field |
|---------------------|------------------|------------------------|
| `none` | `trust_node` governs | `trust_node` governs |
| `assert` | Must equal the certificate identity, or the peer is rejected | `trust_node` governs |
| `force` (default under `mtls`) | The certificate identity | Overwritten with the identity |

Pick `force` at an ingest boundary you do not trust — it is the only setting
where a compromised edge cannot mislabel its entries, including through the
per-entry `node` field. Pick `assert` on a relay-to-relay hop, where the relay
should prove its own identity but the origin labels it forwards must survive.
See [Security](security.md#node-binding).

Formatters render node identity as a syslog-style prefix on the source field:
`edge-01/app.log`. In JSON output the node therefore appears inside the source
field, not as a separate top-level key.

> `trust_node = true` with no `auth` block means any peer the CA vouches for can
> claim **any** node label, including one belonging to another host. On an
> untrusted network set `auth.type = "mtls"` with `node_binding = "force"`;
> `trust_node = false` is the fallback when certificates are not an option.

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

3. The listener reads that line within `hello_timeout_ms` and rejects the
   connection if it is malformed or declares a different protocol version.
4. Every subsequent line is one JSON-encoded `LogEntry`.

Line size is bounded at 1 MiB. An oversized line is a protocol violation and
terminates the connection, because the scanner cannot resynchronize afterwards.

### HTTP transport

Batches of NDJSON delivered by `POST`, with the preamble expressed as headers.

| Header | Direction | Meaning |
|--------|-----------|---------|
| `X-Logwisp-Protocol` | request | Protocol version; must be `1` |
| `X-Logwisp-Node` | request | Origin node label |
| `Content-Type` | request | `application/x-ndjson` |
| `X-Logwisp-Accepted` | response | Number of entries ingested |

Responses: `204` on success, `400` for a bad protocol version or a malformed
body, `413` when the body cap is exceeded, `405` for a non-`POST` method.

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
in at ingest.

## Delivery Semantics

| Transport | Guarantee | Failure behaviour |
|-----------|-----------|-------------------|
| `tcp_chain` | Per-line, held across reconnects | Retries with exponential backoff plus ±20 % jitter until written or shutdown; back-pressure appears upstream as `total_dropped_by_sink` |
| `http_chain` | At-least-once per batch | Retries transport errors, `408`, `429`, `5xx`; drops on any other non-2xx (`dropped_batches`) |

`http_chain` batches can be delivered twice when a successful request's response
is lost. There is no de-duplication downstream; design your consumers to
tolerate it, or use `tcp_chain` where each line is written once per successful
write.

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
host = "relay.internal"
port = 15801
node = "edge-01"
[pipelines.plugin_sinks.config.tls]
enabled   = true
ca_file   = "/etc/logwisp/tls/ca.crt"
cert_file = "/etc/logwisp/tls/edge-01.crt"
key_file  = "/etc/logwisp/tls/edge-01.key"
[pipelines.plugin_sinks.config.auth]
type  = "mtls"
allow = ["relay.internal"]      # pin the relay, not just its hostname
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
`test/mtls-chain-test.sh` builds exactly this shape against a throwaway PKI.

## Operational Notes

- **Formatting is a relay decision.** Because chain links carry structured
  entries, the edge node's `flow.format` affects only its own local sinks. Set
  the output shape on the node that owns the human-facing sink.
- **Filtering early saves bandwidth.** A filter on the edge drops entries before
  they cross the network; a filter on the relay is easier to change centrally.
- **Rate limits are per pipeline.** An edge limit protects the link; a relay
  limit protects the relay from a noisy edge.
- **Heartbeats traverse chain links** as ordinary structured entries and keep
  otherwise-idle links and their sessions warm.
- **Ports** used by the bundled test scripts: `15801` tcp_chain ingest, `15802`
  http_chain ingest, `15803` tcp sink, `15804` http sink.
- **Use `127.0.0.1`, not `localhost`**, when testing locally: all listeners and
  dialers are IPv4-only, and `localhost` may resolve to `::1`.
