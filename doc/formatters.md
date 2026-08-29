# Formatters

The formatter is the last flow stage. It turns a `core.LogEntry` into the byte
payload that sinks write, applying a sanitizer policy on the way.

```toml
[pipelines.flow.format]
type             = "json"
sanitizer_policy = "json"
flags            = 0
timestamp_format = ""
```

One formatter serves the whole pipeline. Sinks receive an identical payload;
there is no per-sink formatting. When you need two shapes of the same data, run
two pipelines, or chain to a node that formats differently.

Omitting `[pipelines.flow.format]` entirely selects `raw`.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | `raw` | `raw`, `txt` (alias `text`), or `json` |
| `sanitizer_policy` | string | derived from `type` | `raw`, `txt`, `json`, or `shell` |
| `flags` | int64 | `0` | Bitmask override; `0` selects a per-type default |
| `timestamp_format` | string | formatter default | Go reference layout, e.g. `"2006-01-02T15:04:05Z07:00"` |

## Types

### raw

Passthrough. `FlagRaw` bypasses both formatting and sanitization, so the
message reaches the sink exactly as the source produced it.

```toml
[pipelines.flow.format]
type = "raw"
```

Fastest option, and the right one when you are relaying text that is already in
its final form. Note that it also bypasses sanitization, so control characters
in the source data reach your sinks intact.

### txt

Human-readable line output with a timestamp and level.

```toml
[pipelines.flow.format]
type             = "txt"
sanitizer_policy = "txt"
timestamp_format = "2006-01-02 15:04:05"
```

### json

Structured output, the natural choice for downstream ingestion.

```toml
[pipelines.flow.format]
type             = "json"
sanitizer_policy = "json"
```

Output has the shape:

```json
{"time":"2026-01-02T15:04:05.123Z","level":"ERROR","trace":"edge-01/app.log","fields":["connection refused"]}
```

The exact key names and structure come from the `lixenwraith/log` formatter, not
from LogWisp; they are stable for a given dependency version but are not part of
LogWisp's own configuration surface.

## Flags

`flags` is a bitmask passed to the underlying formatter. Leave it at `0` unless
you need to override the defaults.

| Value | Name | Effect |
|-------|------|--------|
| `1` | Raw | Bypass formatting and sanitization entirely |
| `2` | ShowTimestamp | Emit the timestamp |
| `4` | ShowLevel | Emit the level |
| `8` | StructuredJSON | Render attached fields as a JSON object |
| `16` | NoTimestamp | Suppress the timestamp |
| `32` | NoLevel | Suppress the level |

With `flags = 0` the formatter selects `1` for `type = "raw"` and `6`
(timestamp + level) for every other type. `8` is added automatically whenever an
entry carries parseable `fields`.

Examples: `flags = 4` for level only, no timestamp; `flags = 2` for timestamp
only, no level.

## Sanitizer Policies

The sanitizer runs before serialization and neutralizes control characters that
would otherwise break framing or reach a terminal.

| Policy | Behaviour | Use with |
|--------|-----------|----------|
| `raw` | No-op passthrough | `type = "raw"` where you control the data |
| `txt` | Escapes non-printable characters | File and console sinks |
| `json` | Escapes control characters for safe JSON embedding | `type = "json"`, chain links |
| `shell` | Strips shell metacharacters, whitespace, and control characters | Data that will be passed to a command |

When `sanitizer_policy` is omitted, the policy is derived from `type`: `json`
for `json`, `txt` for `txt`/`text`, and `raw` for anything else — so the safe
pairing is the default.

> `shell` strips dangerous characters but is **not** sufficient to make a string
> safe for shell construction. Pass arguments through `exec` argv instead of
> building command lines.

To see a policy working, point a pipeline at the `random` source with
`special = true`, which injects control bytes and multi-byte Unicode into every
message.

## Node Identity in Output

Entries that arrived over a chain link carry a `Node` label. The formatter
renders it as a syslog-style prefix on the source field:

```
edge-01/app.log
```

Entries with no node label show the bare source. Node identity therefore appears
*inside* the source field rather than as a separate output key — worth knowing
when writing downstream parsers or grep patterns.

## Structured Fields

When an entry carries `Fields` (raw JSON), the formatter parses it and switches
to structured rendering by adding the `StructuredJSON` flag automatically.
Fields reach a pipeline in two ways: from the `file` source when a tailed line
parses as JSON with a `fields` key, and from the heartbeat generator when
`include_stats = true`.

## Choosing a Configuration

| Goal | Configuration |
|------|---------------|
| Maximum throughput, data already formatted | `type = "raw"` |
| Human reading in a terminal or file | `type = "txt"`, `sanitizer_policy = "txt"` |
| Downstream ingestion (Loki, Elasticsearch, jq) | `type = "json"`, `sanitizer_policy = "json"` |
| Compact console output | `type = "txt"`, `flags = 4` |
| Untrusted log content | never `raw`; pick `txt` or `json` and set the matching policy |

## Formatting and Chain Links

Chain sinks (`tcp_chain`, `http_chain`) do **not** ship the formatted payload.
They re-serialize the structured entry into the canonical chain encoding, which
makes them independent of the local formatter.

The practical consequence: setting `flow.format` on an edge node changes only
that node's own local sinks. The output shape seen by a human or a downstream
system is decided on the node that owns the sink they read.

If an event ever reaches a chain sink without a structured entry, the sink wraps
the formatted payload into a synthetic entry and counts it in `synthesized`.
A non-zero `synthesized` count means something upstream lost structure.

## Performance

Relative cost, cheapest first: `raw` (passthrough) → `txt` (line assembly) →
`json` (serialization). Sanitization adds a scan of the message; the `raw`
policy skips it.

The formatter holds a mutex because the underlying implementation reuses an
internal buffer and is not goroutine-safe. It is the only shared serialization
point in the hot path, and the reason a single pipeline formats entries one at
a time.
