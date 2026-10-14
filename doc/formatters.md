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

One formatter serves the whole pipeline. Sinks receive an identical payload
ending in a newline; under `raw` a message's own newlines stay, so a record
can span lines. Apart from the `http` sink's SSE framing, only the console
sink alters what it writes, escaping control characters on a terminal and
painting level names ([console](sinks.md#console)).
When you need two shapes of the same data, run two pipelines, or chain to a
node that formats differently.

Omitting `[pipelines.flow.format]` entirely selects `raw`.

## Options

Each as type and default:

- `type` (string, `raw`): `raw`, `txt`, or `json`.
- `sanitizer_policy` (string, derived from `type`): `raw`, `txt`, `json`, or
  `shell`.
- `flags` (int64, `0`): bitmask override; `0` selects a per-type default.
- `timestamp_format` (string, `time.RFC3339Nano`): Go reference layout, e.g.
  `"2006-01-02T15:04:05Z07:00"`.

## Types

### raw

Passthrough, the fastest type, for text already in its final form. `FlagRaw`
bypasses formatting and sanitization: the message reaches the sink as the
source produced it, control characters included, with no timestamp, level or
source prefix added, and a newline appended unless the message ends in one.
An entry that also carries `fields` gets the fields JSON appended verbatim
after a single space, so `FlagRaw` (`1`) never drops data or re-encodes it.
Heartbeats format without it, so in `raw` their `include_stats` fields print
in Go's map syntax (`heartbeat map[beat_count:0 type:heartbeat]`), as any
entry's fields do under a non-zero `flags` without `1`.

```toml
[pipelines.flow.format]
type = "raw"
```

The closest to verbatim transport is the `console` source, or the `file`
source with `raw = true`. The whole line, terminator removed, becomes the
message and `fields` stays empty; `raw` writes it back with one `\n`. It is not
byte-exact: empty lines are skipped, CRLF becomes LF, and a line over 1 MiB,
or one the `file` source reads while it is still being written, continues in
the next entry. The `file` source's JSON branch splits a line into message
and fields, so `raw` writes `<msg> <fields>` rather than the original object.

### txt

Human-readable lines, `<time> <level> <source> <message>`, any fields after
the message. The message and the fields are each double-quoted when empty or
holding whitespace, a non-printable character, a quote, or a shell or `=`
character (`$`, `;`, `<`, `*`, ...), with `"` and `\` backslash-escaped
inside; the time and source never are:

```
2026-01-02T15:04:05.123Z ERROR edge-01/app.log "connection refused"
```

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

`level` is DEBUG, INFO, WARN or ERROR, here and in `txt`. Only `DEBUG`,
`INFO`, `WARN`, `WARNING` and `ERROR`, all upper or all lower case, are read as
such; any other level, `TRACE` included, and an entry without one print as
INFO. Filters see the level as the source stored it.

The key names and structure come from the `lixenwraith/log` formatter, not
from LogWisp's configuration.

## Flags

`flags` is a bitmask passed to the underlying formatter. Leave it at `0` unless
you need to override the defaults.

- `1` Raw: bypass formatting and sanitization entirely.
- `2` ShowTimestamp: emit the timestamp.
- `4` ShowLevel: emit the level.
- `8` StructuredJSON: in `json`, the fields become a `fields` object beside
  `message`.
- `16` NoTimestamp: suppress the timestamp.
- `32` NoLevel: suppress the level.

With `flags = 0` the formatter selects `1` for `type = "raw"` and `6`
(timestamp + level) for every other type. `8` is added automatically whenever
an entry's `fields` is a non-empty JSON object and `1` is not set (it shapes
`json` only); `1` always wins.

`txt` and `json` show timestamp and level unless a suppress bit says otherwise
(suppress wins over show), so `2` and `4` alone change nothing. Examples:
`flags = 16` for level only, no timestamp; `flags = 32` for timestamp only, no
level.

## Sanitizer Policies

The sanitizer runs before serialization and neutralizes control characters that
would otherwise break framing or reach a terminal.

Each policy, then what to use it with:

- `raw`: no-op passthrough.
  - `type = "raw"` where you control the data.
- `txt`: writes `<` and non-printable characters as `<hex>` of their bytes
  (`<b>` becomes `<3c>b>`).
  - File and console sinks.
- `json`: writes control characters as JSON escapes (`\t`, `\u001b`) into
  the text, which `type = "json"` quotes again: a reader that decodes the
  record gets the escape, never the character.
  - `type = "json"`.
- `shell`: strips shell metacharacters, whitespace, and control characters.
  - Data that will be passed to a command.

Every policy but `raw` replaces invalid UTF-8 with U+FFFD. `type = "json"` is
valid JSON under any policy, since its own quoting escapes control characters
and replaces invalid UTF-8; with policy `raw` the decoded message keeps its
control characters. With `type = "raw"` and `flags = 0` no policy applies (`1`
bypasses it). When `sanitizer_policy` is omitted, it is the policy of the same
name as `type`, so the safe pairing is the default.

> `shell` strips dangerous characters but is **not** sufficient to make a string
> safe for shell construction. Pass arguments through `exec` argv instead of
> building command lines.

To see a policy working, point a pipeline at the `random` source with
`special = true` and `format` `raw` or `txt`, which mix control and non-ASCII
bytes, often invalid UTF-8, into its messages ([random](sources.md#random)).

## Node Identity in Output

Entries that arrived over a chain link carry a `Node` label, written as a
syslog-style prefix on the source (`trace` in `json`): `edge-01/app.log`.
Entries without one show the bare source. There is no separate node key, which
downstream parsers and grep patterns need to know.

## Structured Fields

When an entry's `fields` is a non-empty JSON object and `1` is not set, the
formatter parses it and adds `8`; without `1`, any other `fields` value
(`[1,2]`, `{}`, `"s"`) is dropped. Fields reach a pipeline from the `file`
source when a tailed line parses as JSON with a `fields` key, from the
`tcp_chain` and `http_chain` sources when the upstream entry carried them, and
from the heartbeat when `include_stats = true`. In `json` output such an entry
is `{"time":…,"level":…,"trace":…,"message":…,"fields":{…}}`; without fields
the message sits in `"fields":[…]`. In `txt` the fields follow the message in
Go's map syntax, keys sorted: `"disk full" "map[dev:sda pct:99]"`.

## Choosing a Configuration

By goal:

- Maximum throughput, data already formatted: `type = "raw"`.
- Human reading in a terminal or file: `type = "txt"`,
  `sanitizer_policy = "txt"`.
- Downstream ingestion (Loki, Elasticsearch, jq): `type = "json"`,
  `sanitizer_policy = "json"`.
- Compact console output: `type = "txt"`, `flags = 16`.
- Untrusted log content: never `raw`; `txt` or `json`, whose policies are the
  default.

## Formatting and Chain Links

Chain sinks (`tcp_chain`, `http_chain`) do **not** ship the formatted payload:
they send the structured entry in the chain encoding. `flow.format` on an edge
node therefore changes only that node's own local sinks; the shape a human or
a downstream system sees is decided on the node that owns the sink they read.

An event that reaches a chain sink without a structured entry is wrapped from
its formatted payload and counted in `synthesized`; a non-zero count means
something upstream lost structure.

## Performance

Relative cost, cheapest first: `raw` (passthrough) → `txt` (line assembly) →
`json` (serialization). Sanitization adds a scan of the message; the `raw`
policy skips it.

The formatter reuses an internal buffer under a mutex, so a pipeline formats
its entries one at a time.
