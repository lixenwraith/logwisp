# Filters

Filters decide which entries continue through a pipeline. They run in the flow,
after rate limiting and before formatting.

```toml
[[pipelines.flow.filters]]
type     = "include"
logic    = "or"
patterns = ["ERROR", "WARN"]
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | `include` | `include` (only matches pass) or `exclude` (matches are dropped) |
| `logic` | string | `or` | `or` (any pattern matches) or `and` (every pattern matches) |
| `patterns` | []string | `[]` | Go RE2 regular expressions |

A filter with no patterns passes everything. Invalid patterns fail at startup
with the filter index and the offending pattern in the message.

## What Gets Matched

Patterns are matched against a single string assembled from the entry:

```
"<source> <level> <message>"
```

Empty parts are omitted, so an entry with no detected level matches
`"<source> <message>"`. This means a pattern can target the source name or the
level as easily as the message body:

| Pattern | Matches |
|---------|---------|
| `"^app\\.log "` | Entries whose source is `app.log` |
| `"ERROR"` | Level `ERROR`, or the word `ERROR` anywhere in the message |

The structured `fields` payload is **not** part of the match text.

For entries that arrived over a chain link, the `source` used here is the bare
source — the `node/source` prefix is applied later, by the formatter — so
filtering by originating node requires matching on the message, or filtering on
the node that produces the entries.

## Filter Types

### include

Only matching entries pass. Everything else is dropped.

```toml
[[pipelines.flow.filters]]
type     = "include"
patterns = ["ERROR", "WARN", "FATAL"]
```

### exclude

Matching entries are dropped. Everything else passes.

```toml
[[pipelines.flow.filters]]
type     = "exclude"
patterns = ["/healthz", "TRACE"]
```

## Logic

### or (default)

```toml
logic    = "or"
patterns = ["ERROR", "WARN"]
# passes: "ERROR in module"      "WARN: low memory"
# blocks: "INFO: started"
```

### and

```toml
logic    = "and"
patterns = ["database", "ERROR"]
# passes: "ERROR: database connection failed"
# blocks: "ERROR: file not found"
```

With `logic = "and"` on an `exclude` filter, an entry is dropped only when it
matches *every* pattern.

## Filter Chains

Filters are evaluated in declaration order and an entry must survive all of
them. The first filter to reject an entry ends its life; later filters never see
it.

```toml
# 1. keep only production traffic
[[pipelines.flow.filters]]
type     = "include"
patterns = ["prod-", "production"]

# 2. of that, keep only failures
[[pipelines.flow.filters]]
type     = "include"
patterns = ["ERROR", "EXCEPTION", "FATAL"]

# 3. minus known noise
[[pipelines.flow.filters]]
type     = "exclude"
patterns = ["ECONNRESET", "broken pipe"]
```

Order matters for cost, not for correctness: put the most selective filter first
so later ones evaluate fewer entries.

## Pattern Syntax

Go's RE2 syntax. No backreferences and no lookaround — RE2 guarantees linear
time, which is exactly what you want in a log hot path.

| Need | Pattern |
|------|---------|
| Literal substring | `ERROR` |
| Case-insensitive | `(?i)error` |
| Whole word | `\\berror\\b` |
| Alternation | `ERROR\|WARN\|FATAL` |
| Character class | `[0-9]{3}` |
| Anchors | `^ERROR`, `ERROR$` |
| Any characters | `.*exception.*` |

Remember that TOML basic strings process escapes, so a regex backslash needs
doubling: `"\\berror\\b"`. TOML literal strings avoid the issue:
`'\berror\b'`.

Anchors apply to the assembled match text, which begins with the source name —
so `^ERROR` will not match an entry whose source is non-empty. Use
`\\bERROR\\b` instead unless you mean to anchor on the source.

## Common Recipes

**Severity floor**

```toml
[[pipelines.flow.filters]]
type     = "include"
patterns = ["ERROR", "FATAL", "CRITICAL"]
```

**Noise reduction**

```toml
[[pipelines.flow.filters]]
type     = "exclude"
patterns = ["/healthz", "/metrics", "\\bping\\b"]
```

**Secret suppression** — see [Security](security.md); filters are the only
redaction mechanism LogWisp currently offers.

```toml
[[pipelines.flow.filters]]
type     = "exclude"
patterns = ["password", "api[_-]?key", "authorization", "bearer ", "secret", "token"]
```

Note this drops the whole entry, it does not redact part of it.

**Per-application routing** — run one pipeline per application, each with its
own include filter, rather than trying to route inside one pipeline. Sinks fan
out to *all* sinks in a pipeline; there is no conditional routing.

## Statistics

Each filter reports `type`, `logic`, `pattern_count`, `total_processed`,
`total_matched`, and `total_dropped`. The chain reports `filter_count`,
`total_processed`, and `total_passed`; the pipeline derives
`total_filtered` as the difference.

## Performance

Patterns compile once at startup. Every entry that reaches the filter stage is
evaluated against every filter until one rejects it, so cost scales with the
number of patterns and their complexity. Prefer literal substrings and simple
alternations over broad `.*` wildcards.

Filters log at DEBUG on every entry — pattern text, match results, and the
final decision. That is invaluable when a filter is not behaving as expected and
very expensive in production; keep `logging.level` at `info` or higher on a busy
pipeline.
