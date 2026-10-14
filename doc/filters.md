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

- `type`, string, default `include`: `include` (only matches pass) or
  `exclude` (matches are dropped).
- `logic`, string, default `or`: `or` (any pattern matches) or `and` (every
  pattern matches).
- `patterns`, []string, default `[]`: Go RE2 regular expressions.

A filter with no patterns passes everything. An invalid pattern is refused
when the configuration loads, named by its path
(`pipelines[0].flow.filters[0].patterns[1]`).

## What Gets Matched

Patterns are matched against a single string assembled from the entry:

```
"<source> <level> <message>"
```

Empty parts are omitted, so an entry with no detected level matches
`"<source> <message>"`. This means a pattern can target the source name or the
level as easily as the message body:

- `"^app\\.log "` matches entries whose source is `app.log`.
- `"ERROR"` matches `ERROR` anywhere in the text: the level, the message, the
  source name, or inside a word (`NOERROR`). Use `"\\bERROR\\b"` for the word.

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

- Literal substring: `ERROR`
- Case-insensitive: `(?i)error`
- Whole word: `\berror\b`
- Alternation: `ERROR|WARN|FATAL`
- Character class: `[0-9]{3}`
- Anchors: `^app\.log ` (the text starts with the source), `ERROR$`
- Any characters: `.*exception.*`

TOML strings process escapes, so a regex backslash needs doubling:
`"\\berror\\b"`. LogWisp's TOML reader has no literal (single-quoted)
strings, so `'\berror\b'` does not load, and a single `\b` is TOML's
backspace: `"\berror\b"` loads and never matches.

Anchors apply to the assembled match text, which begins with the source name,
so `^ERROR` never matches an entry that has a source; use `\bERROR\b`.

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

**Secret suppression**: LogWisp has no redaction; an exclude filter drops each
entry that matches ([Security](security.md)).

```toml
[[pipelines.flow.filters]]
type     = "exclude"
patterns = ["password", "api[_-]?key", "authorization", "bearer ", "secret", "token"]
```

**Per-application routing** — run one pipeline per application, each with its
own include filter, rather than trying to route inside one pipeline. Sinks fan
out to *all* sinks in a pipeline; there is no conditional routing.

## Statistics

Each filter reports `type`, `logic`, `pattern_count`, `total_processed`,
`total_matched`, and `total_dropped`. The chain reports `filter_count`,
`total_processed`, and `total_passed`; the pipeline derives
`total_filtered` as the difference.

## Performance

Patterns compile when a pipeline is built, at startup and on each reload.
Every entry that reaches the filter stage is evaluated against every filter
until one rejects it, and each filter runs all of its patterns whatever its
`logic`, so cost scales with the number of patterns and their complexity.
Prefer literal substrings and simple alternations over broad `.*` wildcards.

Filters log every pattern match and decision at DEBUG: useful when a filter
misbehaves, expensive on a busy pipeline, where `logging.level` stays at
`info` or higher.
