# Configuration Reference

LogWisp is configured with TOML. A complete annotated file listing every option
and its default ships as [`config/logwisp.toml`](../config/logwisp.toml).

## Configuration Precedence

Sources are merged in this order, highest priority first:

1. Command-line flags
2. Environment variables
3. Configuration file
4. Built-in defaults

The `pipelines` array is replaced wholesale, not merged: as soon as your file
defines `[[pipelines]]`, the built-in default pipeline (and its default rate
limit and formatter) disappears entirely.

## File Location

The path is resolved before any other configuration is read:

1. `-c <path>` on the command line
2. `--config=<path>` on the command line
3. `$LOGWISP_CONFIG_FILE`, joined onto `$LOGWISP_CONFIG_DIR` when both are set
4. `$LOGWISP_CONFIG_DIR/logwisp.toml`
5. `~/.config/logwisp/logwisp.toml`, if it exists
6. `./logwisp.toml`

Missing file behaviour differs by how it was chosen. An explicitly requested
file that does not exist is a fatal error (exit code 2); a missing discovered
default is not an error, and LogWisp starts on built-in defaults.

> `--config <path>` with a space is **not** recognized as a config path. It is
> parsed as an unknown flag, warned about, and ignored — LogWisp then silently
> falls back to `./logwisp.toml`. Use `-c <path>` or `--config=<path>`.

## Global Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `quiet` | bool | `false` | Disable all application logging and console diagnostics |
| `status_reporter` | bool | `true` | Emit a periodic status report every 30 s at DEBUG level |
| `auto_reload` | bool | `false` | Watch the config file and reload pipelines on change |

`--version` prints version information and exits; it is not a persistent
setting.

Note that `status_reporter` writes at DEBUG level, so it produces nothing unless
`logging.level = "debug"`.

## Application Logging

This configures LogWisp's own operational log, not the log data it transports.

```toml
[logging]
output = "stdout"      # file | stdout | stderr | split | all | none
level  = "info"        # debug | info | warn | error
format = "txt"         # raw | txt | json
# sanitization = ""    # raw | json | txt | shell

[logging.file]
directory         = "./log"
name              = "logwisp"
max_size_mb       = 100
max_total_size_mb = 1000
retention_hours   = 168.0
```

### Output modes

| Mode | Behaviour |
|------|-----------|
| `file` | Files only |
| `stdout` | Standard output only |
| `stderr` | Standard error only |
| `split` | DEBUG/INFO to stdout, WARN/ERROR to stderr |
| `all` | Files plus split console |
| `none` | No application logging |

`[logging.file]` applies only to the `file` and `all` modes.

> `[logging.console].target` is accepted and validated (`stdout`, `stderr`,
> `split`) but **not applied**. The console destination is derived from
> `logging.output`. The key is retained for compatibility; setting it has no
> effect.

`quiet = true` overrides every logging setting and disables both file and
console output.

## Pipeline Configuration

```toml
[[pipelines]]
name = "app"                       # required, unique across pipelines

# --- flow: everything between sources and sinks ---
[pipelines.flow.rate_limit]
rate                 = 1000.0
burst                = 2000.0
policy               = "drop"
max_entry_size_bytes = 65536

[[pipelines.flow.filters]]
type     = "include"
logic    = "or"
patterns = ["ERROR", "WARN"]

[pipelines.flow.format]
type             = "json"
sanitizer_policy = "json"

[pipelines.flow.heartbeat]
enabled     = true
interval_ms = 30000

# --- sources: one or more ---
[[pipelines.plugin_sources]]
id   = "app_logs"                  # unique within the pipeline
type = "file"
[pipelines.plugin_sources.config]
directory = "/var/log/myapp"

# --- sinks: one or more ---
[[pipelines.plugin_sinks]]
id   = "sse"
type = "http"
[pipelines.plugin_sinks.config]
port = 8080
```

Every source and sink is a plugin instance with three keys:

| Key | Meaning |
|-----|---------|
| `id` | Instance identifier, unique within the pipeline; appears in logs and stats |
| `type` | Registered plugin type |
| `config` | Plugin-specific table; see [Sources](sources.md) and [Sinks](sinks.md) |

`config_file` is reserved on both structures for a future include mechanism and
is not implemented.

### Flow stages

| Block | Optional | Reference |
|-------|----------|-----------|
| `flow.rate_limit` | yes | below |
| `flow.filters` | yes | [Filters](filters.md) |
| `flow.format` | yes (defaults to `raw`) | [Formatters](formatters.md) |
| `flow.heartbeat` | yes | below |

#### Rate limiting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rate` | float | `0` | Entries per second; `<= 0` disables the limiter entirely |
| `burst` | float | `rate` | Token bucket capacity |
| `policy` | string | `pass` | `pass` allows everything through, `drop` discards over-limit entries |
| `max_entry_size_bytes` | int | `0` | Per-entry byte cap; `0` = unlimited |

Two behaviours are easy to trip over:

- The limiter is constructed only when `rate > 0`. With `rate = 0`,
  `max_entry_size_bytes` is never enforced.
- `policy = "pass"` short-circuits the whole check, including the size cap.
  To enforce a size cap you need `rate > 0` **and** `policy = "drop"`.

#### Heartbeat

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable heartbeat generation |
| `interval_ms` | int | `1000` | Interval; minimum `100` |
| `include_timestamp` | bool | `false` | `false` formats with level only, no timestamp |
| `include_stats` | bool | `false` | Attach `beat_count` and measured `interval_ms` as fields |
| `format` | string | `txt` | `txt`, `json`, or `raw` |

Heartbeats are ordinary entries with source `heartbeat` and level `INFO`. They
are generated after the flow's filter and rate-limit stages, so filters do not
suppress them, and they reach every sink in the pipeline.

> `format = "comment"` (SSE comment framing) appears in older documentation and
> in a code path in the generator, but the validator rejects it and the pipeline
> fails to start. Use `txt`, `json`, or `raw`.

## Environment Variables

Environment overrides are derived from the TOML path: `.` becomes `_` and the
result is uppercased.

| TOML path | Environment variable |
|-----------|---------------------|
| `quiet` | `QUIET` |
| `status_reporter` | `STATUS_REPORTER` |
| `logging.level` | `LOGGING_LEVEL` |
| `logging.file.directory` | `LOGGING_FILE_DIRECTORY` |

> **The `LOGWISP_` prefix is not currently applied.** The configuration loader
> requests it, but supplying a custom path-to-variable transform replaces the
> prefixing step rather than composing with it, so LogWisp reads bare
> `QUIET`, `LOGGING_LEVEL`, and so on from the environment. Treat this as
> current behaviour to be aware of — bare names like `QUIET` can collide with
> unrelated variables — rather than as intended design.
>
> The two exceptions are `LOGWISP_CONFIG_FILE` and `LOGWISP_CONFIG_DIR`, which
> are read directly by the path resolver and **do** carry the prefix.

Only scalar paths that exist in the configuration schema can be set this way.
Array elements cannot: `PIPELINES_0_NAME` has no effect.

## Command-Line Overrides

Any scalar configuration path is settable as a flag using its TOML path:

```bash
logwisp --logging.level=debug --status_reporter=false
logwisp --logging.level debug          # space form also works
logwisp --quiet                        # bare flag means true
```

Unrecognized flags are reported on stderr before the logger exists and are then
ignored:

```
Warning: unrecognized flags ignored: [pipelines.0.name]
```

> Array-indexed paths are **not** settable from the command line.
> `--pipelines.0.name=x`, `--pipelines.0.plugin_sinks.0.type=null`, and similar
> flags are reported as unrecognized and ignored. Pipelines, sources, sinks, and
> filters can only be defined in the configuration file. Older documentation
> claimed otherwise.

## Validation

Startup validation is intentionally split.

`internal/config` validates only global structure:

- at least one pipeline
- unique, non-empty pipeline names
- at least one source and one sink per pipeline
- `logging.output`, `logging.level`, `logging.format`, `logging.sanitization`,
  and `logging.console.target` enum membership

Everything else is validated by the plugin constructor that owns it — port
range, required paths, path prefixes, enum values, regex compilation, TLS file
loading. A failure there aborts pipeline construction with a message naming the
pipeline, plugin id, and offending key.

There is **no** cross-pipeline port-conflict detection. Two sinks bound to the
same port fail at listener bind time, when the pipeline starts.

## Hot Reload

```toml
auto_reload = true
```

or send `SIGHUP` / `SIGUSR1`.

Reload rebuilds the whole service: a new service is constructed from the new
configuration first, and only if that succeeds is the old one shut down. A
configuration error therefore leaves the running service untouched.

| Reloaded | Not reloaded |
|----------|--------------|
| Pipelines, sources, sinks | `logging.*` (applied once at startup) |
| Filters, formatters, rate limits, heartbeats | `quiet` |
| `status_reporter` | `auto_reload` (the watcher is not restarted) |

Because the rebuild is total, listeners close and reopen and every connected
client is disconnected. Chain sinks reconnect on their own backoff schedule.

## Type Reference

| TOML type | Go type | Command-line / environment form |
|-----------|---------|-------------------------------|
| String | `string` | Plain text |
| Integer | `int64` | Decimal string |
| Float | `float64` | Decimal string |
| Boolean | `bool` | `true` / `false`, or a bare flag for `true` |
| Array | `[]T` | Not settable outside the file |
| Table | struct | Nested path with `.` (flags) or `_` (environment) |
