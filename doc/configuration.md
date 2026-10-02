# Configuration Reference

LogWisp is configured with TOML. A complete annotated file listing every option
and its default ships as [`config/logwisp.toml`](../config/logwisp.toml).

## Configuration Precedence

- Pipelines come from the first of these that defines any, replacing the rest
  wholesale (the default pipeline's rate limit and formatter included):
  1. pipeline flags: `--source`, `--sink`, ... ([CLI](cli.md#pipelines))
  2. pipeline variables: `LOGWISP_SOURCE`, ...
     ([CLI](cli.md#pipeline-variables))
  3. the file's `[[pipelines]]`
  4. the built-in default pipeline
- Every other key merges, highest priority first:
  1. command-line flags
  2. environment variables
  3. configuration file
  4. built-in defaults

## File Location

The path is resolved before any other configuration is read:

1. `-c <path>`, `--config <path>`, or their `=<path>` forms (last one wins)
2. `$LOGWISP_CONFIG_FILE`, joined onto `$LOGWISP_CONFIG_DIR` when both are set
3. `$LOGWISP_CONFIG_DIR/logwisp.toml`
4. `~/.config/logwisp/logwisp.toml`, if it exists
5. `./logwisp.toml`

Missing file behaviour differs by how it was chosen. An explicitly requested
file that does not exist is a fatal error (exit code 2); a missing discovered
default is not an error, and LogWisp starts on built-in defaults.

File-selection flags are consumed before schema overrides are parsed. A missing
or empty path is a usage error; `--` stops option parsing. The selected path is
runtime metadata and cannot be redirected by a `config_file` key inside the file.

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

Environment overrides are derived from the TOML path: `.` becomes `_`, the
result is uppercased, and `LOGWISP_` is prepended.

| TOML path | Environment variable |
|-----------|---------------------|
| `quiet` | `LOGWISP_QUIET` |
| `status_reporter` | `LOGWISP_STATUS_REPORTER` |
| `logging.level` | `LOGWISP_LOGGING_LEVEL` |
| `logging.file.directory` | `LOGWISP_LOGGING_FILE_DIRECTORY` |

Migration: the old custom transform accidentally read bare names such as `QUIET`
and `LOGGING_LEVEL`. Rename those variables to their prefixed forms; bare names
are now ignored. `LOGWISP_CONFIG_FILE` and `LOGWISP_CONFIG_DIR` still select the
file directly.

Only scalar paths that exist in the configuration schema can be set this way.
Array elements cannot: `LOGWISP_PIPELINES_0_NAME` has no effect. A whole
pipeline can: see [pipeline variables](cli.md#pipeline-variables).

## Command-Line Overrides

Any scalar configuration path is settable as a flag using its TOML path:

```bash
lw --logging.level=debug --status_reporter=false
lw --logging.level debug          # space form also works
lw --quiet                        # bare flag means true
```

Unrecognized flags are reported on stderr before the logger exists and are then
ignored:

```
Warning: unrecognized flags ignored: [pipelines.0.name]
```

Array-indexed paths such as `--pipelines.0.name=x` are unrecognized; whole
pipelines have [their own flags](cli.md#pipelines).

## Validation

Startup validation is intentionally split.

`internal/config` validates only global structure:

- no key the file schema does not declare, at any depth outside a plugin's
  `config` table: `config file "…": unknown key
  "pipelines[0].plugin_sinks[0].confg"`. A misspelled table path would otherwise
  drop the whole table it heads. A top-level `config_file` is ignored
- pipeline [specs](cli.md#pipelines): syntax, and unknown flow-stage keys such
  as `--rate-limit rate=1,polcy=drop`
- at least one pipeline
- unique, non-empty pipeline names
- at least one source and one sink per pipeline
- `logging.output`, `logging.level`, `logging.format`, `logging.sanitization`,
  and `logging.console.target` enum membership

Everything else is validated by the plugin constructor that owns it — port
range, required paths, path prefixes, enum values, regex compilation, TLS and
credentials file loading. A failure there aborts pipeline construction with a
message naming the pipeline, plugin id, and offending key. A key the plugin does
not declare, at any depth, is such a failure (`unknown key "tls.enabeld"`): a
misspelled option must not silently fall back to its default. For the same
reason an `auth` block that names peers or credentials (`allow`,
`allow_patterns`, `credentials_file`, `token_lifetime_ms`, `username`,
`password_file`, `trusted_proxies`) while its `type` is `none` or unset is refused: auth was
intended and the type forgotten. See [Security](security.md#the-auth-block).

There is **no** cross-pipeline port-conflict detection. Two sinks bound to the
same port fail at listener bind time, when the pipeline starts.

## Hot Reload

```toml
auto_reload = true
```

or send `SIGHUP` / `SIGUSR1`. Signals reread the selected file even when watching
is disabled and always rebuild, allowing certificate and credentials rotation
without TOML edits; `auto_reload` watches only the configuration file.
CLI and environment overrides, pipelines included, are captured at startup and
keep their precedence.

Reload rebuilds the whole service: a new service is constructed from the new
configuration first, and only if that succeeds is the old one shut down. Each
candidate is a detached snapshot and runs top-level validation again. Parse,
conversion, validation and construction errors leave the running service intact.
Listener bind/start failures occur after shutdown of the old service and can leave
the application without working pipelines; correct the file and signal again.

Watch errors (including deletion, permission changes and timeout) are logged
without rebuilding. Queued path changes are combined, and unchanged pipelines
and status settings do not trigger another rebuild. Removed file keys fall back
to the remaining sources on the next successful load.

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
| Array | `[]T` | Only in [pipeline specs](cli.md#pipelines): a repeated key |
| Table | struct | Nested path with `.` (flags) or `_` (environment) |

Integer fields reject fractions, overflow and negative unsigned values. Non-finite
floats and integer-to-float precision loss are rejected too. This applies to plugin
maps when their constructors decode them. Only TOML configuration files are accepted;
JSON log formatting and network payloads are unaffected.
