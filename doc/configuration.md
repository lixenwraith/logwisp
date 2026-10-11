# Configuration Reference

LogWisp is configured with TOML. A complete annotated file listing every option
and its default ships as [`config/logwisp.toml`](../config/logwisp.toml).

## Configuration Precedence

- Pipelines come from the first of these that defines any, replacing the rest
  wholesale:
  1. pipeline flags: `--source`, `--sink`, ... ([CLI](cli.md#pipelines))
  2. pipeline variables: `LOGWISP_SOURCE`, ...
     ([CLI](cli.md#pipeline-variables))
  3. the file's `[[pipelines]]`
  4. the built-in `pipe` pipeline ([CLI](cli.md#built-in-defaults))
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

A file named by `-c` or a variable must exist (exit code 2); a missing
discovered one is not an error, and lw runs on built-in defaults. A relative
path that climbs with `..` is refused; give it absolute. A file may hold at
most 10 MiB.

## Global Settings

Top-level keys, each as type and default:

- `quiet` (bool, `false`): disable all application logging and console
  diagnostics; pipeline output still flows. It overrides every logging
  setting.
- `status_reporter` (bool, `true` with a configuration file, `false` without):
  a status report every 30 s, shown only at `logging.level = "debug"`.
- `auto_reload` (bool, `false`): watch the config file and reload pipelines on
  change.
- `color` (string, `"auto"`): level names in color on console sinks, which may
  set their own: `"auto"` (a terminal, `NO_COLOR` unset, `TERM` not `dumb`),
  `"always"` or `"never"`; see the [console sink](sinks.md#console).

`--version`, `--check`, `--dump`, `--schema` and `--tui` are switches, not
settings; the matching variables are ignored.

## Application Logging

This configures LogWisp's own operational log, not the log data it transports.
It goes to stderr by default, so stdout carries only a console sink's data.

```toml
[logging]
output = "stderr"      # file | stdout | stderr | split | all | none
level  = "info"        # debug | info | warn | error; warn without a file
format = "txt"         # raw | txt | json
# sanitization = ""    # raw | json | txt | shell

[logging.file]
directory         = "./log"
name              = "logwisp"
max_size_mb       = 100
max_total_size_mb = 1000
retention_hours   = 168.0
```

`output` modes:

- `file`: files only.
- `stdout`: standard output only.
- `stderr`: standard error only.
- `split`: DEBUG/INFO to stdout, WARN/ERROR to stderr.
- `all`: files plus split console.
- `none`: no application logging.

`[logging.file]` applies only to the `file` and `all` modes. Its limits delete
any `.log` file in `directory`, lw's or not: give lw a directory of its own.
`retention_hours = 0` keeps files. The `stdout`, `split` and `all` modes mix
the log into a console sink's stdout. `[logging.console].target` is validated
(`stdout`, `stderr`, `split`) but not applied: `logging.output` chooses the
console.

## Pipeline Configuration

```toml
[[pipelines]]
name = "app"                       # required, unique across pipelines

# --- flow: everything between sources and sinks ---
[pipelines.flow.rate_limit]
entries_per_second   = 1000.0
burst_entries        = 2000.0
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
id   = "app_logs"                  # unique among the pipeline's sources
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

- `id`: instance identifier, unique among the pipeline's sources, and among
  its sinks; appears in logs and stats.
- `type`: registered plugin type.
- `config`: plugin-specific table; see [Sources](sources.md) and
  [Sinks](sinks.md).

`config_file` on a source or sink is accepted and ignored.

### Flow stages

Every stage is optional:

- `flow.rate_limit`: see [Rate limiting](#rate-limiting).
- `flow.filters`: see [Filters](filters.md).
- `flow.format`: defaults to `raw`; see [Formatters](formatters.md).
- `flow.heartbeat`: see [Heartbeat](#heartbeat).

#### Rate limiting

Options, each as type and default:

- `entries_per_second` (float, `0`): `0` disables the limiter; a negative value
  is refused.
- `burst_entries` (float, `entries_per_second`): token bucket capacity.
- `policy` (string, `pass`): `pass` or `drop`, in lower case like every enum.
  `drop` discards entries over the rate or the size cap; `pass` lets
  everything through.
- `max_entry_size_bytes` (int, `0`): per-entry byte cap; `0` = unlimited.

The limiter, its size cap included, acts only with `entries_per_second > 0`
and `policy = "drop"`.

#### Heartbeat

Options, each as type and default:

- `enabled` (bool, `false`): enable heartbeat generation.
- `interval_ms` (int, `1000`): interval; minimum `100`.
- `include_timestamp` (bool, `false`): `false` writes the level only, no
  timestamp; the `raw` format shows neither.
- `include_stats` (bool, `false`): add `type = "heartbeat"`, `beat_count` and,
  from the second beat, the measured `interval_ms` as fields.
- `format` (string, `txt`): `txt`, `json` or `raw`; no effect: heartbeats go
  through the flow's `format`.

Heartbeats are ordinary entries with source `heartbeat` and level `INFO`. They
are generated after the flow's filter and rate-limit stages, so filters do not
suppress them, and they reach every sink in the pipeline.

## Environment Variables and Flags

Every setting is also a variable and a flag by its path: `logging.level` is
`LOGWISP_LOGGING_LEVEL` and `--logging.level`. Pipelines are not: their flags
and variables replace the file's whole, and an array-indexed path such as
`--pipelines.0.name=x` is an unknown option (exit code 2). See
[CLI](cli.md#options) and [Environment Variables](cli.md#environment-variables).

## Validation

The configuration is checked offline when it loads, at every reload and by
`lw --check`. Each check reports the first problem of each table (the top
level, `logging`, each flow stage, each source and sink) by its key's path:

```
Error: Failed to load config: invalid configuration:
pipelines[0].flow.rate_limit.policy: must be one of pass, drop, got "Drop"
pipelines[0].plugin_sinks[http].config: unknown key "tls.enabeld"
```

- Pipeline flags and variables come first, alone: their syntax and keys
  (`--rate-limit entries_per_second=1,polcy=drop: unknown key "polcy"`).
- Settings: the `color` enum and the `logging` ones (`output`, `level`,
  `format`, `sanitization`, `console.target`).
- Pipelines: at least one; names set and unique; a source and a sink each;
  ids unique among a pipeline's sources and among its sinks; one `console`
  source in the whole configuration.
- Plugin options are decoded in full: unknown keys at any depth, kinds,
  required keys, enums, ranges, paths, and the `tls`, `auth` and `acl` rules
  of the plugin's side; a `tls` table's rules only when it is `enabled`.
- Enums are case-sensitive: `policy = "Drop"` and `target = "STDERR"` are
  refused.
- In plugin options and flow stages, `0`, or `""` for a string, takes the
  key's default, or the meaning its help gives zero (off, none, unlimited). A
  number below its key's minimum is refused, a negative one included where
  zero means the default (`buffer_size = -1`).
- Flow stages are checked whether enabled or not: kinds, enums and ranges,
  and filter patterns must compile ([Filters](filters.md)).
- `auth` enums (`identity`, `node_binding`) are checked whatever `type` is; a
  block naming peers or credentials with `type` `none` or unset is refused
  ([Security](security.md#validation-1)).
- Once the rest is valid, the file itself: the first key the schema does not
  declare outside a plugin's `config` is refused (`config file "…": unknown
  key "pipelines[0].plugin_sinks[0].confg"`), since a misspelled table path
  would drop the whole table it heads. A top-level `config_file`, `version`,
  `check` or `dump` is ignored.
- Files a plugin names (certificates, keys, CA files, credentials, password
  files) are read when it is built: at start, at reload and by `lw --check`.
  Those failures name the pipeline and plugin.

Two listeners on one port pass validation; the second fails at bind and lw
exits 1 ([Networking](networking.md#network-plugins)).

## Hot Reload

`auto_reload = true` watches the configuration file. `SIGHUP` or `SIGUSR1`
rereads it even when watching is off and always rebuilds, so certificates and
credentials rotate without a TOML edit. CLI and environment overrides,
pipelines included, are captured at startup and keep their precedence. A
discovered default file that does not exist is not an error, so an instance
configured by flags or variables alone still rebuilds; once read, though, its
removal fails the reload and the running service stays as it is; restart to
run without the file.

Reload builds a new service from a detached snapshot of the configuration,
validated again, and shuts the old one down only if that succeeds: parse,
validation and construction errors leave the running service intact. Listener
bind failures occur after the old service has stopped and can leave lw without
working pipelines; correct the file and signal again.

Watch errors (deletion, permission changes, timeout) are logged without
rebuilding. Queued changes are combined, and unchanged pipelines and status
settings do not trigger another rebuild. Removed file keys fall back to the
remaining sources on the next successful load.

- Reloaded: pipelines, sources, sinks, flow stages, `status_reporter`, `color`
- Not reloaded: `logging.*` (applied once at startup), `quiet`, `auto_reload`
  (the watcher is not restarted)

The rebuild is total: listeners close and reopen, every connected client is
disconnected, and chain sinks reconnect on their own backoff schedule.

## Type Reference

Each TOML type, its Go type, and its command-line / environment form:

- String (`string`): plain text.
- Integer (`int64`): decimal string.
- Float (`float64`): decimal string.
- Boolean (`bool`): `true` / `false`, or a bare flag for `true`.
- Array (`[]T`): only in [pipeline specs](cli.md#pipelines), as a repeated key.
- Table (struct): nested path with `.` (flags) or `_` (environment).

Integer keys refuse fractions and out-of-range values; number keys refuse inf
and NaN. Configuration files are TOML only.
