# Command Line Interface

```
logwisp [options]
logwisp help | -h | --help
logwisp --version
```

LogWisp has no subcommands. Earlier releases shipped `logwisp auth` and
`logwisp tls` for credential and certificate generation; both were removed
during the restructure. Use `openssl` or your PKI tooling instead — see
[Security](security.md).

## Options

Any scalar configuration key is settable as a flag using its TOML path:

```
--<path>=<value>        e.g. --logging.level=debug
--<path> <value>        e.g. --logging.level debug
--<path>                bare flag, means true
```

### Common

| Flag | Description | Default |
|------|-------------|---------|
| `-c <path>` | Configuration file | `./logwisp.toml` |
| `--config=<path>` | Configuration file (equals form only) | `./logwisp.toml` |
| `--quiet` | Suppress all application output | `false` |
| `--status_reporter=<bool>` | Periodic status logging | `true` |
| `--auto_reload=<bool>` | Reload config when the file changes | `false` |
| `--version` | Print version and exit | — |
| `-h`, `--help`, `help` | Print usage and exit | — |

> `--config <path>` with a space is not recognized. The path resolver
> understands `-c <path>` and `--config=<path>` only; the space form is treated
> as an unknown flag, warned about, and ignored, after which LogWisp silently
> falls back to `./logwisp.toml`.
>
> `-c` as the final argument, with no path after it, crashes with an index
> panic rather than reporting a usage error.

### Logging

| Flag | Values |
|------|--------|
| `--logging.output` | `file`, `stdout`, `stderr`, `split`, `all`, `none` |
| `--logging.level` | `debug`, `info`, `warn`, `error` |
| `--logging.format` | `raw`, `txt`, `json` |
| `--logging.sanitization` | `raw`, `json`, `txt`, `shell` |
| `--logging.file.directory` | path |
| `--logging.file.name` | string |
| `--logging.file.max_size_mb` | integer |
| `--logging.file.max_total_size_mb` | integer |
| `--logging.file.retention_hours` | float |

`--logging.console.target` is accepted but has no effect; the console
destination is derived from `--logging.output`.

### Pipelines

Pipelines, sources, sinks, and filters **cannot** be configured from the command
line. Array-indexed paths such as `--pipelines.0.name=app` or
`--pipelines.0.plugin_sinks.0.type=null` are reported as unrecognized and
ignored:

```
Warning: unrecognized flags ignored: [pipelines.0.name]
```

Use a configuration file. Older documentation described CLI pipeline overrides
that the current loader does not implement.

## Environment Variables

Configuration paths map to environment variables by replacing `.` with `_` and
uppercasing:

```bash
export QUIET=true
export LOGGING_LEVEL=debug
export LOGGING_FILE_DIRECTORY=/var/log/logwisp
```

> The `LOGWISP_` prefix is **not** currently applied to these — see
> [Configuration](configuration.md#environment-variables). Bare names like
> `QUIET` are what LogWisp actually reads, which is worth knowing both to make
> overrides work and to avoid accidental collisions.

The two variables that do carry the prefix are read directly by the path
resolver:

| Variable | Effect |
|----------|--------|
| `LOGWISP_CONFIG_FILE` | Configuration file path; joined onto `LOGWISP_CONFIG_DIR` when both are set |
| `LOGWISP_CONFIG_DIR` | Configuration directory; alone, implies `<dir>/logwisp.toml` |

As with flags, array elements cannot be set this way.

## Precedence

1. Command-line flags
2. Environment variables
3. Configuration file
4. Built-in defaults

## Signals

| Signal | Action |
|--------|--------|
| `SIGINT` | Graceful shutdown |
| `SIGTERM` | Graceful shutdown |
| `SIGHUP` | Reload configuration |
| `SIGUSR1` | Reload configuration |

`SIGHUP` is ignored during startup, before the signal handler is installed, so
LogWisp survives a terminal hang-up like `nohup`. Once running, it triggers a
reload rather than terminating.

Reload rebuilds the whole service. A configuration error leaves the running
service untouched; see [Configuration](configuration.md#hot-reload).

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean shutdown, or `--version` / `--help` |
| `1` | General error: config load or validation failure, logger init failure, service bootstrap failure |
| `2` | Explicitly requested configuration file not found |

Exit code 2 applies only when the file was named explicitly (`-c`,
`--config=`, or the `LOGWISP_CONFIG_*` variables). A missing discovered default
is not an error, and LogWisp starts on built-in defaults.

## Built-in Defaults

With no configuration file present, LogWisp runs one pipeline named
`default_pipeline`: a `random` source with `special = true`, JSON formatting,
a rate limit of 5 entries/second with a burst of 10 and `policy = "drop"`, and a
`console` sink on stdout. It is a self-demonstrating idle mode, not a useful
production configuration.

Note that as soon as your file defines `[[pipelines]]`, that entire default
pipeline — rate limit included — is replaced rather than merged.

## Usage Patterns

**Development**

```bash
# verbose, everything to stderr
logwisp -c dev.toml --logging.output=stderr --logging.level=debug

# no config at all: synthetic generator to stdout
logwisp
```

**Configuration check**

```bash
# starts the service; a config error exits non-zero before any pipeline runs
logwisp -c /etc/logwisp/logwisp.toml --logging.level=debug
```

There is no dry-run or validate-only mode. The closest approximation is starting
with debug logging and stopping once the pipelines report as started.

**Production**

```bash
logwisp -c /etc/logwisp/logwisp.toml --logging.output=file
```

Run under a supervisor (systemd, rc.d) rather than backgrounding it — there is
no `--background` flag; earlier releases had one and it was removed. See
[Installation](installation.md).

**Reload**

```bash
kill -HUP  $(pidof logwisp)
kill -USR1 $(pidof logwisp)
```
