# Command Line Interface

```
logwisp [options]
logwisp auth <command> [flags]
logwisp help | -h | --help
logwisp --version
```

`logwisp auth` manages SCRAM credentials and logs in to `scram` listeners; see
[below](#logwisp-auth). There is no certificate-generation command: use
`openssl` or your PKI tooling — see [Security](security.md#enabling-mtls).

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
| `--config <path>` / `--config=<path>` | Configuration file | `./logwisp.toml` |
| `--quiet` | Suppress all application output | `false` |
| `--status_reporter=<bool>` | Periodic status logging | `true` |
| `--auto_reload=<bool>` | Reload config when the file changes | `false` |
| `--version` | Print version and exit | — |
| `-h`, `--help`, `help` | Print usage and exit | — |

The last file-selection flag wins. `-c=<path>` also works. A missing or empty
path returns an error, and `--` ends option parsing.

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

Configuration paths map to environment variables by replacing `.` with `_`,
uppercasing and adding `LOGWISP_`:

```bash
export LOGWISP_QUIET=true
export LOGWISP_LOGGING_LEVEL=debug
export LOGWISP_LOGGING_FILE_DIRECTORY=/var/log/logwisp
```

Bare names used by older versions are now ignored. Rename them to the prefixed
forms when upgrading; see [Configuration](configuration.md#environment-variables).

The path resolver reads these variables directly:

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

## `logwisp auth`

Manages the credentials files of `auth.type = "scram"` listeners and logs in to
them as a viewer. See
[Password Authentication](security.md#password-authentication-scram).

| Command | Does |
|---------|------|
| `add-user -credentials FILE -user NAME [-password-file FILE] [-generate]` | Adds a user, or replaces its password |
| `remove-user -credentials FILE -user NAME` | Removes a user; refuses the last one |
| `token -url https://HOST:PORT[/PATH] -user NAME -password-file FILE [-unbound] [TLS flags]` | Logs in to an `http` sink or `http_chain` source and prints a bearer token |
| `stream -addr HOST:PORT -user NAME -password-file FILE [TLS flags]` | Logs in to a `tcp` sink and copies its stream to stdout until interrupted |

`logwisp auth <command> -h` lists a command's flags. The exit status is `0` on
success, `1` on failure and `2` on a usage error.

**`add-user`** creates the credentials file, with a fresh `decoy_key`, when it
does not exist or is empty (create it empty first to choose its owner). The password comes from `-password-file` when that file exists
(at least 8 bytes; one trailing line break is trimmed). Otherwise a random
26-character password (130 bits) is generated and written to `-password-file`,
or printed once to stdout when there is none. Replacing an existing user's
password needs an existing `-password-file` or `-generate`, so a mistyped path
cannot replace a working password; `-generate` always generates, overwriting
`-password-file`. New users take the file's existing Argon2 profile.

Both file commands rewrite atomically (a temporary file in the same directory
as the file, or a symlink's target, then a rename), create files `0600`, keep an
existing file's mode and owner, and refuse to write anything the daemon would
not load. A change that cannot keep the owner fails: run it as root or as the
owner.
Neither touches a running LogWisp: send `SIGHUP`, since `auto_reload` does not
watch the credentials file.

**`token`** and **`stream`** build the same TLS and SCRAM client as a chain
sink. TLS flags: `-ca-file` (default: system roots), `-server-name` (default:
the host), and `-cert-file` / `-key-file` for a listener with `tls.client_auth`.
There is no flag to skip verification: an unverified server could relay the
login. Redirects are not followed. `-unbound` logs in to an `http` sink behind
a TLS-terminating proxy (`auth.trusted_proxies`), still pinning the proxy's
certificate across the two requests; only then may `-url` carry the path the
proxy mounts LogWisp at. `stream` exits `0`
on `SIGINT` or `SIGTERM`, and `1` when the server ends the stream (a reload or
shutdown).

```bash
# listener host: a file the service user can read, users, then apply
install -m 0640 -o root -g logwisp /dev/null /etc/logwisp/users.toml
logwisp auth add-user -credentials /etc/logwisp/users.toml -user edge-01 \
  -password-file /etc/logwisp/edge-01.pass
logwisp auth add-user -credentials /etc/logwisp/users.toml -user viewer \
  -password-file viewer.pass
kill -HUP $(pidof logwisp)

# rotate: new password into the file; SIGHUP, deploy the file, SIGHUP the edge
logwisp auth add-user -credentials /etc/logwisp/users.toml -user edge-01 \
  -password-file /etc/logwisp/edge-01.pass -generate

# http sink status, with the token kept out of curl's argv
curl --cacert ca.crt -H @<(printf 'Authorization: Bearer %s\n' \
  "$(logwisp auth token -url https://HOST:PORT -user viewer \
     -password-file viewer.pass -ca-file ca.crt)") https://HOST:PORT/status

# follow a tcp sink
logwisp auth stream -addr HOST:PORT -user viewer -password-file viewer.pass \
  -ca-file ca.crt
```
