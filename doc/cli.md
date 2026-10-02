# Command Line Interface

```
lw [options]
lw auth <command> [flags]
lw help | -h | --help
lw --version
```

`lw auth` manages SCRAM credentials and logs in to `scram` listeners; see
[below](#logwisp-auth). There is no certificate-generation command: use
`openssl` or your PKI tooling — see [Security](security.md#enabling-mtls).

## Options

Any scalar configuration key is settable as a flag using its TOML path;
pipelines have [their own flags](#pipelines):

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

Pipeline flags define whole pipelines. They replace the configuration file's
pipelines and the built-in default; every other key keeps its precedence.

- `--pipeline NAME` starts a pipeline; specs before the first one go to a
  pipeline named `cli`
- `--source SPEC`, `--sink SPEC` and `--filter SPEC` add a stage, repeatable
- `--format SPEC`, `--rate-limit SPEC` and `--heartbeat SPEC`, once per pipeline
- both `--flag SPEC` and `--flag=SPEC` work; `--` ends options

A SPEC is a comma-separated list:

- source, sink, filter and format specs start with a TYPE
  - the plugin type: [Sources](sources.md), [Sinks](sinks.md)
  - `include` or `exclude`: [Filters](filters.md)
  - `json`, `txt` or `raw`: [Formatters](formatters.md)
- rate-limit and heartbeat specs have no TYPE
- the rest are `key=value` pairs with the TOML keys of the plugin's `config`
  table or of the [flow stage](configuration.md#flow-stages)
  - a dotted key reaches a nested table: `tls.cert_file=...`, `auth.type=scram`
  - a repeated key makes a list: `patterns=ERROR,patterns=WARN`
  - a plugin's list option given once splits at commas: `auth.allow=a\,b` is
    two entries; a filter's `patterns` value is always one regex
  - values convert to the option's type: `port=8080`, `raw=true`
- `\` escapes `,`, `=` and `\` in a value; any other backslash stays, so regex
  escapes such as `\d` pass unchanged
- `id=NAME` names a source or sink; the default is its TYPE, then `TYPE_2`,
  `TYPE_3`, ...
- naming a stage turns it on: `--rate-limit` defaults `policy` to `drop`,
  `--heartbeat` defaults `enabled` to `true`

Errors name the flag and the offending part, and nothing starts:

```
--sink http,port: missing "="
--rate-limit rate=100,polcy=drop: unknown key "polcy"
```

A misspelled plugin key fails when the plugin is built, before any listener
opens: `failed to create sink http: ... unknown key "tls.enabeld"`.

```bash
# tail a directory, serve it over SSE
lw --source 'file,directory=/var/log/app,pattern=*.log' \
   --sink http,host=0.0.0.0,port=8080

# errors and warnings as JSON, over TLS with SCRAM logins
lw --source file,directory=/var/log/app \
   --filter include,patterns=ERROR,patterns=WARN --format json \
   --sink "http,port=8443,auth.type=scram,auth.credentials_file=/etc/logwisp/users.toml,\
tls.enabled=true,tls.cert_file=/etc/logwisp/server.crt,tls.key_file=/etc/logwisp/server.key"

# two pipelines
lw --pipeline app --source file,directory=/var/log/app --sink console \
   --pipeline relay --source tcp_chain,port=9000 \
   --sink file,directory=/var/log/relay,name=relay
```

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

### Pipeline Variables

One pipeline can come from the environment, with the [SPEC](#pipelines) syntax.
Any pipeline flag on the command line makes LogWisp ignore all of them.

- `LOGWISP_PIPELINE`: the pipeline's name, default `cli`
- `LOGWISP_SOURCE`, `LOGWISP_SINK`, `LOGWISP_FILTER`: one stage each
  - `LOGWISP_SOURCE_1` .. `LOGWISP_SOURCE_N` add more, after the unnumbered
    one in numeric order; likewise `LOGWISP_SINK_N` and `LOGWISP_FILTER_N`
- `LOGWISP_FORMAT`, `LOGWISP_RATE_LIMIT`, `LOGWISP_HEARTBEAT`
- an empty variable counts as unset

A container needs no configuration file:

```bash
docker run --rm -p 8080:8080 -v /var/log/app:/logs:ro \
  -e LOGWISP_PIPELINE=app \
  -e LOGWISP_SOURCE='file,directory=/logs,pattern=*.log' \
  -e LOGWISP_FILTER='exclude,patterns=DEBUG' \
  -e LOGWISP_SINK='http,host=0.0.0.0,port=8080' \
  -e LOGWISP_SINK_1=console \
  logwisp
```

## Precedence

- Pipelines
  - pipeline flags, if any are given
  - else pipeline variables, if any are set
  - else the configuration file's `[[pipelines]]`
  - else the built-in default
- Every other key
  1. command-line flags
  2. environment variables
  3. configuration file
  4. built-in defaults

A reload rereads the file and keeps the command-line or environment pipelines.

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

As soon as the file defines `[[pipelines]]`, or pipeline flags or variables are
given, that entire default pipeline — rate limit included — is replaced rather
than merged.

## Usage Patterns

**Development**

```bash
# verbose, everything to stderr
lw -c dev.toml --logging.output=stderr --logging.level=debug

# no config at all: synthetic generator to stdout
lw
```

**Configuration check**

```bash
# starts the service; a config error exits non-zero before any pipeline runs
lw -c /etc/logwisp/logwisp.toml --logging.level=debug
```

`lw --check` validates without running: it builds every pipeline and plugin as
a start would (options, TLS files, credentials files, startup warnings), binds
and reads nothing, prints `configuration ok` and exits 0, or the error and
exits 1:

```bash
lw --check -c /etc/logwisp/logwisp.toml
lw --check --source file,directory=/var/log/app --sink http,port=8080
```

**Production**

```bash
lw -c /etc/logwisp/logwisp.toml --logging.output=file
```

Run under a supervisor (systemd, rc.d) rather than backgrounding it — there is
no `--background` flag; earlier releases had one and it was removed. See
[Installation](installation.md).

**Reload**

```bash
kill -HUP  $(pidof lw)
kill -USR1 $(pidof lw)
```

## `lw auth`

Manages the credentials files of `auth.type = "scram"` listeners and logs in to
them as a viewer. See
[Password Authentication](security.md#password-authentication-scram).

| Command | Does |
|---------|------|
| `add-user -credentials FILE -user NAME [-password-file FILE] [-generate]` | Adds a user, or replaces its password |
| `remove-user -credentials FILE -user NAME` | Removes a user; refuses the last one |
| `token -url https://HOST:PORT[/PATH] -user NAME -password-file FILE [-unbound] [TLS flags]` | Logs in to an `http` sink or `http_chain` source and prints a bearer token |
| `stream -addr HOST:PORT -user NAME -password-file FILE [TLS flags]` | Logs in to a `tcp` sink and copies its stream to stdout until interrupted |

`lw auth <command> -h` lists a command's flags. The exit status is `0` on
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
owner. A symlink to a missing file is refused: create the target first.
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

Addresses, as for the plugins ([Networking](networking.md#address-family)):

- An IPv6 address goes in brackets: `-addr [::1]:PORT`,
  `-url https://[::1]:PORT`; in a URL a link-local zone is escaped,
  `https://[fe80::1%25eth0]:PORT`.
- The dial keeps to the address's family; a hostname resolves.
- `-server-name` defaults to the host; an address, without brackets or zone,
  must then be among the certificate's IP SANs.

```bash
# listener host: a file the service user can read, users, then apply
install -m 0640 -o root -g logwisp /dev/null /etc/logwisp/users.toml
lw auth add-user -credentials /etc/logwisp/users.toml -user edge-01 \
  -password-file /etc/logwisp/edge-01.pass
lw auth add-user -credentials /etc/logwisp/users.toml -user viewer \
  -password-file viewer.pass
kill -HUP $(pidof lw)

# rotate: new password into the file; SIGHUP, deploy the file, SIGHUP the edge
lw auth add-user -credentials /etc/logwisp/users.toml -user edge-01 \
  -password-file /etc/logwisp/edge-01.pass -generate

# http sink status, with the token kept out of curl's argv
curl --cacert ca.crt -H @<(printf 'Authorization: Bearer %s\n' \
  "$(lw auth token -url https://HOST:PORT -user viewer \
     -password-file viewer.pass -ca-file ca.crt)") https://HOST:PORT/status

# follow a tcp sink
lw auth stream -addr HOST:PORT -user viewer -password-file viewer.pass \
  -ca-file ca.crt
```
