# Command Line Interface

```
lw [options] [< input]
lw -c <file> [options]
lw --check [options]
lw auth <command> [flags]
lw help | -h | --help
lw --version
```

Without a configuration file or pipeline options, lw is a filter: stdin to
stdout, line for line, until the end of input ([Built-in
Defaults](#built-in-defaults)). With a file it runs the file's pipelines as a
service.

`lw auth` manages SCRAM credentials and logs in to `scram` listeners; see
[below](#lw-auth). There is no certificate-generation command: use
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

- `-c <path>`, `--config <path>`, `--config=<path>`: the configuration file;
  unnamed, `~/.config/logwisp/logwisp.toml` if it exists, else
  `./logwisp.toml` ([Configuration](configuration.md#file-location))
- `--check`: build every pipeline and plugin, bind nothing, report and exit;
  see [Usage Patterns](#usage-patterns)
- `--quiet`: silence lw's own log and notices, default `false`; pipeline
  output still flows
- `--status_reporter=<bool>`: periodic status logging, default `true` with a
  configuration file, `false` without
- `--auto_reload=<bool>`: reload when the configuration file changes, default
  `false`
- `--version`: print the version and exit
- `-h`, `--help`, `help`: print usage and exit

The last file-selection flag wins. `-c=<path>` also works. A missing or empty
path returns an error, and `--` ends option parsing.

### Logging

- `--logging.output`: `file`, `stdout`, `stderr`, `split`, `all` or `none`,
  default `stderr`, so stdout carries only data
- `--logging.level`: `debug`, `info`, `warn` or `error`, default `info` with a
  configuration file, `warn` without
- `--logging.format`: `raw`, `txt` or `json`
- `--logging.sanitization`: `raw`, `json`, `txt` or `shell`
- `--logging.file.directory`: a path
- `--logging.file.name`: a string
- `--logging.file.max_size_mb`, `--logging.file.max_total_size_mb`: integers
- `--logging.file.retention_hours`: a float

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
- a pipeline without `--source` reads stdin (console source `stdin`), one
  without `--sink` writes stdout (console sink `stdout`)
- stdin has one reader, so the whole configuration holds at most one console
  source: `pipeline "b": a console source already reads stdin in pipeline "a"`

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
  - each value is one list entry, commas included: `auth.allow_patterns=^a{1\,3}$`
    is one regex, `auth.allow=a,auth.allow=b` two entries
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
# tail a directory, serve it over SSE on every interface
lw --source 'file,directory=/var/log/app,pattern=*.log' \
   --sink http,host=0.0.0.0,port=8080

# errors and warnings as JSON, over TLS with SCRAM logins
lw --source file,directory=/var/log/app \
   --filter include,patterns=ERROR,patterns=WARN --format json \
   --sink "http,port=8443,auth.type=scram,auth.credentials_file=/etc/logwisp/users.toml,\
tls.enabled=true,tls.cert_file=/etc/logwisp/server.crt,tls.key_file=/etc/logwisp/server.key"

# two pipelines: app writes stdout, relay a file
lw --pipeline app --source file,directory=/var/log/app \
   --pipeline relay --source tcp_chain,port=9000 \
   --sink file,directory=/var/log/relay,name=relay
```

Pipelines over stdin and stdout are under [Usage Patterns](#usage-patterns).

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

- `LOGWISP_CONFIG_FILE`: the configuration file path, joined onto
  `LOGWISP_CONFIG_DIR` when both are set
- `LOGWISP_CONFIG_DIR`: the configuration directory; alone, it implies
  `<dir>/logwisp.toml`

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
  -e LOGWISP_LOGGING_LEVEL=info \
  logwisp
```

Without a file, lw logs at `warn` with no status reporter, so a container
configured through the environment passes `LOGWISP_LOGGING_LEVEL=info` (and
`LOGWISP_STATUS_REPORTER=true`) to keep the service defaults. The image does
not set them: environment variables would override a mounted file's values.

## Precedence

- Pipelines
  - pipeline flags, if any are given
  - else pipeline variables, if any are set
  - else the configuration file's `[[pipelines]]`
  - else the built-in `pipe` ([Built-in Defaults](#built-in-defaults))
- Every other key
  1. command-line flags
  2. environment variables
  3. configuration file
  4. built-in defaults; `logging.level` and `status_reporter` depend on
     whether a file was found

A reload rereads the file and keeps the command-line or environment pipelines.

## Signals

- `SIGINT`, `SIGTERM`: graceful shutdown
- `SIGHUP`, `SIGUSR1`: reload the configuration

`SIGHUP` is ignored during startup, before the signal handler is installed, so
LogWisp survives a terminal hang-up like `nohup`. Once running, it triggers a
reload rather than terminating.

Reload rebuilds the whole service. A configuration error leaves the running
service untouched; see [Configuration](configuration.md#hot-reload).

## Exit Codes

- `0`: the end of input, a clean shutdown (`SIGINT`, `SIGTERM`), `--version` /
  `--help`, or a valid `--check`
- `1`: general error: a configuration load or validation failure (`--check`
  included), a logger init failure, a service bootstrap failure
- `2`: an explicitly requested configuration file is not found
- killed by `SIGPIPE` (shell status `141`): the reader of stdout went away, as
  in `lw | head`; `cat` ends the same way

Exit code 2 applies only when the file was named explicitly (`-c`,
`--config=`, or the `LOGWISP_CONFIG_*` variables). A missing discovered default
is not an error, and LogWisp starts on built-in defaults.

## Built-in Defaults

Without a configuration file and without pipeline flags or variables, lw runs
one built-in pipeline, `pipe`: console source `stdin`, `raw` format, console
sink `stdout`, no filter, no rate limit. lw is then a Unix filter, like `cat`:

```bash
lw < app.log > copy.log
```

- Each line of stdin is one entry and one line of stdout.
  - The terminator (`\n` or `\r\n`) is written back as `\n`; an unterminated
    last line is kept and terminated.
  - Blank lines are skipped.
  - A line over 1 MiB continues in the next entry; no byte is lost.
- Nothing is dropped: a slow reader slows the reading of stdin.
- On a terminal, control characters are written as `<hex>` (`ESC` becomes
  `<1b>`); pipes and files get the bytes unchanged
  ([console sink](sinks.md#console)).
- When a console source reads a terminal, lw says so once on stderr, unless
  `--quiet`: `lw: reading standard input; Ctrl-D ends it (lw --help for usage)`.

A file that defines no `[[pipelines]]` still runs `pipe`. The file's
`[[pipelines]]`, or pipeline flags or variables, replace it whole.

Without a file lw also logs less: `logging.level` defaults to `warn` and
`status_reporter` to `false`, against `info` and `true` with one. Explicit
values from the file, the environment or flags win.

**End of input.** When stdin ends, the console source ends. A pipeline
finishes when all its sources have ended, and once every pipeline has
finished lw shuts down gracefully and exits 0. Only a console source ends on
its own: file and network sources run until a signal, and so does a pipeline
holding one. Console and file sinks write what is queued before the
exit. The `http` and `tcp` sinks do not yet flush their clients' queues, so a
connected client can miss the last entries of a finite input
([To Do](todo.md)).

## Usage Patterns

**Filter**

```bash
# copy, line for line; exits 0 at the end of input
lw < app.log > copy.log

# errors and warnings only
tail -F app.log | lw --filter include,patterns=ERROR,patterns=WARN

# stdin as a live SSE stream; the http and tcp sinks bind 0.0.0.0 by default
journalctl -f | lw --sink http,host=127.0.0.1,port=8080

# a directory's files to one file, through stdout
lw --source file,directory=/var/log/app,pattern='*.log' > all.log
```

A console sink never drops: when its reader is slow, the pipeline waits, and
so does the reading of stdin.

**Development**

```bash
# a file's pipelines, verbose
lw -c dev.toml --logging.level=debug
```

**Configuration check**

`lw --check` validates without running: it builds every pipeline and plugin as
a start would (options, TLS files, credentials files, startup warnings), but
binds no port, reads no stdin, and opens, reads or creates no log file; it
prints `configuration ok: N pipeline(s)` and exits 0, or the error and exits 1
(2 when a named file is missing, see [Exit Codes](#exit-codes)):

```bash
lw --check -c /etc/logwisp/logwisp.toml
lw --check --source file,directory=/var/log/app --sink http,port=8080
```

**Production**

```bash
lw -c /etc/logwisp/logwisp.toml --logging.output=file
```

Run it in the foreground under a supervisor (systemd, rc.d, a container
runtime); there is no `--background` flag. A supervisor's stdin is usually
`/dev/null`, where a console source ends at once, so a service's file defines
its pipelines. See [Operations](operations.md#starting) and
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

```
lw auth add-user    -credentials FILE -user NAME [-password-file FILE] [-generate]
lw auth remove-user -credentials FILE -user NAME
lw auth token       -url https://HOST:PORT[/PATH] -user NAME -password-file FILE
                    [-unbound] [TLS flags]
lw auth stream      -addr HOST:PORT -user NAME -password-file FILE [TLS flags]
```

- `add-user`: adds a user, or replaces its password
- `remove-user`: removes a user; refuses the last one
- `token`: logs in to an `http` sink or `http_chain` source and prints a
  bearer token
- `stream`: logs in to a `tcp` sink and copies its stream to stdout until
  interrupted

`lw auth <command> -h` lists a command's flags. The exit status is `0` on
success, `1` on failure and `2` on a usage error.

**`add-user`** creates the credentials file, with a fresh `decoy_key`, when it
does not exist or is empty (create it empty first to choose its owner). The
password comes from `-password-file` when that file exists (at least 8 bytes;
one trailing line break is trimmed). Otherwise a random
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
proxy mounts LogWisp at. `stream` exits `0` on `SIGINT` or `SIGTERM`, and `1`
when the server ends the stream (a reload or shutdown).

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
