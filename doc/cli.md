# Command Line Interface

```
lw [options] [< input]
lw -c|--config FILE [options]
lw -p|--preset NAME[,KEY=VALUE...] [options]
lw -t|--check [options]
lw --dump [options]
lw auth COMMAND [flags]
lw tls COMMAND [flags]
lw preset NAME [flags]
lw help | -h | --help
lw -V | --version
```

Without a configuration file or pipeline options, lw is a filter: stdin to
stdout, line for line, until the end of input ([Built-in
Defaults](#built-in-defaults)). With a file it runs the file's pipelines as a
service.

A [preset](#presets) builds a common pipeline from a few keys. `lw auth`
manages SCRAM credentials and logs in to `scram` listeners
([below](#lw-auth)); `lw tls` makes a certificate authority and certificates
([below](#lw-tls)). A command is recognized only as the first argument.

## Options

- lw's own options have a long form (`--config`), and the frequent ones a
  one-letter short form that stands for it in every command that has it:
  - `-c` `--config`, `-p` `--preset`, `-q` `--quiet`, `-t` `--check`,
    `-V` `--version`, `-h` `--help`
  - `-u` `--user` in `lw auth` and `lw preset edge`
- A value follows as the next argument or after `=` (`-c FILE`, `-c=FILE`,
  `--config FILE`, `--config=FILE`); a value that starts with `-` follows `=`,
  and `--` ends the options.
- Short options do not combine (`-q -t`, not `-qt`) or take an attached value
  (`-cFILE`); an unknown single-dash option is an error.
- lw's multiword options join words with `-` (`--rate-limit`,
  `--password-file`); configuration keys, spec keys and preset keys keep
  TOML's `_` and `.` (`--status_reporter`, `--sink http,tls.cert_file=F`,
  `lw preset edge --password_file F`).
- `lw auth`, `lw tls` and `lw preset` also take a long option after one dash
  (`-user NAME`), as earlier releases documented.

Any scalar configuration key is settable as a flag using its TOML path;
pipelines have [their own flags](#pipelines):

```
--<path>=<value>        e.g. --logging.level=debug
--<path> <value>        e.g. --logging.level debug
--<path>                bare flag: true, for a boolean path only
```

### Common

- `-c FILE`, `--config FILE`: the configuration file; unnamed,
  `~/.config/logwisp/logwisp.toml` if it exists, else `./logwisp.toml`
  ([Configuration](configuration.md#file-location))
- `-t`, `--check`: build every pipeline and plugin, bind nothing, report and
  exit; see [Usage Patterns](#usage-patterns)
- `--dump`: print the effective configuration, flags, environment and presets
  resolved into it, as TOML that `-c` reads back, and exit
- `--color [WHEN]`, WHEN `auto`, `always` or `never`: level names in color on
  console sinks, default `auto` (a terminal, `NO_COLOR` unset, `TERM` not
  `dumb`); bare, `always`. A console sink's own `color` wins
  ([console sink](sinks.md#console))
- `-q`, `--quiet`: silence lw's own log and notices, default `false`;
  pipeline output still flows
- `--status_reporter=BOOL`: periodic status logging, default `true` with a
  configuration file, `false` without
- `--auto_reload=BOOL`: reload when the configuration file changes, default
  `false`
- `-V`, `--version`: print the version and exit
- `-h`, `--help`, `help`: print usage and exit

The last `-c` wins; a missing or empty path is an error.

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
  pipeline named `cli`, or after the preset that starts them
- `-p SPEC`, `--preset SPEC` starts a pipeline with a [preset](#presets);
  later flags add sources, sinks and filters to it, or replace its format,
  rate limit and heartbeat
- `--source SPEC`, `--sink SPEC` and `--filter SPEC` add a stage, repeatable
- `--format SPEC`, `--rate-limit SPEC` and `--heartbeat SPEC`, once per pipeline
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
# tail a directory, serve it over SSE on every interface; a browser at
# http://HOST:8080/ shows it
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

## Presets

`--preset NAME,key=value,...` takes the [SPEC](#pipelines) syntax. A list
key (`hosts`, `proxy`) takes several values, repeated (`hosts=a,hosts=b`) or
`,`-separated; any other key takes one. `lw preset NAME [--key value ...]`
prints the pipeline a preset expands to, ready for a configuration file; its
flags are the keys, spelled as in the SPEC (`--password_file`), and `-u` is
`--user`;
`lw preset NAME -h` lists its keys and defaults, `lw preset` the presets. An
unknown key fails and lists the valid ones. A `path` is a file, a directory
(its files) or a glob; a preset that takes one reads stdin without it, and
`from` (`end`, or `start`) is where reading a file starts.

- `pipe`: stdin to stdout, the built-in default
  - `format` (`raw`)
- `tail`: follow files to stdout, like `tail -F`
  - `path` (required), `from`, `format` (`raw`)
- `serve`: a live stream, an [http sink](sinks.md#http): a browser at
  `listen` gets the viewer, `/stream` is SSE
  - `path`, `from`, `format` (`json`), `listen` (`127.0.0.1:8080`)
  - `tls`: `off` (default), `self` (a self-signed certificate made at
    startup), `issuer` (one signed by `issuer_cert` and `issuer_key`), or
    `files` (`cert` and `key`); `hosts` adds names to a made certificate
  - without `users` the viewer needs no login, over plain http too
  - `users`: a credentials file; readers then log in with SCRAM, and browsers
    need `proxy` and `viewer=true`: the login page and viewer behind the
    TLS-terminating proxies `proxy` names, since a browser cannot bind its
    login to the TLS channel
- `edge`: forward to an aggregator over TLS (`tcp_chain`, or `http_chain`
  with `transport=http`)
  - `to` (required), `path`, `from`, `transport` (`tcp`), `node`
  - verify the aggregator by `ca` (a CA file; default: system roots) or `pin`
    (its `tls.pin_sha256`), and `server_name`
  - authenticate by `user` and `password_file` (SCRAM), or a client `cert` and
    `key` (mTLS): without either the preset refuses to run
- `aggregator`: receive from edges over TLS, to stdout or files
  - `listen` (`0.0.0.0:9000`), `transport` (`tcp`), `format` (`json`)
  - `tls`: `self` (default), `issuer` or `files`, as for `serve`; never `off`
  - authenticate by `users` (SCRAM) or `client_ca` (mTLS): one is required
  - `out`: a directory for `aggregate*.log` files; default stdout

```bash
# follow a directory, level names in color on a terminal
lw --preset tail,path=/var/log/app

# serve it to a browser at http://127.0.0.1:8080/
lw --preset serve,path=/var/log/app

# serve it over HTTPS, self-signed, to SCRAM users; keep the result as a file
lw --preset serve,path=/var/log/app,tls=self,users=/etc/logwisp/users.toml --dump > serve.toml

# an aggregator with a certificate made at startup, and an edge pinning it
lw --preset aggregator,users=/etc/logwisp/users.toml,out=/var/log/edges
lw --preset edge,path=/var/log/app,to=agg.example.org:9000,pin=sha256//BASE64,\
user=edge-01,password_file=/etc/logwisp/edge-01.pass
```

A self-signed aggregator logs its pin at startup (`pin_sha256`, a warning, so
it shows without a configuration file too). The pin holds across reloads and
changes when lw restarts; a fleet signs with an issuer instead, and edges set
`ca`. See [Security](security.md#certificates-made-at-startup).

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
- `LOGWISP_PRESET`: the [preset](#presets) that starts it
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
  `--help`, `--dump`, or a valid `--check`
- `1`: general error: a command-line error (an unknown option, a missing
  `-c` path), a configuration load or validation failure (`--check`
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
  `<1b>`) and level names are in color; pipes and files get the bytes
  unchanged ([console sink](sinks.md#console)).
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
holding one. Every sink writes what is queued before the exit; the `http`
and `tcp` sinks give each connected client `write_timeout_ms`, at most 2 s,
to take it.

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
lw auth add-user    --credentials FILE -u NAME [--password-file FILE] [--generate]
lw auth remove-user --credentials FILE -u NAME
lw auth token       --url https://HOST:PORT[/PATH] -u NAME --password-file FILE
                    [--unbound] [TLS flags]
lw auth stream      --addr HOST:PORT -u NAME --password-file FILE [TLS flags]
```

`-u` is short for `--user`.

- `add-user`: adds a user, or replaces its password
- `remove-user`: removes a user; refuses the last one
- `token`: logs in to an `http` sink or `http_chain` source and prints a
  bearer token
- `stream`: logs in to a `tcp` sink and copies its stream to stdout until
  interrupted

`lw auth COMMAND -h` lists a command's flags. The exit status is `0` on
success, `1` on failure and `2` on a usage error.

**`add-user`** creates the credentials file, with a fresh `decoy_key`, when it
does not exist or is empty (create it empty first to choose its owner). The
password comes from `--password-file` when that file exists (at least 8 bytes;
one trailing line break is trimmed). Otherwise a random
26-character password (130 bits) is generated and written to `--password-file`,
or printed once to stdout when there is none. Replacing an existing user's
password needs an existing `--password-file` or `--generate`, so a mistyped path
cannot replace a working password; `--generate` always generates, overwriting
`--password-file`. New users take the file's existing Argon2 profile.

Both file commands rewrite atomically (a temporary file in the same directory
as the file, or a symlink's target, then a rename), create files `0600`, keep an
existing file's mode and owner, and refuse to write anything the daemon would
not load. A change that cannot keep the owner fails: run it as root or as the
owner. A symlink to a missing file is refused: create the target first.
Neither touches a running LogWisp: send `SIGHUP`, since `auto_reload` does not
watch the credentials file.

**`token`** and **`stream`** build the same TLS and SCRAM client as a chain
sink. TLS flags: `--ca-file` (default: system roots) or `--pin-sha256` (the
`tls.pin_sha256` a self-signed listener logs), `--server-name` (default: the
host), and `--cert-file` / `--key-file` for a listener with `tls.client_auth`.
There is no flag to skip verification: an unverified server could relay the
login. Redirects are not followed. `--unbound` logs in to an `http` sink behind
a TLS-terminating proxy (`auth.trusted_proxies`), still pinning the proxy's
certificate across the two requests; only then may `--url` carry the path the
proxy mounts LogWisp at. `stream` exits `0` on `SIGINT` or `SIGTERM`, and `1`
when the server ends the stream (a reload or shutdown).

Addresses, as for the plugins ([Networking](networking.md#address-family)):

- An IPv6 address goes in brackets: `--addr [::1]:PORT`,
  `--url https://[::1]:PORT`; in a URL a link-local zone is escaped,
  `https://[fe80::1%25eth0]:PORT`.
- The dial keeps to the address's family; a hostname resolves.
- `--server-name` defaults to the host; an address, without brackets or zone,
  must then be among the certificate's IP SANs.

```bash
# listener host: a file the service user can read, users, then apply
install -m 0640 -o root -g logwisp /dev/null /etc/logwisp/users.toml
lw auth add-user --credentials /etc/logwisp/users.toml --user edge-01 \
  --password-file /etc/logwisp/edge-01.pass
lw auth add-user --credentials /etc/logwisp/users.toml --user viewer \
  --password-file viewer.pass
kill -HUP $(pidof lw)

# rotate: new password into the file; SIGHUP, deploy the file, SIGHUP the edge
lw auth add-user --credentials /etc/logwisp/users.toml --user edge-01 \
  --password-file /etc/logwisp/edge-01.pass --generate

# http sink status, with the token kept out of curl's argv
curl --cacert ca.crt -H @<(printf 'Authorization: Bearer %s\n' \
  "$(lw auth token --url https://HOST:PORT --user viewer \
     --password-file viewer.pass --ca-file ca.crt)") https://HOST:PORT/status

# follow a tcp sink
lw auth stream --addr HOST:PORT --user viewer --password-file viewer.pass \
  --ca-file ca.crt
```

## `lw tls`

Makes ECDSA P-256 certificates for `tls` blocks. It never replaces a file
(remove one to replace it) and writes keys `0600`, certificates `0644`.

```
lw tls ca   --dir DIR [--name NAME] [--days 3650]
lw tls cert --ca-dir DIR --name NAME [--host NAME,...] [--server] [--client]
            [--days 397] [--out DIR]
```

- `ca`: `DIR/ca.crt` and `DIR/ca.key`, a CA that signs leaves only (path
  length 0). `ca.crt` is what dialers set as `tls.ca_file` and listeners as
  `tls.client_ca_file`; with `ca.key` it is a listener's
  `tls.issuer_cert_file` and `tls.issuer_key_file`.
- `cert`: `NAME.crt` and `NAME.key`, in `--out` (default: `--ca-dir`).
  - `--server` for a listener: `--host` lists the DNS names and IP addresses it
    carries, default `NAME`; `--client` for a dialer presenting a certificate;
    both may be given.
  - `NAME` is the subject CN, the identity `auth.type = "mtls"` matches.
  - Valid 397 days (the longest browsers accept), never past the CA. It prints
    the certificate's `pin_sha256`.

```bash
lw tls ca --dir /etc/logwisp/pki
lw tls cert --ca-dir /etc/logwisp/pki --name agg.example.org --server
lw tls cert --ca-dir /etc/logwisp/pki --name edge-01 --client
```
