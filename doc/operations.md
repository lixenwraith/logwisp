# Operations Guide

Running, monitoring, and maintaining LogWisp.

## Starting

```bash
# a filter: stdin to stdout, exits 0 at the end of input
lw < app.log > copy.log
tail -F app.log | lw --filter include:patterns=ERROR

# a service: the file's pipelines, until SIGINT or SIGTERM
lw -c /etc/logwisp/logwisp.toml
```

lw exits on its own only at the end of input ([CLI](cli.md#built-in-defaults)).
A reload stops the old sinks as shutdown does, so a stalled client or
downstream delays it by up to 2 s.

There is no built-in daemon mode. Run LogWisp in the foreground under a
supervisor — systemd, rc.d, or a container runtime — which is where restart,
log capture, and resource limits belong. See [Installation](installation.md).

A supervisor's stdin is `/dev/null` (systemd's default, `docker run` without
`-i`), where a console source ends at once. So a service defines its
pipelines: a file without `[[pipelines]]` runs the built-in stdin-to-stdout
pipeline and exits 0 at once, which `Restart=on-failure` does not restart, and
a container configured through variables needs a `LOGWISP_SOURCE`.

**systemd**

```bash
sudo systemctl start logwisp
sudo systemctl status logwisp
sudo journalctl -u logwisp -f
```

**FreeBSD rc.d**

```bash
sudo service logwisp start
sudo service logwisp status
```

## Configuration Changes

### Hot reload

```toml
auto_reload = true
```

or send a signal:

```bash
kill -HUP $(pidof lw)
```

Signals reread the selected TOML file even when `auto_reload` is disabled.
Reload validates a detached snapshot and builds a new service **before**
tearing the old one down, so a bad configuration leaves the running service
intact. An invalid one logs `Failed to read reload configuration` with the
validator's `validate configuration: <key path>: ...` error. One whose files
fail when its plugins are built (a missing certificate, an unreadable
credentials file) logs `Failed to bootstrap new service, keeping old service
running`.

What reload does *not* do:

- Re-apply `logging.*`; application logging is configured once at startup.
- Preserve connections. Listeners close and reopen, and every SSE, TCP, and
  chain client is disconnected. Chain sinks reconnect on their own backoff;
  browsers reconnect SSE automatically; raw TCP consumers must retry themselves.
- Notice rotated certificates on its own: certificate files are read at plugin
  construction and `auto_reload` watches only the configuration file, so
  rotation requires `SIGHUP`.

Standard input survives a reload: one reader serves the process, so the new
console source continues where the old one stopped, and no line is read twice.

Plan reloads on a busy relay as you would a restart: a listener that fails to
bind does so after the old service stopped, leaving lw without working
pipelines until a corrected configuration reloads
([Hot Reload](configuration.md#hot-reload)).

### Checking a configuration

Before a reload, run `lw --check -c FILE` on the edited file: a failed reload
keeps the running service, and `--check` says why without touching it
([CLI](cli.md#usage-patterns)).

## Monitoring

### Status reporter

Enabled by default with a configuration file (off without one), every 30
seconds. It logs at **DEBUG**, so it produces nothing unless
`logging.level = "debug"` — a common surprise.

```toml
status_reporter = true

[logging]
level = "debug"
```

It emits a service summary and then walks each pipeline, flattening scalar
statistics into log fields and recursing into flow, rate limiter, filter,
source, and sink stats. Each plugin's `details` are spread into its line, so
the auth and TLS rejection counters show up there.

Disable with `status_reporter = false`.

### HTTP status endpoint

When a pipeline has an `http` sink:

```bash
curl -s http://127.0.0.1:8080/status | jq .
```

```json
{
  "endpoints": {
    "status": "/status",
    "stream": "/stream"
  },
  "instance_id": "sse",
  "server": {
    "acl": "none",
    "active_clients": 3,
    "auth": "none",
    "buffer_size": 1000,
    "client_buffer_size": 256,
    "host": "0.0.0.0",
    "max_connections": 32,
    "port": 8080,
    "tls": false,
    "type": "http",
    "uptime_seconds": 8130,
    "write_timeout_ms": 5000
  },
  "service": "LogWisp",
  "statistics": {
    "acl_denied": 0,
    "acl_limited": 0,
    "auth_rejected": 0,
    "dropped_writes": 12,
    "rejected_clients": 0,
    "total_processed": 15234
  },
  "version": "vX.Y.Z"
}
```

This endpoint is scoped to one sink, not to the whole process, and without an
`auth` block it is **unauthenticated**. Bind it to a trusted interface, or
query it with a client certificate or a token from `lw auth token`.

### Metrics worth watching

Each counter, where it is reported, and what a rise means:

- `dropped_entries` (source): downstream cannot keep up with the source; the
  console source never drops, it reads stdin slower
- `total_dropped` (flow): the rate limit or filters are discarding entries,
  often by intent
- `total_dropped_by_sink` (pipeline): a sink's input queue is full; a console
  sink waits instead, so its entries count only when shutdown cuts the wait
- `dropped_writes` (`tcp` and `http` sinks): a client's queue overflowed,
  because it is too slow or one burst exceeded `client_buffer_size`
- `rejected_conns` (`tcp` sink, `tcp_chain` source), `rejected_clients`
  (`http` sink): `max_connections` is being hit; `rejected_conns` also counts
  auth refusals
- `tls_handshake_errors` (`tcp` sink, `tcp_chain` source): a certificate or
  version mismatch, or scanning
- `parse_errors` (chain sources): malformed entry lines from upstream, each
  skipped
- `reconnects` (`tcp_chain` sink): an unstable link or a flapping downstream
- `dropped_batches` (`http_chain` sink): downstream is rejecting batches
  permanently
- `synthesized` (chain sinks): events reach the sink without structure
- `acl_denied`, `acl_limited` (a listener whose `acl` block sets a rule or
  limit; the `http` status always): connections or requests the address
  rules or PROXY-header checks refused, and those over a per-client limit;
  `acl_proxy_headers` counts the PROXY headers read

## Log Management

LogWisp's own log goes to stderr by default. Without a configuration file lw
logs less ([CLI](cli.md#built-in-defaults)), so a container configured only
through variables passes `LOGWISP_LOGGING_LEVEL=info` and
`LOGWISP_STATUS_REPORTER=true`; the image sets neither, as a variable would
override a mounted file's value. `lw-deploy.sh` always passes `-c`, so its
nodes log at `info`. To files:

```toml
[logging]
output = "file"
level  = "info"

[logging.file]
directory         = "/var/log/logwisp"
name              = "logwisp"
max_size_mb       = 100
max_total_size_mb = 1000
retention_hours   = 168.0
```

Rotation is automatic on size, with a total-size cap and a retention window.
There is no signal to reopen log files, so do not move files out from under
LogWisp and expect it to reattach — let it rotate, or restart it.

Production level: `info`, or `warn` on a busy relay. Avoid `debug` under load:
the filter stage logs several lines per entry evaluated.

## Performance Tuning

### Buffers

- `total_dropped_by_sink` climbing while the sink is healthy: a burst
  outran its queue; raise `buffer_size`
- `dropped_writes` on a network sink:
  - a client slower than the sustained rate: drops are intended
  - a burst above `client_buffer_size`, lost even to a fast reader: keep
    `client_buffer_size` at or above the burst a `drop` rate limit lets
    through, its `burst_entries` (`entries_per_second` when 0)
- the HTTP status endpoint reports both queue bounds beside the counters

```toml
[pipelines.plugin_sinks.config]
buffer_size        = 5000
client_buffer_size = 1024
```

### Rate limiting

```toml
[pipelines.flow.rate_limit]
entries_per_second   = 1000.0
burst_entries        = 2000.0
policy               = "drop"
max_entry_size_bytes = 65536
```

Enforcing `max_entry_size_bytes` needs a rate above 0 and `policy = "drop"`
(a file's default is `pass`); see [Rate limiting](configuration.md#rate-limiting).

### Formatting

`raw` is the cheapest and skips sanitization; `json` costs the most. The
formatter serializes on a mutex, so it is the one shared bottleneck in a
pipeline — splitting work across pipelines parallelizes it.

### Chain batching

`http_chain` trades latency for efficiency. Lower `flush_interval_ms` for
freshness, raise `max_batch_count` and `max_batch_bytes` for throughput. Use
`tcp_chain` when per-entry latency matters.

## Troubleshooting

**Nothing appears at the sink**

Walk the pipeline in order and read the counters: source `total_entries` (is
anything being produced?), flow `total_dropped` (filters or rate limit?),
pipeline `total_dropped_by_sink` (sink backed up?), sink `total_processed`.

**A pipeline stalls behind a console sink**

A console sink never drops: when its output is slow (a paused terminal, a full
pipe, a stalled log collector) its pipeline waits, and the pipeline's other
sinks with it. Stdin is read slower; other sources queue, then drop and count
`dropped_entries`. Where a service's stdout may stall, give it a `file` sink
instead. A closed stdout pipe ends lw with `SIGPIPE`.

**File source reads nothing**

- The watcher seeks to end-of-file on start; only content appended afterwards is
  read. Positions are in memory, so a restart re-seeks to end and anything
  written during the downtime is lost. `from = "start"` reads each file whole
  instead, and replays it on every restart.
- `pattern` is a filename glob with `*` and `?` only, and matching is not
  recursive.
- `check_interval_ms` governs how quickly a *new file* is noticed; tailing an
  open file polls at a fixed 100 ms.

**High memory use**

Buffers are bounded, so unbounded growth almost always means many buffers:
count sinks × `buffer_size`, plus clients × `client_buffer_size`. A `tcp_chain`
sink blocked on an unreachable downstream also holds its full input queue.

**Chain link not delivering**

Check `connected` and `reconnects` on a `tcp_chain` sink, `parse_errors` on the
source, and remember `http_chain` waits up to `flush_interval_ms`. For TLS
problems see [Networking](networking.md#troubleshooting).

**Environment variable override has no effect**

Only `LOGWISP_`-prefixed names are read (`LOGWISP_QUIET`,
`LOGWISP_LOGGING_LEVEL`). Array-indexed paths, such as a key inside
`[[pipelines]]`, cannot be set from the environment or the command line;
define whole pipelines there with the
[pipeline flags](cli.md#pipelines) or
[pipeline variables](cli.md#pipeline-variables).

## Security Operations

**Certificate rotation**

```bash
openssl x509 -in /etc/logwisp/tls/relay.crt -noout -enddate
```

Certificates and SCRAM credentials files load at plugin construction, so
rotation is: write the new files, then `kill -HUP`. Startup and every reload
warn at WARN once a certificate is within 30 days of expiry; automate the check
anyway. For passwords see
[rotation and revocation](security.md#rollout-rotation-and-revocation).

**Access review**

With `tls` alone, any certificate signed by the configured `client_ca_file` is
accepted, so "access review" means reviewing what your CA has issued. Add an
`auth` block with an explicit `allow` list, or `scram` with its credentials
file, and the review becomes those files: the identities or users listed there
are the ones that can connect, and removing one plus a `SIGHUP` is the
revocation path. Authorized identities are recorded in session metadata as
`auth_identity`; rejections are counted in `auth_rejected` and logged at WARN.
See [Security](security.md#the-auth-block).

**Secret leakage**

Filters are the only redaction mechanism, and they drop whole entries rather
than masking parts of them. See [Filters](filters.md#common-recipes).

## Maintenance

**Upgrades**

1. Run the new binary's `lw --check -c FILE` against the current
   configuration: unknown or renamed keys fail there.
2. Stop the old process, install the new binary, start it.
3. Confirm each pipeline started and that counters are advancing.

**Backup**

Configuration files and TLS material are the only durable state worth backing
up. LogWisp keeps no persistent runtime state: file read positions live in
memory, connections are re-established on restart, and in-flight entries are
lost.

**Redundancy**

Because there is no persistence, availability comes from topology, not from
LogWisp itself. Give each edge two chain sinks pointing at two relays if you
need to survive a relay outage, and accept that this duplicates entries
downstream.
