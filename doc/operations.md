# Operations Guide

Running, monitoring, and maintaining LogWisp.

## Starting

```bash
# foreground, explicit config
logwisp -c /etc/logwisp/logwisp.toml

# no config: built-in demo pipeline (random source -> stdout)
logwisp
```

There is no built-in daemon mode. Run LogWisp in the foreground under a
supervisor — systemd, rc.d, or a container runtime — which is where restart,
log capture, and resource limits belong. See [Installation](installation.md).

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
kill -HUP $(pidof logwisp)
```

Reload constructs a new service from the new configuration **before** tearing
the old one down, so a broken configuration leaves the running service intact
and logs the failure:

```
ERROR msg="Failed to bootstrap new service, keeping old service running" error=...
```

What reload does *not* do:

- Re-apply `logging.*`; application logging is configured once at startup.
- Preserve connections. Listeners close and reopen, and every SSE, TCP, and
  chain client is disconnected. Chain sinks reconnect on their own backoff;
  browsers reconnect SSE automatically; raw TCP consumers must retry themselves.
- Reload certificates without a reload — certificate files are read at plugin
  construction, so rotation requires `SIGHUP`.

Plan reloads on a busy relay the way you would plan a restart.

### Checking a configuration

There is no validate-only mode. To check a file, start it with debug logging and
watch for pipeline startup:

```bash
logwisp -c candidate.toml --logging.level=debug --logging.output=stderr
```

Success looks like `Created source instance`, `Created sink instance`, and
`Starting pipeline` for each pipeline. Failures name the pipeline and the
offending key:

```
ERROR msg="Failed to create pipeline" pipeline=app error="failed to create sink out: port: must be 1-65535, got 0"
```

Remember that most validation lives in plugin constructors, so a config only
proves itself when the pipeline is actually built.

## Monitoring

### Status reporter

Enabled by default, every 30 seconds. It logs at **DEBUG**, so it produces
nothing unless `logging.level = "debug"` — a common surprise.

```toml
status_reporter = true

[logging]
level = "debug"
```

It emits a service summary and then walks each pipeline, flattening scalar
statistics into log fields and recursing into flow, rate limiter, filter,
source, and sink stats.

Disable with `status_reporter = false`.

### HTTP status endpoint

When a pipeline has an `http` sink:

```bash
curl -s http://127.0.0.1:8080/status | jq .
```

```json
{
  "service": "LogWisp",
  "version": "v0.16.0",
  "instance_id": "sse",
  "server": {
    "type": "http",
    "host": "0.0.0.0",
    "port": 8080,
    "tls": false,
    "active_clients": 3,
    "buffer_size": 1000,
    "uptime_seconds": 8130
  },
  "endpoints": { "stream": "/stream", "status": "/status" },
  "statistics": {
    "total_processed": 15234,
    "dropped_writes": 12,
    "rejected_clients": 0
  }
}
```

This endpoint is scoped to one sink, not to the whole process, and it is
**unauthenticated**. Bind it to a trusted interface.

### Metrics worth watching

| Metric | Where | Meaning if rising |
|--------|-------|-------------------|
| `dropped_entries` | source | Downstream cannot keep up with the source |
| `total_dropped` | flow | Rate limit or filters are discarding entries (often intended) |
| `total_dropped_by_sink` | pipeline | A sink's input queue is full |
| `dropped_writes` | tcp/http sink | A specific client is too slow |
| `rejected_conns` / `rejected_clients` | tcp/http sink, tcp_chain source | `max_connections` is being hit |
| `tls_handshake_errors` | tcp sink, tcp_chain source | Certificate or version mismatch, or scanning |
| `parse_errors` | chain source | Protocol or version skew upstream |
| `reconnects` | chain sink | Unstable link or a flapping downstream |
| `dropped_batches` | http_chain sink | Downstream rejecting batches permanently |
| `synthesized` | chain sink | Events reaching the sink without structure |

## Log Management

LogWisp's own operational log:

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

Raise `buffer_size` when `total_dropped_by_sink` is climbing but the sink itself
is healthy — that is a burst-absorption problem. Raise `client_buffer_size` when
`dropped_writes` is climbing for network sinks; that is a slow-consumer problem,
and a bigger buffer only buys time.

```toml
[pipelines.plugin_sinks.config]
buffer_size        = 5000
client_buffer_size = 1024
```

### Rate limiting

```toml
[pipelines.flow.rate_limit]
rate                 = 1000.0
burst                = 2000.0
policy               = "drop"
max_entry_size_bytes = 65536
```

Two behaviours to keep in mind: the limiter does not exist at all when
`rate <= 0`, and `policy = "pass"` short-circuits the size cap as well as the
rate check. Enforcing `max_entry_size_bytes` therefore requires `rate > 0` and
`policy = "drop"`.

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

**File source reads nothing**

- The watcher seeks to end-of-file on start; only content appended afterwards is
  read. Positions are in memory, so a restart re-seeks to end and anything
  written during the downtime is lost.
- `pattern` is a filename glob with `*` and `?` only, and matching is not
  recursive.
- `check_interval_ms` governs how quickly a *new file* is noticed; tailing an
  open file polls at a fixed 100 ms.

**High memory use**

Buffers are bounded, so unbounded growth almost always means many buffers:
count sinks × `buffer_size`, plus clients × `client_buffer_size`. A `tcp_chain`
sink blocked on an unreachable downstream also holds its full input queue.

**Chain link not delivering**

Check `connected` and `reconnects` on the sink, `parse_errors` on the source,
and remember `http_chain` waits up to `flush_interval_ms`. For TLS problems see
[Networking](networking.md#troubleshooting).

**Environment variable override has no effect**

LogWisp currently reads these **without** the `LOGWISP_` prefix — `QUIET`,
`LOGGING_LEVEL`, and so on. Array-indexed paths cannot be set from the
environment or the command line at all.

## Security Operations

**Certificate rotation**

```bash
openssl x509 -in /etc/logwisp/tls/relay.crt -noout -enddate
```

Certificates load at plugin construction, so rotation is: write the new files,
then `kill -HUP`. Automate the expiry check; nothing in LogWisp warns you.

**Access review**

With `tls` alone, any certificate signed by the configured `client_ca_file` is
accepted, so "access review" means reviewing what your CA has issued. Add an
`auth` block with an explicit `allow` list and the review becomes the config
file itself: the identities listed there are the ones that can connect, and
removing one plus a `SIGHUP` is the revocation path. Authorized identities are
recorded in session metadata as `auth_identity`; rejections are counted in
`auth_rejected` and logged at WARN. See
[Security](security.md#the-auth-block).

**Secret leakage**

Filters are the only redaction mechanism, and they drop whole entries rather
than masking parts of them. See [Filters](filters.md#common-recipes).

## Maintenance

**Upgrades**

1. Read the changelog for configuration-schema changes.
2. Start the new binary against the current configuration in a scratch
   environment.
3. Stop the old process, install the new binary, start it.
4. Confirm each pipeline started and that counters are advancing.

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
