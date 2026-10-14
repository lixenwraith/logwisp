# LogWisp Documentation

The [README](../README.md) has LogWisp's features, a quick start and the
system requirements.

- [Installation](installation.md): building, installing, services,
  the container image, packaging, the end-to-end test scripts
- [Deployment](deployment.md): `deploy/lw-deploy.sh` for edges,
  aggregators, containers, services, jails
- [Architecture](architecture.md): component model, data flow,
  concurrency, back-pressure, the configuration engine's WebAssembly API
- [Configuration](configuration.md): TOML structure, precedence,
  environment and CLI overrides
- [Sources](sources.md) and [Sinks](sinks.md): every plugin and its
  options
- [Filters](filters.md) and [Formatters](formatters.md): pattern
  matching, output shaping and sanitization
- [Chaining](chaining.md): multi-node topologies and the wire protocol
- [Networking](networking.md): listeners, dialers, timeouts, limits
- [Security](security.md): TLS, mTLS, password (SCRAM) authentication,
  address ACLs, certificates made at startup; threat model and current limits
- [CLI](cli.md): filter use, flags, pipeline specifications, presets,
  environment, signals, exit codes, `lw --tui`, `--schema`, `lw auth`,
  `lw tls`, `lw preset`, `lw config`; also the `lw(1)` manual,
  [`lw.1`](lw.1)
- [Operations](operations.md): running, monitoring, tuning,
  troubleshooting
- [To Do](todo.md): the maintainer's release and packaging steps, and
  what `lw --tui` and the schema leave for later

A fully annotated configuration covering every option ships as
[`config/logwisp.toml`](../config/logwisp.toml).
