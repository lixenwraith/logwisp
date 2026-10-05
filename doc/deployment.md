# Deployment

`deploy/lw-deploy.sh` configures and deploys one LogWisp node per run. It asks
for what its flags leave open, prints a plan with the equivalent non-interactive
command, then writes the files, runs `lw --check` on them (the node's binary or
image, with its mounts) and starts the node. `--dry-run` stops at printing;
`--yes` never asks and fails on a missing required value. It creates no
certificates: see [Security](security.md#enabling-mtls).

## Roles

- `edge`
  - tails each `--log-dir` (not recursive) for `--log-pattern` (default `*.log`)
  - forwards to `--aggregator` over `tcp_chain` (port 9440) or, with
    `--chain http`, `http_chain` (port 9441)
  - labels its entries `--node`: the short host name, or the jail name
- `aggregator`
  - one chain listener on `--listen` (default `0.0.0.0`) and `--chain-port`
  - outputs, at least one: `--file-dir` (rotating `--file-name`.log),
    `--http-port` (SSE `/stream`, JSON `/status`), `--tcp-port`
  - `--format` `txt` (default), `json` or `raw`
- `standalone`
  - the edge's sources and the aggregator's outputs, no chain

## Runtimes

- `docker`, `podman` (Linux)
  - the container runs `--read-only --cap-drop ALL --security-opt
    no-new-privileges -u 65532:65532 --restart unless-stopped`
  - `--config-dir` (default `/etc/logwisp/NAME`) holds `logwisp.toml`, `tls/`,
    and the credentials files, owned by 65532 and mounted read-only at
    `/etc/logwisp`
  - log directories mount read-only and the output directory writable, each at
    its host path; `--log-group` adds that group's id to the container
  - listener ports publish on `--listen`, an IP address; the process inside
    binds `0.0.0.0`
  - `--network NET` joins a user network, created when missing, where edges
    reach an aggregator by container name; `host` publishes nothing
  - `--image` defaults to `logwisp:dev`, the `make image` tag; `--build` builds
    it from the repository. Behind an HTTPS-intercepting proxy add
    `--build-ca FILE` and, for a proxy on loopback,
    `--build-flags "--network host"`; the environment's proxy variables pass
    through as build arguments
  - rootful engines need root to give the files to 65532; rootless podman maps
    the caller to 65532 with `--userns keep-id`
  - SELinux hosts must label the mounted directories for containers; the
    script does not relabel, since `:z` on a shared directory such as
    `/var/log` would relabel it for every other service too
- `native`, Linux
  - needs systemd; installs `lw` to `/usr/local/bin` unless one is installed
    (`--bin FILE`, or `--build` for `make build`), and
    `deploy/package/logwisp.service`, `logwisp.sysusers` and
    `logwisp.tmpfiles` under `/etc`
  - a package's unit (`/usr/lib/systemd/system/logwisp.service`) is used as it
    is, with the `lw` its `ExecStart` runs; `--bin` and `--build` then stop the
    run, since the service would never run that binary
  - writes `/etc/logwisp/logwisp.toml`, `root:logwisp`, mode 0640
  - refuses log and output directories under `/tmp` and `/var/tmp`: the unit's
    `PrivateTmp=yes` gives the service its own, empty ones
  - adds `logwisp.service.d/deploy.conf` when the node needs it:
    `ReadWritePaths` for an output outside `/var/log/logwisp`,
    `ProtectHome=read-only` for logs or output under `/home`,
    `SupplementaryGroups` for `--log-group`, `CAP_NET_BIND_SERVICE` for a port
    below 1024
- `native`, FreeBSD
  - installs `deploy/package/logwisp.rc` as `/usr/local/etc/rc.d/logwisp`,
    creates the `logwisp` user with `pw`, enables it with `sysrc`; LogWisp logs
    to syslog under the tag `logwisp`
  - writes `/usr/local/etc/logwisp/logwisp.toml`
  - `--jail NAME` writes the files and runs the commands through `jexec`, so
    the jail's own symlinks cannot redirect a write onto the host; the jail
    must be running, and the script prints a `jail.conf` example when it is not
  - a non-root user binds a port below 1024 only with
    `sysctl net.inet.ip.portrange.reservedhigh` lowered or `mac_portacl`
- `manual`
  - writes into `--config-dir`, an absolute path (default `~/logwisp-ROLE`),
    adds users with the local `lw`, and prints the `lw -c` command

FreeBSD runs no Docker, and podman there runs FreeBSD images only while the
LogWisp image is Linux: on FreeBSD the script offers `native` instead, on the
host or in a jail. A `native` install needs a host of its `--os`; for another
one, `--dry-run` shows the install and `--runtime manual` writes the
configuration.

Re-running the same command updates the node: an existing `logwisp.toml` is
kept as `logwisp.toml.bak`, the container is replaced, generated passwords are
reused. A user already in a credentials file whose password file is missing
stops the run before any change, instead of getting a new password that would
lock its edge out. Under `--yes`, replacing a configuration or a container
needs `--force`.

## Security options

- `--tls` secures every network link of the node; the files are copied into
  the configuration directory as `tls/node.crt`, `tls/node.key`, `tls/ca.crt`
  - listeners present `--cert-file` and `--key-file`
  - an edge verifies the aggregator with `--ca-file`, or the system roots; the
    certificate must name the address dialed (an IP SAN for an IP), or the
    name given as `--server-name`
- `--auth` on the chain link
  - `mtls`: edges present `--cert-file`; the aggregator admits the `--allow`
    CNs (none: any certificate the CA issued); an edge's `--allow` pins the
    aggregator's CN
  - `scram`: the aggregator creates each `--add-user`, its password generated
    into `--secrets-dir`, an absolute path (default `~/logwisp-secrets`), and
    handed to `lw auth add-user`, natively or through the image; copy each
    password file to its edge as `--password-file`, whose name without
    `.pass` is the default `--username`
  - either binds the node label to the authenticated identity
- `--sink-auth` on the `http` and `tcp` outputs
  - `mtls` with `--sink-allow`, or `scram` with `--add-viewer` (a separate
    `viewers.toml`); viewers log in with `lw auth token` and `lw auth stream`
  - without it the outputs admit anyone who reaches them: bind `--listen` to a
    trusted address
- without `--auth` or `--sink-auth`, the auth flags imply their mode:
  `--allow` and `--sink-allow` mtls; `--add-user`, `--username`,
  `--password-file` and `--add-viewer` scram. Under `--yes` one that does not
  apply, such as `--add-user` with `--auth none` or without `--tls`, stops the
  run rather than deploy the node open

## FreeBSD host, jails and one aggregator

Application jails run an edge each; a `logs` jail aggregates. Every jail runs
already, and the `logs` jail has an address the others reach (`AGG_ADDR`).

1. Certificates: a CA, and a server certificate for `logs` naming `AGG_ADDR`
   ([Security](security.md#enabling-mtls)).
2. The aggregator, from the host:

   ```sh
   deploy/lw-deploy.sh --yes --runtime native --jail logs --role aggregator \
     --file-dir /var/log/logwisp --http-port 8080 \
     --tls --cert-file logs.crt --key-file logs.key \
     --auth scram --add-user web1 --add-user db1 \
     --sink-auth scram --add-viewer ops
   ```

   The passwords land in `~/logwisp-secrets/`: `web1.pass`, `db1.pass` and
   `ops.pass`.
3. An edge per application jail:

   ```sh
   deploy/lw-deploy.sh --yes --runtime native --jail web1 --role edge \
     --log-dir /var/log/nginx --aggregator AGG_ADDR \
     --tls --ca-file ca.crt --auth scram --password-file ~/logwisp-secrets/web1.pass
   ```

4. Check: `jexec logs service logwisp status`, the files in the `logs` jail's
   `/var/log/logwisp`, and `https://AGG_ADDR:8080/status` with a token from
   `lw auth token --url https://AGG_ADDR:8080 --user ops --password-file
   ~/logwisp-secrets/ops.pass --ca-file ca.crt` ([CLI](cli.md#lw-auth)).

Variants:

- the aggregator on the host itself: drop `--jail logs`
- no daemon per jail: one `standalone` or `edge` on the host tails each jail's
  logs through the host path (`--log-dir JAIL_PATH/var/log`); the entries then
  carry the host's label and the bare file name, so files of the same name in
  two jails cannot be told apart
- a Linux aggregator: run step 2 with `--runtime docker` on that host and point
  the edges at it; the chain protocol is the same

## Linux host with containers

An aggregator container and an edge container per application, on one user
network:

```sh
deploy/lw-deploy.sh --yes --runtime docker --role aggregator --network logwisp \
  --file-dir /srv/logwisp --http-port 8080 --listen 127.0.0.1
deploy/lw-deploy.sh --yes --runtime docker --role edge --name logwisp-edge-app \
  --network logwisp --aggregator logwisp-aggregator --log-dir /var/log/app
```

`--listen 127.0.0.1` keeps the published ports on loopback; edges on other
hosts need it on an address they reach. `docker kill -s HUP NAME` reloads an
edited configuration or credentials file.

## Not covered

Edit the generated `logwisp.toml` for these; `config/logwisp.toml` documents
every key.

- filters, rate limits, heartbeat, formatter flags and timestamp layouts
- more than one pipeline; both chain transports, or a further hop, on one node
- proxy mode: browser logins through a TLS-terminating proxy
- `acl` on the listeners: address rules, PROXY headers, per-client limits
- mtls identities other than the certificate CN; `node_binding` other than
  `force`
- creating certificates
- several native instances on one host: use one per host or jail

## Testing the script

`test/deploy-test.sh --auto` drives the script with `--yes` and `--dry-run` for
the manual, native and docker runtimes, runs the generated edge, aggregator and
standalone nodes end to end, and checks that `--yes` fails closed and that
`--dry-run` changes nothing.
