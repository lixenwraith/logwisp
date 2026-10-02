# deploy

`lw-deploy.sh` writes a LogWisp configuration for one node and deploys it: in a
docker or podman container, as a systemd or FreeBSD rc.d service (on the host
or inside a jail), or as a configuration you run yourself. It is POSIX sh,
written for FreeBSD's `/bin/sh` as much as for dash.

```sh
deploy/lw-deploy.sh                  # asks, with inline menus
deploy/lw-deploy.sh -h               # every flag
deploy/lw-deploy.sh --dry-run ...    # print the configuration and commands only
deploy/lw-deploy.sh --yes ...        # no questions: defaults, or fail on a missing value
```

- Roles
  - `edge`: tails log directories, forwards the entries to an aggregator
  - `aggregator`: receives from edges; writes files, serves HTTP and TCP streams
  - `standalone`: tails log directories; writes files, serves streams
- Runtimes
  - `docker`, `podman`: a hardened container of the `logwisp` image (Linux)
  - `native`: systemd on Linux, rc.d on FreeBSD, `--jail NAME` for a jail
  - `manual`: the configuration only, for `lw -c`
- Every question has a flag. Before changing anything the script prints its
  plan and the command line that repeats it without questions, ready for the
  next node.
- The native runtimes install the service files of `deploy/package/`.
- Not covered, and printed by the script: filters, rate limits, heartbeat,
  several pipelines, proxy mode, ACLs, certificate creation. Edit the generated
  `logwisp.toml` for those.

Scenarios and what each runtime writes: [doc/deployment.md](../doc/deployment.md).
