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

Roles, runtimes, scenarios and what is not covered: [doc/deployment.md](../doc/deployment.md).

`package/` holds the service files (`logwisp.service`, `.sysusers`,
`.tmpfiles`, `logwisp.rc`) that `make install` and this script install, the
shell completions, and the deb, Arch and FreeBSD packaging:
[doc/installation.md](../doc/installation.md#installing).
