# To Do

Planned work, in order of priority. Each item names what to build, how it fits
the existing seams, and how to verify it. Finished items move to the design doc
they belong to.

## 1. Network access control (ACL)

The next feature push. Today a listener decides *who* a peer is (`tls`, `auth`);
nothing decides *where* a peer may connect from, and every limit except SCRAM
throttling is global. The ACL adds address rules and per-client limits at the
connection level, below TLS, so a refused peer costs no handshake.

### 1.1 One seam: a filtering listener

- New package `internal/netacl`, the third network seam beside `tlsx` and
  `authz` (AGENTS.md lists the seams; add it there).
- `netacl.New(opts *config.ACLOptions, role) (*Policy, error)` compiles the
  block; a nil policy is valid and transparent, like `authz`.
- `(*Policy).Listener(ln net.Listener) net.Listener` wraps the raw listener
  before TLS:
  - TCP plugins wrap it before `tls.NewListener`.
  - HTTP plugins wrap it before `Serve`/`ServeTLS`.
- `Accept` reads an optional PROXY header (1.2), decides allow or deny (1.3),
  applies per-address connection caps (1.4), and returns a `net.Conn` whose
  `RemoteAddr` is the real client.
- Everything downstream then sees the real client with no further change:
  `authz.remoteIP`, SCRAM throttling, sessions, logs and `http.Request.RemoteAddr`.
- Keep the proxy's own address as `peer_addr` in session metadata for audit.
- A denied connection is closed before any byte is read or written, with a
  counter (`acl_denied`) and a rate-limited WARN.

### 1.2 PROXY protocol (deferred gap of SCRAM, see scram-auth-plan.md)

- Why: behind an L4 proxy that passes TLS through (nginx `stream` with
  `ssl_preread`, HAProxy `mode tcp`), every peer arrives from the proxy's
  address.
  - All peers share one SCRAM throttling budget, so one client can lock out
    every login.
  - Logs, sessions and the ACL itself see only the proxy.
- What: accept PROXY v1 (text) and v2 (binary) headers, but only from
  `proxy_from` addresses or CIDRs. Two config keys in the ACL block:
  - `proxy_protocol = "off" | "optional" | "required"`, default off.
  - `proxy_from = [...]`.
- Rules:
  - A listed peer must send the header when `required`.
  - An unlisted peer that sends a header is refused, since the header is
    spoofable.
  - The header must arrive within a short deadline (reuse
    `tlsx.HandshakeTimeout`), with a size cap: v1 at most 107 bytes, v2 with a
    bounded TLV length.
  - `LOCAL`/`UNKNOWN` commands (proxy health checks) keep the socket address.
  - TLVs are ignored.
- The header precedes the TLS ClientHello, so SCRAM channel binding is
  unaffected: LogWisp still terminates TLS.
- nginx side:
  - In the `stream` server, `proxy_protocol on` on the route to LogWisp (it
    sends v1).
  - HAProxy: `send-proxy` or `send-proxy-v2`.
- Relation to `auth.trusted_proxies` (HTTP proxy mode):
  - That list trusts `X-Forwarded-For` from a TLS-terminating L7 proxy;
    `proxy_from` trusts a PROXY header from an L4 proxy.
  - Keep both, with distinct names and docs. They answer different layers, and
    one deployment can use both: nginx `stream` with `proxy_protocol` into an
    nginx `http` block that sets `X-Forwarded-For $proxy_protocol_addr`.

### 1.3 Address rules

- `allow = [CIDR...]`, `deny = [CIDR...]`, IPv4 and IPv6 (strict per family,
  as the listeners are).
- Order: deny wins, then allow; an empty allow list admits everyone not denied.
- Rules match the real client (after PROXY), never the proxy.
  - In HTTP proxy mode, `X-Forwarded-For` is applied by `authz.ClientAddr` after
    the connection-level decision.
  - Address rules for forwarded HTTP clients therefore belong in a second,
    request-level check inside `authz.ClientAddr`: reuse the compiled `netacl`
    rules there rather than duplicating them.
- Startup warnings (in `LogStartup` style): an allow list containing
  `0.0.0.0/0` or `::/0`, `proxy_from` covering public ranges, a listener on a
  wildcard host with no `allow`.

### 1.4 Per-client limits

- Generalize the SCRAM limiter in `internal/authz/scram.go` (token bucket per
  key, bounded table that fails closed, idle sweep, IPv6 per /64 via
  `throttleKey`) into the shared per-key limiter. One mechanism (AGENTS.md):
  SCRAM throttling then uses it too.
- Keys:
  - `max_connections_per_client` on every listener (concurrent connections per
    address).
  - `requests_per_second_per_client` on HTTP listeners (ingest, stream and
    status requests).
- Later: per-identity limits once a peer is authenticated (the mtls plan's
  deferred item 2), keyed by identity instead of address.

### 1.5 Config, validation, docs

- Config shape: `[...config.acl]` beside `tls` and `auth` on the four listener
  plugins.
  - Decode through `config.Scan`, so unknown keys fail.
  - Dialers have no ACL block.
- Intent rule as in `authz`: an ACL key on a dialer, or `proxy_from` without
  `proxy_protocol`, is an error.
- Stats: `acl_denied`, `acl_proxy_headers`, `acl_limited`, merged into the
  plugin stats like `authz.Stats`.
- Docs: a security.md section, plus networking.md troubleshooting lines for
  each refusal.

### 1.6 Verification

- Go tests, one per rule:
  - PROXY v1 and v2 parse, including malformed, oversized and slow headers.
  - A header from an unlisted peer refused; `required` without a header
    refused; `LOCAL` kept.
  - Deny over allow; IPv6 rules.
  - Per-client connection cap; the limiter table failing closed.
  - The real client reaching SCRAM throttling and session metadata.
- `test/acl-test.sh`:
  - A Go stub proxy that sends v1 and v2 headers in front of each listener
    type.
  - nginx `stream` with `proxy_protocol on` when nginx is installed.
  - Denied and allowed clients; per-client SCRAM budgets behind one proxy
    address.

## 2. Hardening review of `lixenwraith/config` and `lixenwraith/toml`

Both parse untrusted-shaped input (config files, environment, command line)
and were not reviewed with the auth work. Review them as `auth` was reviewed:
adversarial lenses, reproduction before belief, a fix per confirmed finding in
the library repository, then a dependency bump here.

- toml parser:
  - Limits on nesting depth, key count, string and array length, and number
    sizes.
  - Behaviour on invalid UTF-8, duplicate keys and tables, dotted-key and
    inline-table redefinition.
  - Fuzz targets (`go test -fuzz`) seeded with the TOML test suite.
- config:
  - The weakly typed decoder: string-to-number overflow, duration and size
    parsing, the comma split into slices.
  - `maxValueDepth` and `MaxValueSize`, environment and CLI precedence, and
    unknown-key reporting.
- Files:
  - `PreventPathTraversal`, symlink handling and the file-size cap.
  - The watcher: polling, debounce, a file replaced by rename or symlink swap,
    TOCTOU between stat and read.
- Errors: values must never echo secrets (a misplaced password in a config
  value reported back in an error).
- Deliverables:
  - Findings per library.
  - Fuzz targets committed in the library repositories.
  - A note in this repository's security.md once done.

## 3. Packaging: AUR, FreeBSD ports, Debian

The foundation exists:
- The `lw` binary name.
- `make install` with `DESTDIR`, `PREFIX` and `SYSCONFDIR`.
- The `doc/lw.1` manual.
- Service files in `deploy/package/`: systemd unit, sysusers, tmpfiles and the
  FreeBSD rc.d script.
- Skeletons in `deploy/package/arch/` and `deploy/package/freebsd/`.

What remains:

- Releases:
  - The repository has no tags, so versions come from `git describe` and fall
    back to a commit hash. Tag releases `vX.Y.Z`.
  - Publish source tarballs with checksums, and sign them.
- Module path:
  - The module is `logwisp`, so `go install github.com/lixenwraith/logwisp/cmd/lw@latest`
    does not work.
  - FreeBSD's `USES=go:modules` and Debian's dh-golang expect the canonical
    path.
  - Rename the module to `github.com/lixenwraith/logwisp`: a mechanical
    import rewrite in one commit.
- Name check before submission:
  - Arch: `pkgfile -s lw` against the official repositories, and the AUR
    package list for `lw` and `logwisp`.
  - Already checked: Ubuntu 26.04 and 24.04 contents and the FreeBSD 15.1
    ports tree ship no `bin/lw`.
- Arch (AUR):
  - Finalize the PKGBUILD (source URL and checksum of a tagged tarball, the
    Arch Go flags `-trimpath -buildmode=pie -mod=readonly -modcacherw`).
  - Run namcap, generate `.SRCINFO`, and publish `logwisp` (and optionally
    `logwisp-git`).
- FreeBSD:
  - Turn the skeleton into a port (`sysutils/logwisp`): `GH_TUPLE` or
    `go:modules` distinfo, `USE_RC_SUBR=logwisp`, `USERS`/`GROUPS`, a
    pkg-plist with the `.sample` config.
  - Test with poudriere on 14.x and 15.x, then submit through Bugzilla.
- Debian:
  - Debian policy wants every Go dependency packaged; the four `lixenwraith`
    libraries are not.
  - Either package them too (dh-golang), or start with an `.deb` built by the
    Makefile `install` target (nfpm or `dpkg-deb`) and a PPA, and move to the
    archive later.
- Shell completion for bash, zsh and fish, installed by `make install`.
- A packaging CI job: build the AUR package in an Arch container and the port
  in a FreeBSD VM, run `lw --version` and `make image-check`.
