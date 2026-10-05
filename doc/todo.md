# To Do

Planned work, in order of priority. Each item names what to build, how it fits
the existing seams, and how to verify it. Finished items move to the design doc
they belong to.

## 1. Network access control (ACL)

The seam exists: `internal/netacl` wraps each listener's socket before TLS,
and the `acl` block's `allow` and `deny` refuse peers by address
([Security](security.md#the-acl-block)). Every limit except SCRAM throttling
is still global, and behind an L4 proxy every peer is the proxy.

### 1.1 The filtering listener

- `Accept` is to read an optional PROXY header (1.2) before the address rules
  and apply per-address connection caps (1.4) after them, returning a
  `net.Conn` whose `RemoteAddr` is the real client.
- Everything downstream then sees the real client with no further change:
  `authz.remoteIP`, SCRAM throttling, sessions, logs and `http.Request.RemoteAddr`.
- Keep the proxy's own address as `peer_addr` in session metadata for audit.

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

### 1.3 Address rules for forwarded clients

- Rules match the real client (after PROXY), never the proxy.
- In HTTP proxy mode, `X-Forwarded-For` is applied by `authz.ClientAddr` after
  the connection-level decision, so rules for forwarded HTTP clients belong in
  a second, request-level check there, reusing the compiled `netacl` rules.
  `authz.parseProxies` then takes netacl's address-or-CIDR parsing too.
- Startup warning: `proxy_from` covering public ranges.

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

- `proxy_protocol`, `proxy_from` and the 1.4 keys join `allow` and `deny` in
  the `acl` block.
- Intent rule as in `authz`: `proxy_from` without `proxy_protocol` is an error.
- Stats: `acl_proxy_headers` and `acl_limited` beside `acl_denied`.
- Docs: the security.md section, plus networking.md troubleshooting lines for
  each refusal.

### 1.6 Verification

- Go tests, one per rule:
  - PROXY v1 and v2 parse, including malformed, oversized and slow headers.
  - A header from an unlisted peer refused; `required` without a header
    refused; `LOCAL` kept.
  - Per-client connection cap; the limiter table failing closed.
  - The real client reaching SCRAM throttling and session metadata.
- `test/acl-test.sh`, which covers the address rules, adds:
  - A Go stub proxy that sends v1 and v2 headers in front of each listener
    type.
  - nginx `stream` with `proxy_protocol on` when nginx is installed.
  - Per-client SCRAM budgets behind one proxy address.

## 2. Packaging: AUR, FreeBSD ports, Debian

The foundation exists:
- The `lw` binary name, free in Arch (official repositories and AUR), Ubuntu
  24.04 and 26.04, and the FreeBSD 15.1 ports tree.
- The canonical module path `github.com/lixenwraith/logwisp`, which
  `go install`, FreeBSD's `USES=go:modules` and Debian's dh-golang expect.
- `make install` with `DESTDIR`, `PREFIX` and `SYSCONFDIR`.
- The `doc/lw.1` manual.
- Service files in `deploy/package/`: systemd unit, sysusers, tmpfiles and the
  FreeBSD rc.d script.
- Skeletons in `deploy/package/arch/` and `deploy/package/freebsd/`.

What remains. Steps 1 to 3 are the maintainer's: they need push rights and an
identity, and both skeletons download the tagged source.

1. Tag the release on the merged main commit, `vX.Y.Z`:
   ```
   git tag -a vX.Y.Z -m vX.Y.Z      # git tag -s signs it with your key
   git push origin vX.Y.Z
   ```
   - `make` then stamps `vX.Y.Z` (from `git describe`), and
     `go install github.com/lixenwraith/logwisp/cmd/lw@vX.Y.Z` works.
   - A GitHub release for the tag is optional; the tag alone serves
     `archive/vX.Y.Z.tar.gz`, which the PKGBUILD downloads.
2. Arch (AUR), `deploy/package/arch/PKGBUILD`:
   - `pkgver=X.Y.Z` and the `# Maintainer: Name <email>` line.
   - `updpkgsums` (pacman-contrib) replaces `sha256sums=('SKIP')` with the
     tarball's checksum.
   - `namcap PKGBUILD`, then `makepkg -si` (builds, runs `check()`,
     installs), then `makepkg --printsrcinfo > .SRCINFO`.
   - Push `PKGBUILD` and `.SRCINFO` to
     `ssh://aur@aur.archlinux.org/logwisp.git`; optionally a `logwisp-git`
     package built from the main branch.
3. FreeBSD, `deploy/package/freebsd/` (`sysutils/logwisp`):
   - `DISTVERSION=X.Y.Z` and `MAINTAINER=` your address.
   - `make makesum` writes `distinfo`: the module zip that the Go proxy
     serves for `GO_MODULE` at the tag.
   - The `logwisp` user needs an ID registered in the ports tree. Take a
     number below 1000 that is free in both `/usr/ports/UIDs` and
     `/usr/ports/GIDs`, and add to the same patch:
     ```
     UIDs: logwisp:*:NNN:NNN::0:0:LogWisp daemon:/nonexistent:/usr/sbin/nologin
     GIDs: logwisp:*:NNN:
     ```
   - `portlint -AC`, `poudriere testport` on 14.x and 15.x jails, then a
     Bugzilla report with the port directory and the UIDs/GIDs diff.
4. Debian:
   - Debian policy wants every Go dependency packaged; the four `lixenwraith`
     libraries are not.
   - Either package them too (dh-golang), or start with an `.deb` built by the
     Makefile `install` target (nfpm or `dpkg-deb`) and a PPA, and move to the
     archive later.
5. Shell completion for bash, zsh and fish, installed by `make install`.
6. A packaging CI job: build the AUR package in an Arch container and the port
   in a FreeBSD VM, run `lw --version` and `make image-check`.

## 3. Follow-ups

Smaller items found along the way; each is independent of the ACL.

1. A late browser sees no backlog: the `http` sink keeps none, so the viewer
   shows entries from when it connects. A bounded replay (a `replay_lines`
   option, sent after `event: connected`) would fill it. The viewer also hides
   a `503` from `max_connections` behind "retrying"; the status JSON it already
   fetches could name it.
2. Level detection. `source.ExtractLogLevel` needs a delimiter after the name
   (`ERROR:`, `[WARN]`, ` INFO `), so `warning disk full` or `DBG x` get no
   level, hence no color. Match the names as words, as the console sink's
   painter does, with one table for both.
3. Command line:
   - a positional word at the top level (`lw tail`, `lw -t FILE`) still reaches
     config with an unclear message; name it ("unexpected argument X; the file
     is -c FILE");
   - Go's flag errors keep single dashes ("flag needs an argument: -u");
   - an unknown `--key` only warns and then runs the stdin pipe; consider an
     error when stdin is a terminal;
   - `lw tls cert --host` could become `--hosts` (keeping `--host`), to match
     `tls.hosts` and the preset key;
   - top-level usage errors exit 1, subcommand ones 2.
4. `GET /favicon.ico` answers 404; the logo could serve as the icon once the
   pages' CSP allows `img-src 'self'`.
5. TLS: the generated-certificate key is one per process, so a pin taken from a
   `self_signed` listener also matches an `issuer` listener of the same
   process; document it or key per listener. Pins are checked in
   `VerifyPeerCertificate`, which Go skips on resumption: guard it if a dialer
   ever keeps a `ClientSessionCache`.
6. `core.ShutdownTimeout` is unused.
