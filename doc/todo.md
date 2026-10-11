# To Do

Planned work, in order of priority. Each item names what to build, how it fits
the existing seams, and how to verify it. Finished items move to the design doc
they belong to.

## 1. Packaging: AUR, FreeBSD ports, Debian

[Installation](installation.md#packaging-status) lists what is in place. The
`lw` name is free in Arch (official repositories and AUR), Ubuntu 24.04 and
26.04, and the FreeBSD 15.1 ports tree; `go install`, FreeBSD's
`USES=go:modules` and Debian's dh-golang expect the module path
`github.com/lixenwraith/logwisp`.

What remains is the maintainer's: it needs push rights, an identity or a
release tag, and both skeletons download the tagged source.

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
   - `make deb` serves direct installs. A PPA builds from a signed source
     package without network access: a `debian/` directory (changelog,
     control, rules) and the Go modules vendored into the source tarball.
   - The archive wants every Go dependency packaged (dh-golang); the
     `lixenwraith` libraries in `go.mod` are not.
   - `lintian` on the `make deb` package reports `no-changelog` (a source
     package's `debian/changelog` provides it), `statically-linked-binary`
     (lw is static by design) and `maintainer-script-calls-systemctl` (dh's
     scripts use `deb-systemd-helper` instead).
5. With a tag, the packaging workflow's FreeBSD job can build the port itself
   from a ports tree (`make stage check-plist` in a copy of
   `deploy/package/freebsd/`), rather than BSD make on the checkout.

## 2. What `lw --tui` and its engine leave for later

`lw --tui` ([CLI](cli.md#lw---tui)) and the configuration engine it shares
with the website ([Architecture](architecture.md#configuration-engine)) are
in place. Not yet:
- Pins and export in the live view, as vif-log has them: pinned rows survive
  filter changes and show alone on a key; the pins or the shown rows go to a
  new file.
- Per-sink taps: what each sink took, where the tap at the flow's exit shows
  what dispatch offered (a full sink input drops for that sink only).
- Live filter patching: a filter edited while `t` runs takes effect through
  `Filter.UpdatePatterns` (unused), not a rerun that rebinds every listener.
- The wide-rune table `internal/tui/view.go` copies from
  `lixenwraith/terminal`'s one-cell rule goes once terminal exports that rule.
- A scripted session on a pseudo-terminal for Run, each output and `t` (keys,
  the password dialog, `SIGHUP`), on a text console and over ssh.
- The schema lists `auth.node_binding` on every listener and
  `auth.trusted_proxies` on both HTTP listeners, though `AuthOptions.Check`
  refuses a binding off the chain sources (under `mtls` or `scram`) and
  `trusted_proxies` off the `http` sink; side tags for chain sources and the
  `http` sink would filter them as `http` filters HTTP's keys.
- Optional, in `lixenwraith/color`: export the 16 xterm reference shades
  (`RGBTo16` maps the site's hues badly, so the 16-color tier is chosen by
  hand).
