# To Do

Planned work, in order of priority. Each item names what to build, how it fits
the existing seams, and how to verify it. Finished items move to the design doc
they belong to.

## 1. Packaging: AUR, FreeBSD ports, Debian

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

## 2. Follow-ups

Smaller items found along the way, each independent of the others.

1. Level detection. `source.ExtractLogLevel` needs a delimiter after the name
   (`ERROR:`, `[WARN]`, ` INFO `), so `warning disk full` or `DBG x` get no
   level, hence no color. Match the names as words, as the console sink's
   painter does, with one table for both.
2. Command line:
   - a positional word at the top level (`lw tail`, `lw -t FILE`) still reaches
     config with an unclear message; name it ("unexpected argument X; the file
     is -c FILE");
   - Go's flag errors keep single dashes ("flag needs an argument: -u");
   - an unknown `--key` only warns and then runs the stdin pipe; consider an
     error when stdin is a terminal;
   - `lw tls cert --host` could become `--hosts` (keeping `--host`), to match
     `tls.hosts` and the preset key;
   - top-level usage errors exit 1, subcommand ones 2.
3. TLS: the generated-certificate key is one per process, so a pin taken from a
   `self_signed` listener also matches an `issuer` listener of the same
   process; document it or key per listener. Pins are checked in
   `VerifyPeerCertificate`, which Go skips on resumption: guard it if a dialer
   ever keeps a `ClientSessionCache`.
4. `core.ShutdownTimeout` is unused.
