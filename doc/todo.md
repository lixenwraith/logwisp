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
release tag, and both recipes download the tagged source; they name 0.40.0,
the first release.

1. Tag the release on the merged main commit, `vX.Y.Z`:
   ```
   git tag -a vX.Y.Z -m vX.Y.Z      # git tag -s signs it with your key
   git push origin vX.Y.Z
   ```
   - The Makefile's builds then stamp `vX.Y.Z` (from `git describe`), and
     `go install github.com/lixenwraith/logwisp/cmd/lw@vX.Y.Z` works.
   - A GitHub release for the tag is optional; the tag alone serves
     `archive/vX.Y.Z.tar.gz`, which the PKGBUILD downloads.
2. Arch (AUR), from `deploy/package/arch/PKGBUILD`:
   - Once: an account on aur.archlinux.org holding the public half of an SSH
     key (`ssh-keygen -f ~/.ssh/aur`), and in `~/.ssh/config`:
     ```
     Host aur.archlinux.org
       IdentityFile ~/.ssh/aur
       User aur
     ```
   - Clone the package's repository, empty until the first push creates the
     package; the AUR takes only the `master` branch:
     ```
     git -c init.defaultBranch=master clone ssh://aur@aur.archlinux.org/logwisp.git ~/aur/logwisp
     cp deploy/package/arch/PKGBUILD ~/aur/logwisp/
     ```
   - In the copy: the `# Maintainer: Name <email>` line, `pkgver=X.Y.Z` and
     `pkgrel=1`, then `updpkgsums` (pacman-contrib), which replaces
     `sha256sums=('SKIP')` with the tag tarball's sum. The repository's
     PKGBUILD keeps `SKIP`: `make arch` builds it from the working tree.
   - `makepkg -si` builds, runs `check()` and installs; `namcap PKGBUILD` and
     `namcap logwisp-X.Y.Z-1-x86_64.pkg.tar.zst` lint the recipe and the
     package. A clean chroot (`extra-x86_64-build`, from devtools) shows a
     missing dependency.
   - `makepkg --printsrcinfo > .SRCINFO`, after every change to the
     PKGBUILD; `git add PKGBUILD .SRCINFO`, commit, `git push`. Commit only
     those two: the build leaves `src/`, `pkg/` and the tarballs beside them.
   - A later release repeats the copy's steps with its version; a fix to the
     recipe alone raises `pkgrel`. Optionally a `logwisp-git` package built
     from the main branch.
3. FreeBSD, `deploy/package/freebsd/` (`sysutils/logwisp`), copied into a
   ports tree with `cp -RL` (`files/logwisp.in` links to
   `deploy/package/logwisp.rc`):
   - `DISTVERSION=X.Y.Z` and `MAINTAINER=` your address.
   - `make makesum` writes `distinfo`, the checksums of the `.mod` and `.zip`
     that the Go proxy serves for `GO_MODULE` at the tag.
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
   from a ports tree (`make stage check-plist` in a `cp -RL` copy of
   `deploy/package/freebsd/`), rather than BSD make on the checkout.
