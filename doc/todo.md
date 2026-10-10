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
- `make install` with `DESTDIR`, `PREFIX`, `SYSCONFDIR` and `SERVICE`: the
  binary, the `doc/lw.1` manual, bash, zsh and fish completion generated from
  `cmd/lw`'s `shorts` and `commands` tables, and the service files in
  `deploy/package/` (systemd unit, sysusers, tmpfiles, FreeBSD rc.d script)
  with the configuration, kept on reinstall.
- `make deb`, a binary package built with `dpkg-deb`, and `make arch`, the
  PKGBUILD built from the working tree.
- Skeletons in `deploy/package/arch/` and `deploy/package/freebsd/`.
- `.github/workflows/package.yml`: `make arch`, the `.deb` and BSD make on
  FreeBSD 15.1, each reinstalled over an edited configuration; the systemd
  and rc.d services run; a home install with `SERVICE=no` and
  `lw config init`; and `make image image-check`.

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
   - The archive wants every Go dependency packaged (dh-golang); the four
     `lixenwraith` libraries are not.
   - `lintian` on the `make deb` package reports `no-changelog` (a source
     package's `debian/changelog` provides it), `statically-linked-binary`
     (lw is static by design) and `maintainer-script-calls-systemctl` (dh's
     scripts use `deb-systemd-helper` instead).
5. With a tag, the packaging workflow's FreeBSD job can build the port itself
   from a ports tree (`make stage check-plist` in a copy of
   `deploy/package/freebsd/`), rather than BSD make on the checkout.

## 2. `lw --tui` and the configuration engine it shares with lixen.com

`lw --tui` composes pipelines in a full-screen terminal UI, then either runs
them at once or prints one form of them, chosen on exit: a command line,
environment variables, or a configuration file. Its logic is a pure engine that
lixen.com's planned Configure tab (lixencom `doc/todo.md`) runs as WebAssembly,
so no part of LogWisp is rewritten in JavaScript.

What exists:
- Option structs with toml tags for every plugin and flow stage
  (`internal/config/config.go`), presets as rows with typed parameters
  (`preset.go`), the command-line and environment grammar (`spec.go`),
  `ValidateConfig`, `--check` and `--dump`.
- The option schema, in `internal/config`: `default:`, `help:` and `lw:` tags
  on the option structs, one catalogue row per plugin type, `Decode` (every
  constructor decodes through it and keeps only I/O), `Coerce` for typed
  command-line values, and a `ValidateConfig` that decodes every plugin
  offline and names the refused key's path.
- `internal/config` already compiles for `GOOS=js`; it links no net/http,
  crypto/tls or terminal code.
- The engine, `internal/compose`: starts empty, from a preset (whose path
  `config.IsDir` resolves, nil off the host), a loaded configuration or a
  pasted command line; adds, removes and moves sources, sinks and filters,
  sets and unsets keys, validates; writes a command line, environment
  variables or a file, each loading back to the same pipelines. Its test
  fails when it links TLS, HTTP, process, signal or terminal code.
- `lw --schema`: settings, pipeline flags, flow stages in order, the tls,
  auth and acl tables, sources, sinks and presets, as one JSON document.
- `github.com/lixenwraith/terminal` (pinned) and its `tui` package: regions,
  layout, boxes, List, Tree, TabBar, StatusBar, TextField, Form, Modal,
  ConfirmDialog, scrolling, mouse; themed Radio, Field, TextInput,
  OptionList and menus, Frame, Rule, Wires and Window, which `lw --tui`
  draws with. `github.com/lixenwraith/color`: RGB,
  blending, RGBTo256, RGBTo16.

Steps:
1. Schema, in `internal/config`: done.
2. Engine, `internal/compose`: done.
3. `lw --schema`: done. The site generates its catalogue from it.
4. `lixenwraith/terminal` v0.2.0: done: 16 and no color, the terminal's
   default colors, `/dev/tty`, bracketed paste, themed form controls. Still
   optional, in `color`: export the 16 xterm reference shades (RGBTo16 maps
   the site's hues badly, so the 16-color tier is chosen by hand). v0.3.0:
   radio buttons, narrow form fields and option lists, menus, frames, rules,
   wires and windows, moved from `lw --tui`.
5. `lw --tui`: done ([doc/cli.md](cli.md#lw---tui)).
6. WebAssembly: done. `make wasm` builds `bin/lwconf.wasm`, version stamped,
   beside the toolchain's `wasm_exec.js`, and prints both checksums: about
   6.9 MB, 1.9 MB gzipped. `wasm_exec.js` uses no eval, so the page needs only
   `'wasm-unsafe-eval'` in its `script-src`. The page runs the module with
   `new Go().run(instance)`, then calls `globalThis.lwconf`; each call takes
   strings and returns a JSON object, `{"value": ...}` or `{"error": "..."}`:
   - `schema()`: what `lw --schema` prints.
   - `preset(name, values)`: a preset's pipelines; `values` is a JSON object
     of strings, and a directory path ends in `/`.
   - `parse(line)`: a pasted command line's pipelines.
   - `validate(pipelines)`: the pipelines settled (defaults, kinds, ids), or
     the first problem by its key path.
   - `emit(pipelines, form)`: `command`, `environment` or `file`.
   - Pipelines are a JSON list in the file's shape (`name`, `flow`,
     `plugin_sources`, `plugin_sinks`); a misspelled key is refused.

Still to verify: a scripted session on a pseudo-terminal for Run and each
output.
