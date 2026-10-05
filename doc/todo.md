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
- `make install` with `DESTDIR`, `PREFIX` and `SYSCONFDIR`: the binary, the
  `doc/lw.1` manual, bash, zsh and fish completion generated from `cmd/lw`'s
  `shorts` and `commands` tables, and the service files in `deploy/package/`
  (systemd unit, sysusers, tmpfiles, FreeBSD rc.d script).
- `make deb`, a binary package built with `dpkg-deb`.
- Skeletons in `deploy/package/arch/` and `deploy/package/freebsd/`.
- `.github/workflows/package.yml`: `makepkg` on the PKGBUILD, the `.deb`
  installed, started and purged, BSD make and the rc.d service on FreeBSD
  15.1, and `make image image-check`.

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
- `internal/config` already compiles for `GOOS=js`; it links no net/http,
  crypto/tls or terminal code.
- `github.com/lixenwraith/terminal` (pinned) and its `tui` package: regions,
  layout, boxes, List, Tree, TabBar, StatusBar, TextField, Form, Modal,
  ConfirmDialog, scrolling, mouse. `github.com/lixenwraith/color`: RGB,
  blending, RGBTo256, RGBTo16.

What is missing:
- A machine-readable option schema. Defaults, enums and required checks live
  inside the plugin constructors (about 50 `Default*` constants, 24 inline
  validators); `doc/sources.md`, `doc/sinks.md`, `config/logwisp.toml` and the
  site's catalogue copy them by hand, and the site's copy already lags.
- Offline plugin validation: the constructors mix their checks with reading
  certificates, credentials and files.
- Typed command-line values: `lw --sink http,port=8080 --dump` prints
  `port = "8080"`, a file `port = 8080`.
- A host-independent preset: `fileSource` (`preset.go`) decides directory or
  pattern with `os.Stat`, so off the target host `path=/var/log` expands to
  directory `/var`, pattern `log`.
- Emitters: only parsers exist for the three forms.

Steps:
1. Schema, in `internal/config`, as the one source of truth.
   - Tags on the option structs: `default:`, `help:`, and `lw:` for required,
     enum, min and max, what zero means (default, none, unlimited), hints
     (path, regex, file) and roles (listener, dialer) on the shared tls, auth
     and acl tables.
   - One catalogue table, one row per plugin type: role, network role, single
     instance, summary, option struct. `RegisterSource`/`RegisterSink` panic on
     a type without a row.
   - `Decode[T](role, type, map)` applies defaults, unknown-key and tag checks,
     then the struct's pure `Check()`. Every constructor decodes through it and
     keeps only I/O; the `Default*` constants and inline validators go.
   - Pure cross-field checks become methods that tlsx, authz and netacl call
     first: TLS role rules, auth bindings without file reads, ACL parsing, the
     http sink's paths, filter regexes.
   - `Coerce` converts command-line and environment strings, and JSON floats,
     to the declared kinds; `spec.go` uses it, so a command line dumps typed.
   - `ValidateConfig` adds unique plugin ids per pipeline and decodes every
     plugin, naming the path (`pipelines[0].plugin_sinks[view].config.port`).
     It opens nothing; `lw --check` stays the authority on files.
   - Keep under test what moves: file sink `min_disk_free_mb` (negative means
     100, 0 means none), a backoff maximum below the minimum, format `text`.
2. Engine, `internal/compose`.
   - Imports internal/config, internal/version and lixenwraith/toml only; a
     test fails when `go list -deps` shows net, crypto/tls, os/exec, os/signal,
     x/term or the auth, log and terminal modules.
   - Starts: empty; a preset, with a `stat` function that is nil off the host
     (the UI then asks "directory or file pattern"); a loaded configuration; a
     pasted command line (wrapping `cliSpecs` and `buildPipelines`).
   - Operations: add or remove a source, sink or filter; set or unset an
     option; move a filter; validate.
   - Emitters, one form per call:
     - Command line: `--pipeline NAME`, `id=`, the rate limit policy and
       heartbeat `enabled` always explicit (their command-line defaults differ
       from the file's); `--key=value` when a value starts with `-`; `,` `=`
       `\` escaped; POSIX-quoted.
     - Environment: `LOGWISP_SOURCE_1` and the rest, single-quoted
       `KEY='value'` lines; an error for more than one pipeline, which the
       environment form cannot hold.
     - File: the TOML `lw --dump` prints for those pipelines.
3. `lw --schema`, a parser switch like `--help` (not a Config field, so no
   file or environment can trigger it). It prints one JSON document: version;
   settings with kind, default, enum, flag and variable; the pipeline flags;
   flow stage order; the tls, auth and acl tables; sources, sinks, presets.
   The site generates its catalogue from it.
4. In `lixenwraith/terminal`, released and pinned before the TUI:
   - Full-screen 8- and 16-color output (SGR 30-37, 90-97, 40-47) and the
     default colors 39/49; it emits only 256-color and truecolor today.
   - Detection as `inline` does it: 16 colors on text consoles, none under
     `NO_COLOR`, refusal on `TERM=dumb`, and an override for LogWisp's `color`
     key.
   - Drawing on `/dev/tty`, so `lw --tui > logwisp.toml` and `cmd | lw --tui`
     keep stdin and stdout as data.
   - Bracketed paste into text fields.
   - `tui` widgets the site's controls have: segmented choice, filterable
     option list, toggle, typed fields (default as placeholder, required mark,
     error and help line, folded groups), a focus ring; every widget styled
     from one `tui.Theme`.
   - In `color`, optional: export the 16 xterm reference shades. RGBTo16 maps
     the site's hues badly (green to cyan, red to bright black), so the
     8-color tier is chosen by hand.
5. `lw --tui`.
   - A parser switch, no short form. With `-c FILE`, pipeline flags or
     `LOGWISP_SOURCE` it starts from that composition, and never rewrites FILE
     (TOML encoding drops its comments); bare, it opens the preset menu (pipe,
     tail, serve, edge, aggregator, empty).
   - The pipeline as the site draws it: SOURCES, FLOW, SINKS; a node is a
     tinted bar, its type, listens or dials, and a summary line; the four flow
     stages in order inside a dashed box, the ones off dimmed; wires drawn from
     per-cell connectivity so every junction is right. The inspector sits
     below at 80 to 109 columns, beside at 110 and over; under 64 columns the
     stages stack, as on the site.
     ```
      ● SOURCES              ● FLOW                       ● SINKS
      ▌ file             ─┐  ╭╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╮  ┌─▌ http      listens
      ▌ /var/log  *.log   │  ╎ ▌ rate_limit 400/s   ╎  │ ▌ :8080  /stream
      █ tcp_chain listens─┴─►╎ ▌ filters -TRACE     ╎─►┤
      █ :9000  tls  scram    ╎ ▌ format txt         ╎  └─▌ console
                             ╎ ○ heartbeat off      ╎    ▌ stdout
                             ╰╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╯
     ── tcp_chain · source · id src-2 ─────────────────── ⏎ edit  tab next ──
        host     0.0.0.0  default        format   raw [txt] json
        port *   9000▌                   tls      ▸ on   (auth, acl folded)
      ✓ valid   a add  d delete  ␣ on/off  J/K move  p preset  o output  ? help
     ```
   - Keys: arrows or hjkl move, Enter edits, `a` adds from the catalogue, `d`
     deletes, Space switches a flow stage, `J`/`K` reorder filters, `p`
     presets, `[` `]` switch pipelines, `c` lists errors, `o` output, `?`
     help, `q` quits.
   - Theme: the site's dark tokens as one role table in four tiers. Truecolor
     and 256 colors paint the site's background; 8 colors and mono keep the
     terminal's. Sources cyan, flow violet, sinks green, accent blue, muted
     grey, errors red. A selection always changes a glyph (bar, `▸`,
     underline), never only a shade. Glyphs: Unicode, a CP437 set on text
     consoles, ASCII outside UTF-8.
   - Output, `o`: Run hands `config.Args` built from the composition to the
     usual `config.Load`, after the terminal is released and before anything
     reads stdin; reloads keep the pipelines, and `--tui --check` and `--tui
     --dump` follow. Or exactly one of command line, environment and file,
     printed to stdout once the screen closes.
6. WebAssembly: `cmd/lwconf` (`js && wasm`) exposes schema, preset, parse,
   validate and emit to the page as JSON strings. `make wasm` builds
   `bin/lwconf.wasm` with the version stamped, copies the toolchain's
   `wasm_exec.js`, and prints both checksums. A prototype measured about 6 MB,
   1.7 MB gzipped, ready in about 60 ms in Chromium; `wasm_exec.js` uses no
   eval, so the page needs only `'wasm-unsafe-eval'` in its `script-src`.

Verify:
- A Go test in `cmd/lw`: for every preset, an edge and aggregator pair,
  escaped values and two pipelines, the pipelines loaded from the emitted
  command line, file and environment (one pipeline) are equal. It runs in an
  empty directory with the `LOGWISP_` environment cleared, since a discovered
  file would add settings.
- A schema test: every option has a kind, every enum values, every catalogue
  row a factory; `TestEveryPluginRejectsUnknownKeys` still passes.
- CI builds `cmd/lwconf` for `GOOS=js` and runs a node test of its calls.
- The diagram rendered into a cell buffer at 80x24 and 64x24, per tier; a
  scripted session on a pseudo-terminal for Run and each output.
