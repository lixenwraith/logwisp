# LogWisp. GNU make and BSD make alike: no conditionals or functions specific
# to either; decisions run in the shell. Plain `make` prints the targets.

BINARY := lw
SRC := ./cmd/lw
BIN_DIR := bin
PKG_DIR := deploy/package
WEB_DIR := internal/sink/http/web

VERSION_DEFAULT != git describe --tags --always --dirty 2>/dev/null || echo dev
VERSION ?= $(VERSION_DEFAULT)
GIT_COMMIT_DEFAULT != git rev-parse --short HEAD 2>/dev/null || echo unknown
GIT_COMMIT ?= $(GIT_COMMIT_DEFAULT)
# SOURCE_DATE_EPOCH makes package builds reproducible; GNU date takes -d, BSD date -r.
BUILD_TIME_DEFAULT != f='+%Y-%m-%d_%H:%M:%S'; e="$${SOURCE_DATE_EPOCH:-}"; \
	if [ -n "$$e" ]; then date -u -d "@$$e" "$$f" 2>/dev/null || date -u -r "$$e" "$$f"; else date -u "$$f"; fi
BUILD_TIME ?= $(BUILD_TIME_DEFAULT)
# The image and the wasm stamp the commit time, so a rebuild of one commit
# stays cached, and the website's engine keeps its checksums
IMAGE_BUILD_TIME_DEFAULT != TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d_%H:%M:%S 2>/dev/null || echo unknown
IMAGE_BUILD_TIME ?= $(IMAGE_BUILD_TIME_DEFAULT)
COMMIT_LDFLAGS = -X 'github.com/lixenwraith/logwisp/internal/version.Version=$(VERSION)' \
	-X 'github.com/lixenwraith/logwisp/internal/version.GitCommit=$(GIT_COMMIT)'
VERSION_LDFLAGS = $(COMMIT_LDFLAGS) -X 'github.com/lixenwraith/logwisp/internal/version.BuildTime=$(BUILD_TIME)'
# Not LDFLAGS/GOFLAGS: packagers export those for the C linker and go itself.
GO_BUILDFLAGS ?=
GO_LDFLAGS ?=

# FreeBSD packages each Go release under its own name: go.mod's 1.27 is go127.
GO_DEFAULT != uname -s | grep -q FreeBSD && sed -n 's/^go \([0-9]*\)\.\([0-9]*\).*/go\1\2/p' go.mod 2>/dev/null | grep . || echo go
GO ?= $(GO_DEFAULT)

E2E ?= test/*-test.sh

CONTAINER_ENGINE ?= docker
IMAGE ?= logwisp
IMAGE_TAG ?= dev
IMAGE_REVISION_DEFAULT != git rev-parse HEAD 2>/dev/null || echo unknown
IMAGE_REVISION ?= $(IMAGE_REVISION_DEFAULT)
# A PEM bundle the builder trusts while downloading modules (an intercepting
# proxy); it reaches the build as a BuildKit secret, never a layer.
BUILD_CA ?=
IMAGE_BUILD_FLAGS ?=
IMAGE_CHECK_CONFIG ?= config/logwisp.toml
IMAGE_RUN = $(CONTAINER_ENGINE) run --read-only --user 65532:65532 \
	--network none --cap-drop ALL --security-opt no-new-privileges

DESTDIR ?=
INSTALL_OS_DEFAULT != uname -s
INSTALL_OS ?= $(INSTALL_OS_DEFAULT)
# FreeBSD keeps everything outside the base system under /usr/local.
SYSTEM_PREFIX != [ '$(INSTALL_OS)' = FreeBSD ] && echo /usr/local || echo /usr
# Unstaged, a user who cannot write the system's bin directory installs for
# itself: under ~/.local, without the service. sudo make install is system-wide.
USER_INSTALL != [ -z '$(DESTDIR)' ] && [ "$$(id -u)" != 0 ] && [ ! -w '$(SYSTEM_PREFIX)/bin' ] && echo yes || echo no
PREFIX_DEFAULT != [ '$(USER_INSTALL)' = yes ] && echo "$$HOME/.local" || echo '$(SYSTEM_PREFIX)'
PREFIX ?= $(PREFIX_DEFAULT)
SYSCONFDIR_DEFAULT != if [ '$(USER_INSTALL)' = yes ]; then echo "$$HOME/.config"; \
	elif [ '$(INSTALL_OS)' = FreeBSD ]; then echo /usr/local/etc; else echo /etc; fi
SYSCONFDIR ?= $(SYSCONFDIR_DEFAULT)
# SERVICE=no leaves out the service files and the configuration, which lw
# config init then places where the user wants it.
SERVICE_DEFAULT != [ '$(USER_INSTALL)' = yes ] && echo no || echo yes
SERVICE ?= $(SERVICE_DEFAULT)
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
DOCDIR ?= $(PREFIX)/share/doc/logwisp
LICENSEDIR ?= $(PREFIX)/share/licenses/logwisp
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
# Debian's zsh reads /usr/share/zsh/vendor-completions, not site-functions
ZSHCOMPDIR_DEFAULT != [ '$(PREFIX)' = /usr ] && [ -f /etc/debian_version ] && \
	echo /usr/share/zsh/vendor-completions || echo '$(PREFIX)/share/zsh/site-functions'
ZSHCOMPDIR ?= $(ZSHCOMPDIR_DEFAULT)
FISHCOMPDIR ?= $(PREFIX)/share/fish/vendor_completions.d
DEB_MAINTAINER ?= Maintainer <maintainer@example.org>

.DEFAULT_GOAL := help
# Goals run in the order given, so make release install installs what it built.
.NOTPARALLEL:

.PHONY: help check-go build release dev wasm test verify e2e image image-check install uninstall deb arch completion clean version

help:
	@echo "Usage: make <target> [VARIABLE=value ...]"
	@echo ""
	@echo "Build:"
	@echo "  build        Build $(BIN_DIR)/$(BINARY) with version metadata"
	@echo "  release      Build it static, stripped and trimmed (CGO_ENABLED=0)"
	@echo "  dev          Build it with the race detector"
	@echo "  wasm         Write $(WASM_DIR)/, the engine a website drops in: lwconf.wasm, its"
	@echo "               loader wasm_exec.js, lwconf.js, schema.json, and lwconf.json, their manifest"
	@echo "  version      Print the version metadata a build embeds"
	@echo "  completion   Regenerate $(PKG_DIR)/completion from lw's command tables"
	@echo "  clean        Remove $(BIN_DIR)/"
	@echo "Check:"
	@echo "  test         Run the Go tests"
	@echo "  verify       vet, gofmt, tests, linux, freebsd and wasm cross builds, node tests"
	@echo "  e2e          Build, then run each of $(E2E) with --auto and report"
	@echo "Container:"
	@echo "  image        Build $(IMAGE):$(IMAGE_TAG) with $(CONTAINER_ENGINE) (scratch, static, UID 65532)"
	@echo "  image-check  Run it read-only, offline, without capabilities: --version, then"
	@echo "               --check on $(IMAGE_CHECK_CONFIG)"
	@echo "Install (build or release first, as in make release install):"
	@echo "  install      Binary, manual, shell completion, licence and docs under $(PREFIX); unless"
	@echo "               SERVICE=no, the service files and $(SYSCONFDIR)/logwisp/logwisp.toml (kept"
	@echo "               if present). A user who cannot write $(SYSTEM_PREFIX)/bin gets ~/.local and no service"
	@echo "  uninstall    Remove them, keeping $(SYSCONFDIR)/logwisp"
	@echo "  deb          Package a release build as $(BIN_DIR)/logwisp_VERSION_ARCH.deb (dpkg-deb)"
	@echo "  arch         Build the Arch package from this working tree in $(BIN_DIR)/arch (makepkg)"
	@echo ""
	@echo "Variables: GO=$(GO) PREFIX=$(PREFIX) SYSCONFDIR=$(SYSCONFDIR) DESTDIR=$(DESTDIR) SERVICE=$(SERVICE)"
	@echo "  INSTALL_OS=$(INSTALL_OS) (the layout install uses: FreeBSD or any other)"
	@echo "  GO_BUILDFLAGS, GO_LDFLAGS (extra go build and linker flags), E2E (scripts),"
	@echo "  CONTAINER_ENGINE, IMAGE, IMAGE_TAG, BUILD_CA, IMAGE_BUILD_FLAGS, IMAGE_CHECK_CONFIG,"
	@echo "  BASHCOMPDIR, ZSHCOMPDIR, FISHCOMPDIR, DEB_MAINTAINER"

check-go:
	@command -v $(GO) >/dev/null 2>&1 || { \
		echo "Go toolchain '$(GO)' not found; go.mod requires go $$(sed -n 's/^go //p' go.mod)."; \
		[ -z "$${SUDO_USER:-}" ] || echo "  sudo may reset PATH: make release as $$SUDO_USER, then sudo make install"; \
		if [ "$$(uname -s)" = FreeBSD ]; then echo "  FreeBSD: pkg install $(GO_DEFAULT)"; \
		elif [ -f /etc/arch-release ]; then echo "  Arch Linux: pacman -S go"; \
		else echo "  Elsewhere: https://go.dev/dl/ (distribution packages often lag)"; fi; \
		echo "  Or name a toolchain: make GO=/path/to/go ..."; \
		exit 1; }

build: check-go
	$(GO) build $(GO_BUILDFLAGS) -ldflags "$(VERSION_LDFLAGS) $(GO_LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(SRC)

release: check-go
	CGO_ENABLED=0 $(GO) build -trimpath $(GO_BUILDFLAGS) -ldflags "-s -w $(VERSION_LDFLAGS) $(GO_LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(SRC)

dev: check-go
	$(GO) build -race $(GO_BUILDFLAGS) -ldflags "$(VERSION_LDFLAGS) $(GO_LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(SRC)

# The page loads the toolchain's own loader, which uses no eval: its CSP needs
# only 'wasm-unsafe-eval'. schema.json is lw --schema stamped as the engine is,
# so it equals the engine's schema(); lwconf.json records the build.
WASM_DIR = $(BIN_DIR)/lwconf
WASM_FILES = lwconf.wasm wasm_exec.js lwconf.js schema.json
WASM_LDFLAGS = -s -w $(COMMIT_LDFLAGS) -X 'github.com/lixenwraith/logwisp/internal/version.BuildTime=$(IMAGE_BUILD_TIME)' $(GO_LDFLAGS)
wasm: check-go
	@rm -rf $(WASM_DIR) && mkdir -p $(WASM_DIR)
	GOOS=js GOARCH=wasm $(GO) build -trimpath $(GO_BUILDFLAGS) -ldflags "$(WASM_LDFLAGS)" -o $(WASM_DIR)/lwconf.wasm ./cmd/lwconf
	install -m 0644 "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" cmd/lwconf/lwconf.js $(WASM_DIR)
	$(GO) run -trimpath $(GO_BUILDFLAGS) -ldflags "$(WASM_LDFLAGS)" $(SRC) --schema > $(WASM_DIR)/schema.json
	@set -eu; go=$$($(GO) env GOVERSION); cd $(WASM_DIR); \
	sums=$$(sha256sum $(WASM_FILES) 2>/dev/null || sha256 -r $(WASM_FILES)); echo "$$sums"; \
	{ printf '{\n  "version": "%s",\n  "commit": "%s",\n  "go": "%s",\n  "sha256": {' '$(VERSION)' '$(GIT_COMMIT)' "$$go"; \
		echo "$$sums" | awk '{ sub(/^\*/, "", $$2); printf "%s\n    \"%s\": \"%s\"", (NR > 1 ? "," : ""), $$2, $$1 }'; \
		printf '\n  }\n}\n'; } > lwconf.json

test: check-go
	$(GO) test ./...

# A test fails when the committed scripts differ from what the tables generate
completion: check-go
	$(GO) test ./cmd/lw -run '^TestCompletionScriptsAreCurrent$$' -args -update

# gofmt checks the Go files changed since the branch forked from GOFMT_BASE,
# exact renames aside, or the whole tree without git or that ref: older files
# predate the gate, and AGENTS.md formats what a change touches.
GOFMT_BASE ?= main
verify: test
	$(GO) vet ./...
	@base='$(GOFMT_BASE)'; \
	if [ -n "$$base" ] && fork=$$(git merge-base "$$base" HEAD 2>/dev/null); then \
		files=$$( { git diff --name-only --find-renames=100% --diff-filter=dr "$$fork" -- cmd config internal; \
			git ls-files --others --exclude-standard -- cmd config internal; } | grep '\.go$$' || true); \
	else \
		files=$$(find cmd config internal -name '*.go'); \
	fi; \
	bad=$$( [ -z "$$files" ] || "$$($(GO) env GOROOT)/bin/gofmt" -l $$files ); \
	if [ -n "$$bad" ]; then echo "gofmt -l reports:"; echo "$$bad"; exit 1; fi
	@for target in linux/amd64 linux/arm64 freebsd/amd64 freebsd/arm64; do \
		echo "cross build $$target"; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} $(GO) build -o /dev/null $(SRC) || exit 1; \
	done
	@echo "cross build js/wasm"; GOOS=js GOARCH=wasm $(GO) build -o /dev/null ./cmd/lwconf
	@if command -v node >/dev/null 2>&1; then \
		(cd $(WEB_DIR) && node --test) && cd cmd/lwconf && GO='$(GO)' node --test; \
	else \
		echo "node not found: web client and lwconf tests skipped"; \
	fi

# A script exits 0 (passed), 77 (skipped: the host lacks what it tests) or
# anything else (failed); only failures fail the target.
e2e: build
	@if [ "$${FORCE_COLOR:-0}" != 0 ] || { [ -t 1 ] && [ -z "$${NO_COLOR:-}" ]; }; then \
		g=$$(printf '\033[1;32m'); r=$$(printf '\033[1;31m'); y=$$(printf '\033[1;33m'); \
		b=$$(printf '\033[1m'); o=$$(printf '\033[0m'); \
	else g=; r=; y=; b=; o=; fi; \
	pass=0; fail=0; skip=0; results=; \
	for t in $(E2E); do \
		echo; "$$t" --auto; rc=$$?; \
		case $$rc in \
		0) pass=$$((pass + 1)); results="$$results PASS:$$t" ;; \
		77) skip=$$((skip + 1)); results="$$results SKIP:$$t" ;; \
		*) fail=$$((fail + 1)); results="$$results FAIL:$$t:$$rc" ;; \
		esac; \
	done; \
	printf '\n%se2e summary%s\n' "$$b" "$$o"; \
	for x in $$results; do \
		st=$${x%%:*}; t=$${x#*:}; c=$$g; note=; \
		case $$st in SKIP) c=$$y ;; FAIL) c=$$r; note=" (exit $${t##*:})"; t=$${t%:*} ;; esac; \
		printf '  %s%s%s  %s%s\n' "$$c" "$$st" "$$o" "$$t" "$$note"; \
	done; \
	c=$$g; [ "$$fail" -eq 0 ] || c=$$r; \
	printf '%se2e: %d passed, %d failed, %d skipped%s\n' "$$c" "$$pass" "$$fail" "$$skip" "$$o"; \
	[ "$$fail" -eq 0 ]

image:
	@set --; if [ -n '$(BUILD_CA)' ]; then set -- --secret 'id=build_ca,src=$(BUILD_CA)'; fi; \
	set -x; \
	$(CONTAINER_ENGINE) build "$$@" $(IMAGE_BUILD_FLAGS) \
		--build-arg VERSION='$(VERSION)' \
		--build-arg REVISION='$(IMAGE_REVISION)' \
		--build-arg BUILD_TIME='$(IMAGE_BUILD_TIME)' \
		-t '$(IMAGE):$(IMAGE_TAG)' .

# --check builds every pipeline and plugin, as a start would, and binds nothing
image-check:
	$(IMAGE_RUN) --rm '$(IMAGE):$(IMAGE_TAG)' --version
	@set -eu; cfg='$(IMAGE_CHECK_CONFIG)'; case "$$cfg" in /*) ;; *) cfg="$$(pwd)/$$cfg" ;; esac; \
	$(IMAGE_RUN) --rm --mount "type=bind,src=$$cfg,dst=/etc/logwisp/logwisp.toml,readonly" \
		'$(IMAGE):$(IMAGE_TAG)' --check -c /etc/logwisp/logwisp.toml

# install stages what a package ships and compiles nothing, so a packager owns
# the build flags. It writes nothing until every directory it needs is
# writable, and leaves existing directories as they are. The service files get
# the installed paths substituted; a configuration already in place is kept.
install:
	@set -eu; \
	[ -x $(BIN_DIR)/$(BINARY) ] || { echo "no $(BIN_DIR)/$(BINARY): make build or make release first, as in make release install" >&2; exit 1; }; \
	case '$(SERVICE)' in yes|no) ;; *) echo "SERVICE is yes or no, not '$(SERVICE)'" >&2; exit 2 ;; esac; \
	root='$(DESTDIR)'; etc="$$root$(SYSCONFDIR)/logwisp"; \
	dirs='$(BINDIR) $(MANDIR) $(BASHCOMPDIR) $(ZSHCOMPDIR) $(FISHCOMPDIR) $(LICENSEDIR) $(DOCDIR)'; \
	[ '$(SERVICE)' = no ] || case '$(INSTALL_OS)' in \
		FreeBSD) dirs="$$dirs $(SYSCONFDIR)/logwisp $(PREFIX)/etc/rc.d" ;; \
		*) dirs="$$dirs $(SYSCONFDIR)/logwisp $(PREFIX)/lib/systemd/system $(PREFIX)/lib/sysusers.d $(PREFIX)/lib/tmpfiles.d" ;; \
	esac; \
	for d in $$dirs; do d="$$root$$d"; while [ ! -e "$$d" ]; do d=$$(dirname "$$d"); done; \
		[ -w "$$d" ] || { echo "no write access to $$d: sudo make install, or set PREFIX, SYSCONFDIR or SERVICE=no" >&2; exit 1; }; \
	done; \
	if [ '$(USER_INSTALL)' = yes ] && [ '$(PREFIX)' = '$(PREFIX_DEFAULT)' ]; then \
		echo "$(SYSTEM_PREFIX)/bin is not writable: installing for $$(id -un) under $(PREFIX) (sudo make install: system-wide)"; fi; \
	dir() { [ -d "$$1" ] || install -d -m 0755 "$$1"; }; \
	put() { dir "$${3%/*}"; install -m "$$1" "$$2" "$$3"; echo "install $$3"; }; \
	sub() { dir "$${3%/*}"; \
		sed -e 's|@BINDIR@|$(BINDIR)|g' -e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' -e 's|%%BINDIR%%|$(BINDIR)|g' \
			-e 's|%%PREFIX%%/etc|$(SYSCONFDIR)|g' -e 's|%%PREFIX%%|$(PREFIX)|g' "$$2" > "$$3"; \
		chmod "$$1" "$$3"; echo "install $$3"; }; \
	put 0755 $(BIN_DIR)/$(BINARY) "$$root$(BINDIR)/$(BINARY)"; \
	put 0644 doc/lw.1 "$$root$(MANDIR)/man1/lw.1"; \
	put 0644 $(PKG_DIR)/completion/lw.bash "$$root$(BASHCOMPDIR)/lw"; \
	put 0644 $(PKG_DIR)/completion/_lw "$$root$(ZSHCOMPDIR)/_lw"; \
	put 0644 $(PKG_DIR)/completion/lw.fish "$$root$(FISHCOMPDIR)/lw.fish"; \
	put 0644 LICENSE "$$root$(LICENSEDIR)/LICENSE"; \
	for src in README.md logwisp-logo.svg doc/*.md doc/lw.1 config/logwisp.toml; do put 0644 "$$src" "$$root$(DOCDIR)/$$src"; done; \
	if [ '$(SERVICE)' = no ]; then echo "skip    the service and $$etc (SERVICE=no): lw config init writes a configuration"; \
	else \
		if [ -e "$$etc/logwisp.toml" ]; then echo "keep    $$etc/logwisp.toml"; \
		else put 0644 config/logwisp.toml "$$etc/logwisp.toml"; fi; \
		case '$(INSTALL_OS)' in \
		FreeBSD) \
			sub 0755 $(PKG_DIR)/logwisp.rc "$$root$(PREFIX)/etc/rc.d/logwisp" ;; \
		*) \
			sub 0644 $(PKG_DIR)/logwisp.service "$$root$(PREFIX)/lib/systemd/system/logwisp.service"; \
			sub 0644 $(PKG_DIR)/logwisp.sysusers "$$root$(PREFIX)/lib/sysusers.d/logwisp.conf"; \
			sub 0644 $(PKG_DIR)/logwisp.tmpfiles "$$root$(PREFIX)/lib/tmpfiles.d/logwisp.conf" ;; \
		esac; \
	fi; \
	[ -n "$$root" ] || case ":$$PATH:" in *':$(BINDIR):'*) ;; *) echo "note:   $(BINDIR) is not on PATH" ;; esac

uninstall:
	@set -eu; root='$(DESTDIR)'; \
	if [ '$(USER_INSTALL)' = yes ] && [ '$(PREFIX)' = '$(PREFIX_DEFAULT)' ]; then \
		echo "$(SYSTEM_PREFIX)/bin is not writable: uninstalling under $(PREFIX) (sudo make uninstall: system-wide)"; fi; \
	for f in "$$root$(BINDIR)/$(BINARY)" "$$root$(MANDIR)/man1/lw.1" \
		"$$root$(BASHCOMPDIR)/lw" "$$root$(ZSHCOMPDIR)/_lw" "$$root$(FISHCOMPDIR)/lw.fish" \
		"$$root$(PREFIX)/lib/systemd/system/logwisp.service" \
		"$$root$(PREFIX)/lib/sysusers.d/logwisp.conf" "$$root$(PREFIX)/lib/tmpfiles.d/logwisp.conf" \
		"$$root$(PREFIX)/etc/rc.d/logwisp"; do \
		if [ -e "$$f" ]; then rm -f "$$f"; echo "remove  $$f"; fi; \
	done; \
	for d in "$$root$(DOCDIR)" "$$root$(LICENSEDIR)"; do \
		case "$$d" in */logwisp) ;; *) echo "keep    $$d (not a logwisp directory)"; continue ;; esac; \
		if [ -d "$$d" ]; then rm -rf "$$d"; echo "remove  $$d"; fi; \
	done; \
	if [ -d "$$root$(SYSCONFDIR)/logwisp" ]; then echo "keep    $$root$(SYSCONFDIR)/logwisp (configuration and credentials)"; fi

# deb stages install in Debian's layout and takes the architecture from the
# binary. An untagged or modified tree's version sorts below every release and
# by build time, so each build upgrades the last.
deb: release
	@set -eu; stage=$(BIN_DIR)/deb; doc="$$stage/usr/share/doc/logwisp"; rm -rf "$$stage"; \
	$(MAKE) install DESTDIR="$$stage" PREFIX=/usr SYSCONFDIR=/etc INSTALL_OS=Linux \
		LICENSEDIR=/usr/share/doc/logwisp ZSHCOMPDIR=/usr/share/zsh/vendor-completions >/dev/null; \
	meta=$$($(GO) version -m $(BIN_DIR)/$(BINARY)); \
	case $$meta in *GOOS=linux*) ;; *) echo "$(BIN_DIR)/$(BINARY) is not a Linux build" >&2; exit 1 ;; esac; \
	arch=$$(echo "$$meta" | sed -n 's/^[[:space:]]*build[[:space:]]*GOARCH=//p'); \
	case $$arch in 386) arch=i386 ;; arm) arch=armhf ;; ppc64le) arch=ppc64el ;; \
		mipsle) arch=mipsel ;; mips64le) arch=mips64el ;; esac; \
	stamp=$$(echo '$(BUILD_TIME)' | tr -dc 0-9); \
	version=$$(echo '$(VERSION)' | sed -e 's/^v//' -e 's/-dirty$$/+dirty/' \
		-e 's/-\([0-9][0-9]*\)-g/+\1.g/' -e 's/-/~/g'); \
	case $$version in \
	[0-9]*.*+dirty) version="$$version.$$stamp" ;; \
	[0-9]*.*) ;; \
	*) version="0~$$stamp.$$version" ;; \
	esac; \
	mv "$$doc/LICENSE" "$$doc/copyright"; gzip -9n "$$stage/usr/share/man/man1/lw.1"; \
	install -d -m 0755 "$$stage/DEBIAN"; \
	for f in postinst prerm postrm; do install -m 0755 $(PKG_DIR)/deb/$$f "$$stage/DEBIAN/$$f"; done; \
	echo /etc/logwisp/logwisp.toml > "$$stage/DEBIAN/conffiles"; \
	(cd "$$stage" && find usr -type f -exec md5sum {} + | LC_ALL=C sort -k 2) > "$$stage/DEBIAN/md5sums"; \
	size=$$(du -sk --apparent-size "$$stage/usr" "$$stage/etc" | awk '{ s += $$1 } END { print s }'); \
	{ printf 'Package: logwisp\nVersion: %s\nArchitecture: %s\nMaintainer: %s\nInstalled-Size: %s\n' \
		"$$version" "$$arch" "$(DEB_MAINTAINER)" "$$size"; cat $(PKG_DIR)/deb/control; \
		sed -e 's/^$$/./' -e 's/^/ /' $(PKG_DIR)/freebsd/pkg-descr; } > "$$stage/DEBIAN/control"; \
	dpkg-deb --root-owner-group --build "$$stage" "$(BIN_DIR)/logwisp_$${version}_$$arch.deb"

# arch builds the PKGBUILD from this working tree, tracked and new files, as
# the release tarball it names; no tag or download is needed. Untagged, the
# version is 0.rCOUNT.gHASH, below every release and rising with each commit.
# The package and build tree stay in bin/arch whatever makepkg.conf says.
arch:
	@set -eu; dir=$(BIN_DIR)/arch; [ ! -d "$$dir" ] || chmod -R u+w "$$dir"; rm -rf "$$dir"; mkdir -p "$$dir"; \
	ver=$$(echo '$(VERSION)' | sed -e 's/^v//' -e 's/-\([0-9][0-9]*\)-g/.r\1.g/' -e 's/-/./g'); \
	case '$(VERSION)' in v[0-9]*) ;; *) ver="0.r$$(git rev-list --count HEAD).g$$ver" ;; esac; \
	git ls-files -z --cached --others --exclude-standard | tar --null -T - --ignore-failed-read \
		--transform "s,^,logwisp-$$ver/,S" -czf "$$dir/logwisp-$$ver.tar.gz"; \
	sed "s/^pkgver=.*/pkgver=$$ver/" $(PKG_DIR)/arch/PKGBUILD > "$$dir/PKGBUILD"; \
	cd "$$dir"; export PKGDEST="$$PWD" BUILDDIR="$$PWD"; makepkg; \
	echo "install or reinstall: sudo pacman -U $$(makepkg --packagelist | grep -v -- -debug-)"

# A toolchain go downloaded into make arch's GOPATH is read-only.
clean:
	[ ! -d $(BIN_DIR) ] || chmod -R u+w $(BIN_DIR)
	rm -rf $(BIN_DIR)

version:
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(GIT_COMMIT)"
	@echo "Build time: $(BUILD_TIME)"
