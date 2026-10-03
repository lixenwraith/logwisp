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
# The image stamps the commit time, so a rebuild of one commit stays cached
IMAGE_BUILD_TIME_DEFAULT != TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d_%H:%M:%S 2>/dev/null || echo unknown
IMAGE_BUILD_TIME ?= $(IMAGE_BUILD_TIME_DEFAULT)
VERSION_LDFLAGS = -X 'logwisp/internal/version.Version=$(VERSION)' \
	-X 'logwisp/internal/version.GitCommit=$(GIT_COMMIT)' \
	-X 'logwisp/internal/version.BuildTime=$(BUILD_TIME)'
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
PREFIX_DEFAULT != [ '$(INSTALL_OS)' = FreeBSD ] && echo /usr/local || echo /usr
PREFIX ?= $(PREFIX_DEFAULT)
SYSCONFDIR_DEFAULT != [ '$(INSTALL_OS)' = FreeBSD ] && echo /usr/local/etc || echo /etc
SYSCONFDIR ?= $(SYSCONFDIR_DEFAULT)
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
DOCDIR ?= $(PREFIX)/share/doc/logwisp
LICENSEDIR ?= $(PREFIX)/share/licenses/logwisp

.DEFAULT_GOAL := help

.PHONY: help check-go build release dev test verify e2e image image-check install uninstall clean version

help:
	@echo "Usage: make <target> [VARIABLE=value ...]"
	@echo ""
	@echo "Build:"
	@echo "  build        Build $(BIN_DIR)/$(BINARY) with version metadata"
	@echo "  release      Build it static, stripped and trimmed (CGO_ENABLED=0)"
	@echo "  dev          Build it with the race detector"
	@echo "  version      Print the version metadata a build embeds"
	@echo "  clean        Remove $(BIN_DIR)/"
	@echo "Check:"
	@echo "  test         Run the Go tests"
	@echo "  verify       vet, gofmt, tests, linux and freebsd cross builds, web client tests"
	@echo "  e2e          Build, then run each of $(E2E) with --auto and report"
	@echo "Container:"
	@echo "  image        Build $(IMAGE):$(IMAGE_TAG) with $(CONTAINER_ENGINE) (scratch, static, UID 65532)"
	@echo "  image-check  Run it read-only, offline, without capabilities: --version, then"
	@echo "               --check on $(IMAGE_CHECK_CONFIG)"
	@echo "Install (build or release first):"
	@echo "  install      Binary, manual, sample config, service files, licence and docs"
	@echo "  uninstall    Remove them, keeping $(SYSCONFDIR)/logwisp"
	@echo ""
	@echo "Variables: GO=$(GO) PREFIX=$(PREFIX) SYSCONFDIR=$(SYSCONFDIR) DESTDIR=$(DESTDIR)"
	@echo "  INSTALL_OS=$(INSTALL_OS) (the layout install uses: FreeBSD or any other)"
	@echo "  GO_BUILDFLAGS, GO_LDFLAGS (extra go build and linker flags), E2E (scripts),"
	@echo "  CONTAINER_ENGINE, IMAGE, IMAGE_TAG, BUILD_CA, IMAGE_BUILD_FLAGS, IMAGE_CHECK_CONFIG"

check-go:
	@command -v $(GO) >/dev/null 2>&1 || { \
		echo "Go toolchain '$(GO)' not found; go.mod requires go $$(sed -n 's/^go //p' go.mod)."; \
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

test: check-go
	$(GO) test ./...

# gofmt checks the Go files changed since the branch forked from GOFMT_BASE,
# exact renames aside, or the whole tree without git or that ref: older files
# predate the gate, and AGENTS.md formats what a change touches.
GOFMT_BASE ?= main
verify: test
	$(GO) vet ./...
	@base='$(GOFMT_BASE)'; \
	if [ -n "$$base" ] && fork=$$(git merge-base "$$base" HEAD 2>/dev/null); then \
		files=$$( { git diff --name-only --find-renames=100% --diff-filter=dr "$$fork" -- cmd internal; \
			git ls-files --others --exclude-standard -- cmd internal; } | grep '\.go$$' || true); \
	else \
		files=$$(find cmd internal -name '*.go'); \
	fi; \
	bad=$$( [ -z "$$files" ] || "$$($(GO) env GOROOT)/bin/gofmt" -l $$files ); \
	if [ -n "$$bad" ]; then echo "gofmt -l reports:"; echo "$$bad"; exit 1; fi
	@for target in linux/amd64 linux/arm64 freebsd/amd64 freebsd/arm64; do \
		echo "cross build $$target"; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} $(GO) build -o /dev/null $(SRC) || exit 1; \
	done
	@if command -v node >/dev/null 2>&1; then \
		cd $(WEB_DIR) && node --test; \
	else \
		echo "node not found: web client tests skipped"; \
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
# the build flags. The service files get the installed paths substituted; a
# configuration already in place is kept.
install:
	@set -eu; \
	[ -x $(BIN_DIR)/$(BINARY) ] || { echo "no $(BIN_DIR)/$(BINARY): run make build or make release first" >&2; exit 1; }; \
	put() { install -d -m 0755 "$${3%/*}"; install -m "$$1" "$$2" "$$3"; echo "install $$3"; }; \
	sub() { install -d -m 0755 "$${3%/*}"; \
		sed -e 's|@BINDIR@|$(BINDIR)|g' -e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' -e 's|%%BINDIR%%|$(BINDIR)|g' \
			-e 's|%%PREFIX%%/etc|$(SYSCONFDIR)|g' -e 's|%%PREFIX%%|$(PREFIX)|g' "$$2" > "$$3"; \
		chmod "$$1" "$$3"; echo "install $$3"; }; \
	root='$(DESTDIR)'; etc="$$root$(SYSCONFDIR)/logwisp"; \
	put 0755 $(BIN_DIR)/$(BINARY) "$$root$(BINDIR)/$(BINARY)"; \
	put 0644 doc/lw.1 "$$root$(MANDIR)/man1/lw.1"; \
	put 0644 LICENSE "$$root$(LICENSEDIR)/LICENSE"; \
	for src in README.md doc/*.md; do put 0644 "$$src" "$$root$(DOCDIR)/$$src"; done; \
	case '$(INSTALL_OS)' in \
	FreeBSD) \
		put 0644 config/logwisp.toml "$$etc/logwisp.toml.sample"; \
		if [ -z "$$root" ] && [ ! -e "$$etc/logwisp.toml" ]; then put 0644 config/logwisp.toml "$$etc/logwisp.toml"; fi; \
		sub 0755 $(PKG_DIR)/logwisp.rc "$$root$(PREFIX)/etc/rc.d/logwisp" ;; \
	*) \
		if [ -e "$$etc/logwisp.toml" ]; then echo "keep    $$etc/logwisp.toml"; \
		else put 0644 config/logwisp.toml "$$etc/logwisp.toml"; fi; \
		sub 0644 $(PKG_DIR)/logwisp.service "$$root$(PREFIX)/lib/systemd/system/logwisp.service"; \
		sub 0644 $(PKG_DIR)/logwisp.sysusers "$$root$(PREFIX)/lib/sysusers.d/logwisp.conf"; \
		sub 0644 $(PKG_DIR)/logwisp.tmpfiles "$$root$(PREFIX)/lib/tmpfiles.d/logwisp.conf" ;; \
	esac

uninstall:
	@set -eu; root='$(DESTDIR)'; \
	for f in "$$root$(BINDIR)/$(BINARY)" "$$root$(MANDIR)/man1/lw.1" \
		"$$root$(PREFIX)/lib/systemd/system/logwisp.service" \
		"$$root$(PREFIX)/lib/sysusers.d/logwisp.conf" "$$root$(PREFIX)/lib/tmpfiles.d/logwisp.conf" \
		"$$root$(PREFIX)/etc/rc.d/logwisp" "$$root$(SYSCONFDIR)/logwisp/logwisp.toml.sample"; do \
		if [ -e "$$f" ]; then rm -f "$$f"; echo "remove  $$f"; fi; \
	done; \
	for d in "$$root$(DOCDIR)" "$$root$(LICENSEDIR)"; do \
		case "$$d" in */logwisp) ;; *) echo "keep    $$d (not a logwisp directory)"; continue ;; esac; \
		if [ -d "$$d" ]; then rm -rf "$$d"; echo "remove  $$d"; fi; \
	done; \
	echo "keep    $$root$(SYSCONFDIR)/logwisp (configuration and credentials)"

clean:
	rm -rf $(BIN_DIR)

version:
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(GIT_COMMIT)"
	@echo "Build time: $(BUILD_TIME)"
