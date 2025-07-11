# LogWisp Makefile
# Compatible with GNU Make (Linux) and BSD Make (FreeBSD)

BINARY_NAME = logwisp
BUILD_DIR = bin
BINARY_PATH = $(BUILD_DIR)/$(BINARY_NAME)
VERSION != git describe --tags --always --dirty 2>/dev/null || echo "dev"
GIT_COMMIT != git rev-parse --short HEAD 2>/dev/null || echo "unknown"
BUILD_TIME != date -u '+%Y-%m-%d_%H:%M:%S'

# Go build variables
GO = go
GOFLAGS =
LDFLAGS = -X 'logwisp/src/internal/version.Version=$(VERSION)' \
          -X 'logwisp/src/internal/version.GitCommit=$(GIT_COMMIT)' \
          -X 'logwisp/src/internal/version.BuildTime=$(BUILD_TIME)'

# Installation directories
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

# Default target
all: build

# Build the binary
build:
	mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_PATH) ./src/cmd/logwisp

# Install the binary
install: build
	install -m 755 $(BINARY_PATH) $(BINDIR)/

# Uninstall the binary
uninstall:
	rm -f $(BINDIR)/$(BINARY_PATH)

# Clean build artifacts
clean:
	rm -f $(BINARY_PATH)

# Development build with race detector
dev:
	$(GO) build $(GOFLAGS) -race -ldflags "$(LDFLAGS)" -o $(BINARY_PATH) ./src/cmd/logwisp

# Show current version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

.PHONY: all build install uninstall clean dev version