# FILE: logwisp/Makefile
BINARY_NAME := logwisp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

LDFLAGS := -ldflags "-X 'logwisp/src/internal/version.Version=$(VERSION)' \
                     -X 'logwisp/src/internal/version.GitCommit=$(GIT_COMMIT)' \
                     -X 'logwisp/src/internal/version.BuildTime=$(BUILD_TIME)'"

.PHONY: build
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./src/cmd/logwisp

.PHONY: install
install: build
	install -m 755 $(BINARY_NAME) /usr/local/bin/

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)

.PHONY: test
test:
	go test -v ./...

.PHONY: release
release:
	@if [ -z "$(TAG)" ]; then echo "TAG is required: make release TAG=v1.0.0"; exit 1; fi
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)
