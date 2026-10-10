# Builder pin and go.mod directive are the same patch release deliberately;
# an older builder reports the mismatch only after downloading the module graph.
ARG GO_VERSION=1.27.2

# The builder runs natively and cross-compiles, so foreign platforms need no emulation.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:${GO_VERSION}-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
# The optional build_ca secret adds a CA (an intercepting proxy's) for this step
# only: Go reads SSL_CERT_DIR besides the system bundle, and a secret mount
# never reaches a layer. Proxy variables are Docker's predefined build args.
RUN --mount=type=secret,id=build_ca,target=/run/build-ca/ca.pem \
    SSL_CERT_DIR=/run/build-ca go mod download

COPY . .

# No defaults: a declared default would override the platform BuildKit passes.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_TIME=unknown
# REVISION identifies the commit: the context has no .git, so no VCS stamping.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X github.com/lixenwraith/logwisp/internal/version.Version=${VERSION} -X github.com/lixenwraith/logwisp/internal/version.GitCommit=${REVISION} -X github.com/lixenwraith/logwisp/internal/version.BuildTime=${BUILD_TIME}" \
      -o /out/lw ./cmd/lw

FROM scratch

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="logwisp" \
      org.opencontainers.image.description="Log transport: sources, flow, sinks" \
      org.opencontainers.image.source="https://github.com/lixenwraith/logwisp" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="BSD-3-Clause"

# Dialers without tls.ca_file, and `lw auth` without --ca-file, verify against system roots.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/lw /lw

# Numeric identity is required in scratch and satisfies a restricted pod spec.
USER 65532:65532

ENTRYPOINT ["/lw"]
