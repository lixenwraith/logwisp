# Builder pin and go.mod directive are the same patch release deliberately;
# an older builder reports the mismatch only after downloading the module graph.
ARG GO_VERSION=1.27.1

FROM docker.io/library/golang:${GO_VERSION}-alpine AS build

# Git supplies Go's VCS build information; only /out/logwisp crosses stages.
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X logwisp/internal/version.Version=${VERSION} -X logwisp/internal/version.GitCommit=${REVISION}" \
      -o /out/logwisp ./cmd/logwisp

FROM scratch

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="logwisp" \
      org.opencontainers.image.description="Log transport: sources, flow, sinks" \
      org.opencontainers.image.source="https://github.com/lixenwraith/logwisp" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="BSD-3-Clause"

COPY --from=build /out/logwisp /logwisp

# Numeric identity is required in scratch and satisfies a restricted pod spec.
USER 65532:65532

ENTRYPOINT ["/logwisp"]
