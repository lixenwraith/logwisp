#!/usr/bin/env bash
# logwisp chain test: edge-tcp and edge-http feed a relay that runs one
# pipeline per transport, without fan-in (chain-aggregate-test.sh fans in).
# Requires: bash 5+, coreutils (timeout), curl. Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run
PORT_TCP_CHAIN=15801
PORT_HTTP_CHAIN=15802
PORT_TCP_SINK=15803
PORT_HTTP_SINK=15804
PORTS="$PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK"
e2e_init "$@"

section "Setup"
need curl
ports_free 127.0.0.1 $PORTS
mkdir -p "$CONF" "$LOG"

edge_conf() { # name sink_type port [sink options]
	cat >"$CONF/$1.toml" <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "info"

[[pipelines]]
name = "$1"
[[pipelines.plugin_sources]]
id = "rand"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 200
format = "txt"
length = 24
[[pipelines.plugin_sinks]]
id = "to_relay"
type = "$2"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $3
node = "${1/_/-}"
${4:-}
EOF
}
edge_conf edge_tcp tcp_chain $PORT_TCP_CHAIN
edge_conf edge_http http_chain $PORT_HTTP_CHAIN "flush_interval_ms = 500"

cat >"$CONF/relay.toml" <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "info"

[[pipelines]]
name = "relay_tcp"
[pipelines.flow.format]
type = "json"
sanitizer_policy = "json"
[[pipelines.plugin_sources]]
id = "in_tcp"
type = "tcp_chain"
[pipelines.plugin_sources.config]
host = "127.0.0.1"
port = $PORT_TCP_CHAIN
[[pipelines.plugin_sinks]]
id = "out_tcp"
type = "tcp"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_TCP_SINK

[[pipelines]]
name = "relay_http"
[pipelines.flow.format]
type = "json"
sanitizer_policy = "json"
[[pipelines.plugin_sources]]
id = "in_http"
type = "http_chain"
[pipelines.plugin_sources.config]
host = "127.0.0.1"
port = $PORT_HTTP_CHAIN
[[pipelines.plugin_sinks]]
id = "out_http"
type = "http"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_HTTP_SINK
EOF
info "configurations in $(short "$CONF")/"

section "Startup"
start_daemon relay relay.toml
for p in $PORTS; do
	wait_port "$p" || abort "relay port $p is not listening" relay
done
# Chain sinks retry with backoff, so the edges could start first too
start_daemon edge_tcp edge_tcp.toml
start_daemon edge_http edge_http.toml
daemons_up

guide "logwisp chain test" <<EOF
Ports (IPv4 only: 127.0.0.1, not localhost):
  $PORT_TCP_CHAIN  relay tcp_chain ingest, from edge-tcp
  $PORT_HTTP_CHAIN  relay http_chain ingest (POST /ingest), from edge-http
  $PORT_TCP_SINK  tcp sink: edge-tcp's entries as JSON
  $PORT_HTTP_SINK  http sink: edge-http's entries, SSE /stream, JSON /status
Watch:
> nc 127.0.0.1 $PORT_TCP_SINK
> curl -N http://127.0.0.1:$PORT_HTTP_SINK/stream
> curl http://127.0.0.1:$PORT_HTTP_SINK/status
Logs: $(short "$LOG")/
EOF
manual_hold

section "Checks"
info "settling 3 s (connect, first http_chain flush)"
sleep 3

# 1. TCP chain: edge-tcp -> relay -> tcp sink
tcp_out="$(tcp_read "$PORT_TCP_SINK" 4)"
n=$(grep -c 'edge-tcp/' <<<"$tcp_out")
check "tcp path: entries on :$PORT_TCP_SINK with node=edge-tcp ($n lines)" $((n >= 1))

# 2. HTTP chain: edge-http -> relay -> SSE sink
sse_out="$(curl -sN --noproxy '*' --max-time 4 "http://127.0.0.1:$PORT_HTTP_SINK/stream" || true)"
n=$(grep -c '^data:.*edge-http/' <<<"$sse_out")
check "http path: SSE events on :$PORT_HTTP_SINK with node=edge-http ($n events)" $((n >= 1))

# 3. HTTP sink status endpoint
status="$(curl -s --noproxy '*' --max-time 3 "http://127.0.0.1:$PORT_HTTP_SINK/status" || true)"
proc=$(grep -o '"total_processed"[ :] *[0-9]*' <<<"$status" | grep -o '[0-9]*' || echo 0)
check "status endpoint: total_processed=$proc > 0" $((proc > 0))

summary
