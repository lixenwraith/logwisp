#!/usr/bin/env bash
# logwisp chain topology test
#
#   random --> tcp_chain sink  --> :15801 tcp_chain src  --> :15803 tcp sink
#   random --> http_chain sink --> :15802 http_chain src --> :15804 http sink (SSE)
#
# Usage:
#   ./chain_test.sh            manual mode: 2 edge daemons + relay foreground
#   ./chain_test.sh --auto     all daemonized, automated curl//dev/tcp checks, teardown
#   ./chain_test.sh --keep     (with --auto) skip teardown on success
#
# Requires: bash 5+, coreutils (timeout), curl. Linux dev host only.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${LOGWISP_BIN:-$SCRIPT_DIR/../bin/logwisp}"
RUN="$SCRIPT_DIR/run"
CONF="$RUN/conf"
LOG="$RUN/log"

PORT_TCP_CHAIN=15801
PORT_HTTP_CHAIN=15802
PORT_TCP_SINK=15803
PORT_HTTP_SINK=15804

AUTO=0; KEEP=0
for a in "$@"; do case "$a" in
	--auto) AUTO=1 ;;
	--keep) KEEP=1 ;;
	*) echo "unknown arg: $a" >&2; exit 1 ;;
esac; done

PIDS=()
cleanup() {
	local rc=$?
	trap - EXIT INT TERM
	if (( ${#PIDS[@]} )); then
		echo "--- teardown: stopping ${#PIDS[@]} daemon(s)"
		kill -TERM "${PIDS[@]}" 2>/dev/null
		local deadline=$(( SECONDS + 10 ))
		for pid in "${PIDS[@]}"; do
			while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 0.2; done
			kill -KILL "$pid" 2>/dev/null
		done
	fi
	exit "$rc"
}
trap cleanup EXIT INT TERM

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3>&-; }

wait_port() { # port timeout_s
	local i; for (( i=0; i < $2 * 10; i++ )); do
		port_open "$1" && return 0
		sleep 0.1
	done
	return 1
}

# Reads TCP sink stream for N seconds; connection counts as a sink client
tcp_read() { # port secs
	timeout "$2" bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; cat <&3" 2>/dev/null || true
}

start_daemon() { # name conf
	"$BIN" -c "$CONF/$2" > "$LOG/$1.out" 2>&1 &
	PIDS+=($!)
	echo "started $1 (pid $!)"
}

# --- Preflight ---
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (build: go build -o bin/logwisp ./cmd/logwisp)" >&2; exit 1; }
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK; do
	port_open "$p" && { echo "port $p already in use" >&2; exit 1; }
done
mkdir -p "$CONF" "$LOG"

# --- Config generation ---
cat > "$CONF/edge_tcp.toml" <<EOF
status_reporter = false
[logging]
output = "file"
level = "info"
[logging.file]
directory = "$LOG"
name = "edge_tcp"

[[pipelines]]
name = "edge_tcp"
[[pipelines.plugin_sources]]
id = "rand"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 200
format = "txt"
length = 24
[[pipelines.plugin_sinks]]
id = "to_relay"
type = "tcp_chain"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_TCP_CHAIN
node = "edge-tcp"
EOF

cat > "$CONF/edge_http.toml" <<EOF
status_reporter = false
[logging]
output = "file"
level = "info"
[logging.file]
directory = "$LOG"
name = "edge_http"

[[pipelines]]
name = "edge_http"
[[pipelines.plugin_sources]]
id = "rand"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 200
format = "txt"
length = 24
[[pipelines.plugin_sinks]]
id = "to_relay"
type = "http_chain"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_HTTP_CHAIN
node = "edge-http"
flush_interval_ms = 500
EOF

cat > "$CONF/relay.toml" <<EOF
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

# --- Guide ---
cat <<EOF
================================================================
 logwisp chain test — port map
   $PORT_TCP_CHAIN  relay ingest  (tcp_chain,  from edge-tcp)
   $PORT_HTTP_CHAIN  relay ingest  (http_chain, from edge-http, POST /ingest)
   $PORT_TCP_SINK  TCP sink     -> live check:  nc 127.0.0.1 $PORT_TCP_SINK
   $PORT_HTTP_SINK  HTTP sink    -> live check:  browser/curl:
                     http://127.0.0.1:$PORT_HTTP_SINK/stream   (SSE)
                     http://127.0.0.1:$PORT_HTTP_SINK/status   (JSON stats)
 Use 127.0.0.1, not localhost — sinks reject IPv6.
 Expected: json entries, node "edge-tcp" on :$PORT_TCP_SINK, "edge-http" on :$PORT_HTTP_SINK.
 Logs: $LOG/
================================================================
EOF

if (( AUTO == 0 )); then
	# Manual mode: edges daemonized first (chain sinks backoff-retry), relay foreground
	start_daemon edge_tcp  edge_tcp.toml
	start_daemon edge_http edge_http.toml
	echo "--- relay starting in FOREGROUND; Ctrl-C stops relay and both edges"
	"$BIN" -c "$CONF/relay.toml"
	exit 0
fi

# --- Auto mode ---
start_daemon relay relay.toml
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK; do
	wait_port "$p" 10 || { echo "FAIL: relay port $p not listening (see $LOG/relay.out)"; exit 1; }
done
start_daemon edge_tcp  edge_tcp.toml
start_daemon edge_http edge_http.toml

echo "--- settling 3s (connect + first http_chain flush)"
sleep 3

fail=0
check() { # label condition_result
	if (( $2 )); then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

# 1. TCP chain: edge-tcp -> relay -> tcp sink
tcp_out="$(tcp_read "$PORT_TCP_SINK" 4)"
n=$(grep -c '"node":"edge-tcp"' <<< "$tcp_out")
check "tcp path: entries on :$PORT_TCP_SINK with node=edge-tcp ($n lines)" $(( n >= 1 ))

# 2. HTTP chain: edge-http -> relay -> SSE sink
sse_out="$(curl -sN --max-time 4 "http://127.0.0.1:$PORT_HTTP_SINK/stream" || true)"
n=$(grep -c '^data:.*"node":"edge-http"' <<< "$sse_out")
check "http path: SSE events on :$PORT_HTTP_SINK with node=edge-http ($n events)" $(( n >= 1 ))

# 3. HTTP sink status endpoint
status="$(curl -s --max-time 3 "http://127.0.0.1:$PORT_HTTP_SINK/status" || true)"
proc=$(grep -o '"total_processed":[0-9]*' <<< "$status" | grep -o '[0-9]*' || echo 0)
check "status endpoint: total_processed=$proc > 0" $(( proc > 0 ))

echo "================================================================"
if (( fail == 0 )); then
	echo "RESULT: ALL PASS"
	(( KEEP )) && { echo "--keep: daemons left running (pids: ${PIDS[*]})"; PIDS=(); }
else
	echo "RESULT: FAILURES — inspect $LOG/*.out and $LOG/*.log"
fi
exit "$fail"

