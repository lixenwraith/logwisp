#!/usr/bin/env bash
# logwisp mTLS authentication test
#
# Scenario 1 — chained instances, client authenticates with mTLS:
#   edge-01 cert --> tcp_chain  sink --> :15811 tcp_chain  src --> file sink
#   edge-01 cert --> http_chain sink --> :15812 http_chain src --> file sink
#   edge-99 cert --> tcp_chain  sink --> :15811 rejected by the allow list
#
# Scenario 2 — a viewer client reads a streaming sink over mTLS:
#   viewer-01 cert --> :15813 tcp sink   (openssl s_client)
#   viewer-01 cert --> :15814 http sink  (curl, /stream and /status)
#   rogue     cert --> both, rejected by the allow list
#
# Also covers: node binding (a peer holding the edge-01 certificate cannot
# label its entries anything else), dialer-side server identity pinning, and
# a peer presenting no certificate at all.
#
# Usage:
#   ./mtls-chain-test.sh           manual mode: relay + edges up, guide printed
#   ./mtls-chain-test.sh --auto    automated checks and teardown
#   ./mtls-chain-test.sh --keep    (with --auto) skip teardown on success
#
# Requires: bash 5+, coreutils (timeout), openssl, curl. Linux dev host only.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${LOGWISP_BIN:-$SCRIPT_DIR/../bin/logwisp}"
RUN="$SCRIPT_DIR/run-mtls"
CONF="$RUN/conf"
LOG="$RUN/log"
PKI="$RUN/pki"
OUT="$RUN/out"

PORT_TCP_CHAIN=15811
PORT_HTTP_CHAIN=15812
PORT_TCP_SINK=15813
PORT_HTTP_SINK=15814

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

start_daemon() { # name conf
	"$BIN" -c "$CONF/$2" > "$LOG/$1.out" 2>&1 &
	PIDS+=($!)
	echo "started $1 (pid $!)"
}

# --- Preflight ---
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (build: go build -o bin/logwisp ./cmd/logwisp)" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK; do
	port_open "$p" && { echo "port $p already in use" >&2; exit 1; }
done
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$OUT"

# --- PKI ---
# One CA for every peer: the point of the test is that CA membership alone is
# no longer sufficient, so the identities must all be issued by the same CA.
gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

gen_leaf() { # name CN eku [SAN]
	local name=$1 cn=$2 eku=$3 san=${4:-}
	gen_key "$PKI/$name.key"
	openssl req -new -key "$PKI/$name.key" -out "$PKI/$name.csr" -subj "/CN=$cn" 2>/dev/null
	local ext="extendedKeyUsage=$eku"
	[[ -n $san ]] && ext+=$'\n'"subjectAltName=$san"
	printf '%s\n' "$ext" > "$PKI/$name.ext"
	openssl x509 -req -in "$PKI/$name.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
		-CAcreateserial -out "$PKI/$name.crt" -days 2 -extfile "$PKI/$name.ext" 2>/dev/null
}

echo "--- generating test PKI in $PKI"
gen_key "$PKI/ca.key"
openssl req -x509 -new -key "$PKI/ca.key" -days 2 -out "$PKI/ca.crt" \
	-subj "/CN=LogWisp Test CA" 2>/dev/null
gen_leaf relay     relay.internal serverAuth "IP:127.0.0.1,DNS:relay.internal"
gen_leaf edge-01   edge-01        clientAuth
gen_leaf edge-99   edge-99        clientAuth
gen_leaf viewer-01 viewer-01      clientAuth
gen_leaf rogue     rogue-viewer   clientAuth
[[ -s "$PKI/rogue.crt" ]] || { echo "PKI generation failed" >&2; exit 1; }

# --- Config generation ---
# Relay: both ingest ports authorize edge-01 only and bind the node label to
# the certificate identity; both streaming sinks authorize viewer-01 only.
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
[pipelines.plugin_sources.config.tls]
enabled = true
cert_file = "$PKI/relay.crt"
key_file = "$PKI/relay.key"
client_auth = true
client_ca_file = "$PKI/ca.crt"
[pipelines.plugin_sources.config.auth]
type = "mtls"
identity = "cn"
allow = ["edge-01"]
node_binding = "force"

[[pipelines.plugin_sinks]]
id = "file_tcp"
type = "file"
[pipelines.plugin_sinks.config]
directory = "$OUT"
name = "tcp_chain"
flush_interval_ms = 200

[[pipelines.plugin_sinks]]
id = "out_tcp"
type = "tcp"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_TCP_SINK
[pipelines.plugin_sinks.config.tls]
enabled = true
cert_file = "$PKI/relay.crt"
key_file = "$PKI/relay.key"
client_auth = true
client_ca_file = "$PKI/ca.crt"
[pipelines.plugin_sinks.config.auth]
type = "mtls"
allow = ["viewer-01"]

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
[pipelines.plugin_sources.config.tls]
enabled = true
cert_file = "$PKI/relay.crt"
key_file = "$PKI/relay.key"
client_auth = true
client_ca_file = "$PKI/ca.crt"
[pipelines.plugin_sources.config.auth]
type = "mtls"
allow = ["edge-01"]
node_binding = "force"

[[pipelines.plugin_sinks]]
id = "file_http"
type = "file"
[pipelines.plugin_sinks.config]
directory = "$OUT"
name = "http_chain"
flush_interval_ms = 200

[[pipelines.plugin_sinks]]
id = "out_http"
type = "http"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_HTTP_SINK
[pipelines.plugin_sinks.config.tls]
enabled = true
cert_file = "$PKI/relay.crt"
key_file = "$PKI/relay.key"
client_auth = true
client_ca_file = "$PKI/ca.crt"
[pipelines.plugin_sinks.config.auth]
type = "mtls"
allow = ["viewer-01"]
EOF

# edge_tcp holds the edge-01 certificate but declares node "edge-tcp":
# node_binding = "force" must relabel its entries to "edge-01".
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
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
cert_file = "$PKI/edge-01.crt"
key_file = "$PKI/edge-01.key"
[pipelines.plugin_sinks.config.auth]
type = "mtls"
allow = ["relay.internal"]
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
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
cert_file = "$PKI/edge-01.crt"
key_file = "$PKI/edge-01.key"
[pipelines.plugin_sinks.config.auth]
type = "mtls"
allow = ["relay.internal"]
EOF

# edge_rogue holds a CA-issued certificate the relay does not authorize, and
# claims to be edge-01 on top of it.
cat > "$CONF/edge_rogue.toml" <<EOF
status_reporter = false
[logging]
output = "file"
level = "info"
[logging.file]
directory = "$LOG"
name = "edge_rogue"

[[pipelines]]
name = "edge_rogue"
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
node = "edge-01"
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
cert_file = "$PKI/edge-99.crt"
key_file = "$PKI/edge-99.key"
EOF

# edge_pinfail pins a server identity the relay does not have: the dialer must
# refuse the handshake even though the certificate chains to the trusted CA.
cat > "$CONF/edge_pinfail.toml" <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "debug"

[[pipelines]]
name = "edge_pinfail"
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
node = "edge-pinfail"
backoff_max_ms = 1000
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
cert_file = "$PKI/edge-01.crt"
key_file = "$PKI/edge-01.key"
[pipelines.plugin_sinks.config.auth]
type = "mtls"
allow = ["some-other-relay.internal"]
EOF

# --- Guide ---
cat <<EOF
================================================================
 logwisp mTLS auth test — port map
   $PORT_TCP_CHAIN  relay ingest (tcp_chain,  mTLS, allow = edge-01)
   $PORT_HTTP_CHAIN  relay ingest (http_chain, mTLS, allow = edge-01)
   $PORT_TCP_SINK  TCP sink     (mTLS, allow = viewer-01)
   $PORT_HTTP_SINK  HTTP sink    (mTLS, allow = viewer-01)

 Read the TCP sink as an authorized viewer:
   openssl s_client -quiet -connect 127.0.0.1:$PORT_TCP_SINK \\
     -CAfile $PKI/ca.crt -cert $PKI/viewer-01.crt -key $PKI/viewer-01.key
 Read the HTTP sink:
   curl -N --noproxy '*' --cacert $PKI/ca.crt \\
     --cert $PKI/viewer-01.crt --key $PKI/viewer-01.key \\
     https://127.0.0.1:$PORT_HTTP_SINK/stream
 Swap in rogue.crt/rogue.key for either and the policy refuses it.

 Ingested entries land in $OUT/ (node label forced to the certificate CN).
 Logs: $LOG/
================================================================
EOF

# --- Startup ---
start_daemon relay relay.toml
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK; do
	wait_port "$p" 10 || { echo "FAIL: relay port $p not listening (see $LOG/relay.out)"; exit 1; }
done
start_daemon edge_tcp     edge_tcp.toml
start_daemon edge_http    edge_http.toml
start_daemon edge_rogue   edge_rogue.toml
start_daemon edge_pinfail edge_pinfail.toml

if (( AUTO == 0 )); then
	echo "--- daemons running; Ctrl-C to stop"
	while :; do sleep 1; done
fi

echo "--- settling 4s (connect + first http_chain flush)"
sleep 4

fail=0
check() { # label condition_result
	if (( $2 )); then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

# Viewer helpers
tcp_view() { # cert_basename secs
	timeout "$2" openssl s_client -quiet \
		-connect 127.0.0.1:$PORT_TCP_SINK -CAfile "$PKI/ca.crt" \
		-cert "$PKI/$1.crt" -key "$PKI/$1.key" </dev/null 2>/dev/null || true
}

http_get() { # path cert_basename|"" -> "<http_code>|<body>"
	local path=$1 name=${2:-}
	local args=(-s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*'
		--cacert "$PKI/ca.crt")
	[[ -n $name ]] && args+=(--cert "$PKI/$name.crt" --key "$PKI/$name.key")
	curl "${args[@]}" "https://127.0.0.1:$PORT_HTTP_SINK$path" 2>/dev/null || true
}

relay_log="$LOG/relay.out"
ingested() { cat "$OUT"/${1}* 2>/dev/null; }

echo "=== Scenario 1: chained instances over mTLS ==="

# 1. An authorized edge delivers entries into the relay's file sink
tcp_file="$(ingested tcp_chain)"
n=$(grep -c 'edge-01/' <<< "$tcp_file")
check "tcp_chain: authorized edge-01 entries reached the file sink ($n lines)" $(( n >= 1 ))

http_file="$(ingested http_chain)"
n=$(grep -c 'edge-01/' <<< "$http_file")
check "http_chain: authorized edge-01 entries reached the file sink ($n lines)" $(( n >= 1 ))

# 2. node_binding = "force" overrode the label the sender configured
n=$(grep -c 'edge-tcp/' <<< "$tcp_file")
check "node binding: sender's own label \"edge-tcp\" was not honored ($n lines)" $(( n == 0 ))
n=$(grep -c 'edge-http/' <<< "$http_file")
check "node binding: sender's own label \"edge-http\" was not honored ($n lines)" $(( n == 0 ))

# 3. An identity outside the allow list is refused, even claiming to be edge-01
n=$(grep -c 'Connection rejected by auth policy' "$relay_log")
check "allow list: unauthorized edge-99 connection rejected ($n rejections)" $(( n >= 1 ))
n=$(grep -c 'edge-99' <<< "$tcp_file")
check "allow list: no edge-99 entry was ingested" $(( n == 0 ))

# 4. A peer with no certificate cannot complete the handshake
timeout 5 openssl s_client -connect 127.0.0.1:$PORT_TCP_CHAIN \
	-CAfile "$PKI/ca.crt" </dev/null >/dev/null 2>&1
sleep 0.5
n=$(grep -c 'TLS handshake failed' "$relay_log")
check "client_auth: a peer with no certificate was refused ($n handshake errors)" $(( n >= 1 ))

# 5. Dialer-side pinning: the relay's identity is not the one edge_pinfail pins
n=$(grep -c 'is not allowed' "$LOG/edge_pinfail.out")
check "server pinning: dialer refused a CA-valid server it does not pin ($n refusals)" $(( n >= 1 ))
n=$(grep -c 'edge-pinfail' <<< "$tcp_file")
check "server pinning: pin-failing edge delivered nothing" $(( n == 0 ))

echo "=== Scenario 2: viewer clients on mTLS-gated sinks ==="

# 6. TCP sink: authorized viewer streams, rogue gets nothing
out="$(tcp_view viewer-01 4)"
n=$(grep -c 'edge-01/' <<< "$out")
check "tcp sink: viewer-01 streamed entries ($n lines)" $(( n >= 1 ))

out="$(tcp_view rogue 4)"
n=$(grep -c '"message"' <<< "$out")
check "tcp sink: rogue viewer received no entries" $(( n == 0 ))

# 7. HTTP sink: stream and status both gated
code="$(http_get /status viewer-01)"
check "http sink: /status served to viewer-01 (HTTP $code)" $([[ $code == 200 ]] && echo 1 || echo 0)

code="$(http_get /status rogue)"
check "http sink: /status refused to rogue viewer (HTTP $code)" $([[ $code == 403 ]] && echo 1 || echo 0)

code="$(http_get /stream rogue)"
check "http sink: /stream refused to rogue viewer (HTTP $code)" $([[ $code == 403 ]] && echo 1 || echo 0)

# curl reports 000 when the handshake itself fails, which is what a client
# with no certificate must hit
code="$(http_get /status)"
check "http sink: client with no certificate failed the handshake (curl $code)" \
	$([[ $code == 000 ]] && echo 1 || echo 0)

sse="$(timeout 4 curl -sN --noproxy '*' --cacert "$PKI/ca.crt" \
	--cert "$PKI/viewer-01.crt" --key "$PKI/viewer-01.key" \
	"https://127.0.0.1:$PORT_HTTP_SINK/stream" 2>/dev/null || true)"
n=$(grep -c '^data:.*edge-01/' <<< "$sse")
check "http sink: viewer-01 received SSE events ($n events)" $(( n >= 1 ))

# 8. The status endpoint reports the policy and its rejection count
status="$(curl -s --max-time 5 --noproxy '*' --cacert "$PKI/ca.crt" \
	--cert "$PKI/viewer-01.crt" --key "$PKI/viewer-01.key" \
	"https://127.0.0.1:$PORT_HTTP_SINK/status" 2>/dev/null || true)"
n=$(grep -c 'mtls' <<< "$status")
check "http sink: status endpoint reports the auth policy" $(( n >= 1 ))
rej=$(grep -o '"auth_rejected"[ :]*[0-9]*' <<< "$status" | grep -o '[0-9]*$' || echo 0)
check "http sink: status endpoint counts auth rejections (auth_rejected=$rej)" $(( rej >= 1 ))

echo "================================================================"
if (( fail == 0 )); then
	echo "RESULT: ALL PASS"
	(( KEEP )) && { echo "--keep: daemons left running (pids: ${PIDS[*]})"; PIDS=(); }
else
	echo "RESULT: FAILURES — inspect $LOG/*.out and $LOG/*.log"
fi
exit "$fail"
