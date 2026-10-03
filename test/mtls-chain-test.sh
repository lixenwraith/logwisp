#!/usr/bin/env bash
# logwisp mTLS test: edges authenticate to a relay with client certificates,
# viewers to its tcp and http sinks; covers the allow lists, node binding (an
# edge-01 certificate labels its entries edge-01), dialer-side server pinning
# and a peer without a certificate.
# Requires: bash 5+, coreutils (timeout), openssl, curl. Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run-mtls
PKI=$RUN/pki
OUT=$RUN/out
PORT_TCP_CHAIN=15811
PORT_HTTP_CHAIN=15812
PORT_TCP_SINK=15813
PORT_HTTP_SINK=15814
PORTS="$PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK"
e2e_init "$@"

section "Setup"
need openssl curl
ports_free $PORTS
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$OUT"

# One CA for every peer: the point of the test is that CA membership alone is
# no longer sufficient, so the identities must all be issued by the same CA.
pki_ca
pki_leaf relay relay.internal serverAuth "IP:127.0.0.1,DNS:relay.internal"
pki_leaf edge-01 edge-01 clientAuth
pki_leaf edge-99 edge-99 clientAuth
pki_leaf viewer-01 viewer-01 clientAuth
pki_leaf rogue rogue-viewer clientAuth
info "test PKI in $(short "$PKI")/: ca, relay, edge-01, edge-99, viewer-01, rogue"

# Relay: both ingest ports authorize edge-01 only and bind the node label to
# the certificate identity; both streaming sinks authorize viewer-01 only.
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

edge_conf() { # name sink_type port node cert level [sink options]: the auth block follows
	cat >"$CONF/$1.toml" <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "$6"

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
node = "$4"
${7:-}
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
cert_file = "$PKI/$5.crt"
key_file = "$PKI/$5.key"
EOF
}
pin() { printf '[pipelines.plugin_sinks.config.auth]\ntype = "mtls"\nallow = ["%s"]\n' "$2" >>"$CONF/$1.toml"; }

# edge_tcp holds the edge-01 certificate but declares node "edge-tcp":
# node_binding = "force" must relabel its entries to "edge-01".
edge_conf edge_tcp tcp_chain $PORT_TCP_CHAIN edge-tcp edge-01 info
pin edge_tcp relay.internal
edge_conf edge_http http_chain $PORT_HTTP_CHAIN edge-http edge-01 info "flush_interval_ms = 500"
pin edge_http relay.internal
# edge_rogue holds a CA-issued certificate the relay does not authorize, and
# claims to be edge-01 on top of it.
edge_conf edge_rogue tcp_chain $PORT_TCP_CHAIN edge-01 edge-99 info
# edge_pinfail pins a server identity the relay does not have: the dialer must
# refuse the handshake even though the certificate chains to the trusted CA.
edge_conf edge_pinfail tcp_chain $PORT_TCP_CHAIN edge-pinfail edge-01 debug "backoff_max_ms = 1000"
pin edge_pinfail some-other-relay.internal
info "configurations in $(short "$CONF")/"

section "Startup"
start_daemon relay relay.toml
for p in $PORTS; do
	wait_port "$p" || abort "relay port $p is not listening" relay
done
start_daemon edge_tcp edge_tcp.toml
start_daemon edge_http edge_http.toml
start_daemon edge_rogue edge_rogue.toml
start_daemon edge_pinfail edge_pinfail.toml
daemons_up
write_env LW="$BIN" PKI="$PKI" CA="$PKI/ca.crt" CERT="$PKI/viewer-01.crt" KEY="$PKI/viewer-01.key"

guide "logwisp mTLS test" <<EOF
Ports:
  $PORT_TCP_CHAIN  relay tcp_chain ingest, mTLS, allow edge-01
  $PORT_HTTP_CHAIN  relay http_chain ingest, mTLS, allow edge-01
  $PORT_TCP_SINK  tcp sink, mTLS, allow viewer-01
  $PORT_HTTP_SINK  http sink, mTLS, allow viewer-01
Edges: edge_tcp, edge_http (edge-01) deliver; edge_rogue (edge-99) is
refused; edge_pinfail pins a server name the relay does not have.
Shell setup (CA, and viewer-01's CERT and KEY):
> . $(short "$RUN")/env
Read the tcp sink, then the http sink, as viewer-01:
> openssl s_client -quiet -connect 127.0.0.1:$PORT_TCP_SINK -CAfile \$CA -cert \$CERT -key \$KEY
> curl -N --cacert \$CA --cert \$CERT --key \$KEY https://127.0.0.1:$PORT_HTTP_SINK/stream
With \$PKI/rogue.crt and rogue.key instead, the policy refuses either.
Ingested entries (node label forced to the certificate CN): $(short "$OUT")/
Logs: $(short "$LOG")/
EOF
manual_hold

info "settling 4 s (connect, first http_chain flush)"
sleep 4

# Viewer helpers
tcp_view() { # cert_basename secs
	timeout "$2" openssl s_client -quiet \
		-connect 127.0.0.1:$PORT_TCP_SINK -CAfile "$PKI/ca.crt" \
		-cert "$PKI/$1.crt" -key "$PKI/$1.key" </dev/null 2>/dev/null || true
}

http_get() { # path cert_basename|"" -> "<http_code>"
	local path=$1 name=${2:-}
	local args=(-s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*'
		--cacert "$PKI/ca.crt")
	[[ -n $name ]] && args+=(--cert "$PKI/$name.crt" --key "$PKI/$name.key")
	curl "${args[@]}" "https://127.0.0.1:$PORT_HTTP_SINK$path" 2>/dev/null || true
}

relay_log="$LOG/relay.out"

section "Scenario 1: chained instances over mTLS"

# 1. An authorized edge delivers entries into the relay's file sink
tcp_file="$(ingested tcp_chain)"
n=$(grep -c 'edge-01/' <<<"$tcp_file")
check "tcp_chain: authorized edge-01 entries reached the file sink ($n lines)" $((n >= 1))

http_file="$(ingested http_chain)"
n=$(grep -c 'edge-01/' <<<"$http_file")
check "http_chain: authorized edge-01 entries reached the file sink ($n lines)" $((n >= 1))

# 2. node_binding = "force" overrode the label the sender configured
n=$(grep -c 'edge-tcp/' <<<"$tcp_file")
check "node binding: sender's own label \"edge-tcp\" was not honored ($n lines)" $((n == 0))
n=$(grep -c 'edge-http/' <<<"$http_file")
check "node binding: sender's own label \"edge-http\" was not honored ($n lines)" $((n == 0))

# 3. An identity outside the allow list is refused, even claiming to be edge-01
n=$(grep -c 'Connection rejected by auth policy' "$relay_log")
check "allow list: unauthorized edge-99 connection rejected ($n rejections)" $((n >= 1))
n=$(grep -c 'edge-99' <<<"$tcp_file")
check "allow list: no edge-99 entry was ingested" $((n == 0))

# 4. A peer with no certificate cannot complete the handshake; edge_pinfail
# fails handshakes too, with "bad certificate"
timeout 5 openssl s_client -connect 127.0.0.1:$PORT_TCP_CHAIN \
	-CAfile "$PKI/ca.crt" </dev/null >/dev/null 2>&1
sleep 0.5
n=$(grep -c "TLS handshake failed.*didn't provide a certificate" "$relay_log")
check "client_auth: a peer with no certificate was refused ($n handshake errors)" $((n >= 1))

# 5. Dialer-side pinning: the relay's identity is not the one edge_pinfail pins
n=$(grep -c 'is not allowed' "$LOG/edge_pinfail.out")
check "server pinning: dialer refused a CA-valid server it does not pin ($n refusals)" $((n >= 1))
n=$(grep -c 'edge-pinfail' <<<"$tcp_file")
check "server pinning: pin-failing edge delivered nothing" $((n == 0))

section "Scenario 2: viewer clients on mTLS-gated sinks"

# 6. TCP sink: authorized viewer streams, rogue gets nothing
out="$(tcp_view viewer-01 4)"
n=$(grep -c 'edge-01/' <<<"$out")
check "tcp sink: viewer-01 streamed entries ($n lines)" $((n >= 1))

out="$(tcp_view rogue 4)"
n=$(grep -c '"message"' <<<"$out")
check "tcp sink: rogue viewer received no entries" $((n == 0))

# 7. HTTP sink: stream and status both gated
code="$(http_get /status viewer-01)"
check "http sink: /status served to viewer-01 (HTTP $code)" $(is "$code" 200)

code="$(http_get /status rogue)"
check "http sink: /status refused to rogue viewer (HTTP $code)" $(is "$code" 403)

code="$(http_get /stream rogue)"
check "http sink: /stream refused to rogue viewer (HTTP $code)" $(is "$code" 403)

# curl reports 000 when the handshake itself fails, which is what a client
# with no certificate must hit
code="$(http_get /status)"
check "http sink: client with no certificate failed the handshake (curl $code)" $(is "$code" 000)

sse="$(timeout 4 curl -sN --noproxy '*' --cacert "$PKI/ca.crt" \
	--cert "$PKI/viewer-01.crt" --key "$PKI/viewer-01.key" \
	"https://127.0.0.1:$PORT_HTTP_SINK/stream" 2>/dev/null || true)"
n=$(grep -c '^data:.*edge-01/' <<<"$sse")
check "http sink: viewer-01 received SSE events ($n events)" $((n >= 1))

# 8. The status endpoint reports the policy and its rejection count
status="$(curl -s --max-time 5 --noproxy '*' --cacert "$PKI/ca.crt" \
	--cert "$PKI/viewer-01.crt" --key "$PKI/viewer-01.key" \
	"https://127.0.0.1:$PORT_HTTP_SINK/status" 2>/dev/null || true)"
n=$(grep -c 'mtls' <<<"$status")
check "http sink: status endpoint reports the auth policy" $((n >= 1))
rej=$(grep -o '"auth_rejected"[ :]*[0-9]*' <<<"$status" | grep -o '[0-9]*$' || echo 0)
check "http sink: status endpoint counts auth rejections (auth_rejected=$rej)" $((rej >= 1))

summary
