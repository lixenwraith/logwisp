#!/usr/bin/env bash
# logwisp IPv6 test: a relay on ::1 takes both chain transports and serves
# viewers over TLS with an IPv6 SAN, and listeners keep to their address
# family. Skips (exit 77) on a host without an IPv6 loopback.
# Requires: bash 5+, openssl, curl, an IPv6 loopback. Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run-ipv6
PKI=$RUN/pki
AUTH=$RUN/auth
OUT=$RUN/out
USERS=$AUTH/users.toml
PORT_TCP_CHAIN=15851
PORT_HTTP_CHAIN=15852
PORT_TCP_SINK=15853
PORT_HTTP_SINK=15854
PORT_FAMILY=15855
PORTS="$PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK $PORT_FAMILY"
e2e_init "$@"

section "Setup"
# /proc/net/if_inet6 lists ::1 as 31 zeros and a 1; it is absent without IPv6
grep -qs '^0\{31\}1 ' /proc/net/if_inet6 || skip_all "this host has no IPv6 loopback (::1)"
need openssl curl
ports_free 127.0.0.1 $PORTS
ports_free ::1 $PORTS
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$AUTH" "$OUT"

# The relay certificate names only ::1: every dialer verifies an IPv6 SAN
pki_ca
pki_leaf relay relay.internal serverAuth "IP:::1"
info "test PKI in $(short "$PKI")/: ca, relay (SAN IP ::1)"
add_users "$USERS" edge-01 viewer-01
info "users edge-01, viewer-01 in $(short "$USERS")"

tls_server() { printf '[%s.tls]\nenabled = true\ncert_file = "%s"\nkey_file = "%s"\n' "$1" "$PKI/relay.crt" "$PKI/relay.key"; }
scram_server() { printf '[%s.auth]\ntype = "scram"\ncredentials_file = "%s"\n' "$1" "$USERS"; }

relay_pipeline() { # name source_type source_port sink_type sink_port
	cat <<EOF

[[pipelines]]
name = "$1"
[pipelines.flow.format]
type = "json"
sanitizer_policy = "json"

[[pipelines.plugin_sources]]
id = "in"
type = "$2"
[pipelines.plugin_sources.config]
host = "::1"
port = $3
EOF
	tls_server pipelines.plugin_sources.config
	scram_server pipelines.plugin_sources.config
	cat <<EOF

[[pipelines.plugin_sinks]]
id = "file"
type = "file"
[pipelines.plugin_sinks.config]
directory = "$OUT"
name = "$2"
flush_interval_ms = 200

[[pipelines.plugin_sinks]]
id = "out"
type = "$4"
[pipelines.plugin_sinks.config]
host = "::1"
port = $5
EOF
	tls_server pipelines.plugin_sinks.config
	scram_server pipelines.plugin_sinks.config
}

{
	printf 'status_reporter = false\n[logging]\noutput = "stdout"\nlevel = "info"\n'
	relay_pipeline relay_tcp tcp_chain $PORT_TCP_CHAIN tcp $PORT_TCP_SINK
	relay_pipeline relay_http http_chain $PORT_HTTP_CHAIN http $PORT_HTTP_SINK
} >"$CONF/relay.toml"

edge_conf() { # name sink_type port
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
host = "::1"
port = $3
node = "$1"
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
[pipelines.plugin_sinks.config.auth]
type = "scram"
username = "edge-01"
password_file = "$AUTH/edge-01.pass"
EOF
}
edge_conf edge_tcp tcp_chain $PORT_TCP_CHAIN
edge_conf edge_http http_chain $PORT_HTTP_CHAIN

# Plain http sinks whose /status names the listener that answered
family_conf() { # name host
	cat >"$CONF/$1.toml" <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "info"

[[pipelines]]
name = "$1"
[[pipelines.plugin_sources]]
id = "none"
type = "null"
[[pipelines.plugin_sinks]]
id = "$1"
type = "http"
[pipelines.plugin_sinks.config]
host = "$2"
port = $PORT_FAMILY
EOF
}
family_conf any6 "::"
family_conf any4 "0.0.0.0"
info "configurations in $(short "$CONF")/"

section "Startup"
start_daemon relay relay.toml
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK; do
	wait_port "$p" ::1 || abort "relay port $p is not listening on ::1" relay
done
start_daemon edge_tcp edge_tcp.toml
start_daemon edge_http edge_http.toml
start_daemon any6 any6.toml
ANY6_PID=${PIDS[-1]}
wait_port $PORT_FAMILY ::1 || abort "any6 is not listening on [::]:$PORT_FAMILY" any6
# The checks start any4 themselves, after testing :: alone
((AUTO)) || start_daemon any4 any4.toml
daemons_up
write_env LW="$BIN" CA="$PKI/ca.crt" PW="$AUTH/viewer-01.pass"

guide "logwisp IPv6 test" <<EOF
Ports (relay on ::1, TLS with SAN IP ::1, scram):
  $PORT_TCP_CHAIN  relay tcp_chain ingest, edge_tcp dials [::1]
  $PORT_HTTP_CHAIN  relay http_chain ingest, edge_http dials [::1]
  $PORT_TCP_SINK  tcp sink
  $PORT_HTTP_SINK  http sink
  $PORT_FAMILY  plain http sinks side by side: any6 on ::, any4 on 0.0.0.0
Shell setup (LW, CA, PW: viewer-01's password file):
> . $(short "$RUN")/env
Read the tcp sink as viewer-01:
> \$LW auth stream -addr [::1]:$PORT_TCP_SINK -user viewer-01 -password-file \$PW -ca-file \$CA
Read the http sink (bearer keeps the token off argv; -g leaves the brackets to the URL):
> token=\$(\$LW auth token -url https://[::1]:$PORT_HTTP_SINK -user viewer-01 -password-file \$PW -ca-file \$CA)
> curl -gN --cacert \$CA -H @<(bearer) https://[::1]:$PORT_HTTP_SINK/stream
Which listener answers on $PORT_FAMILY:
> curl -s http://127.0.0.1:$PORT_FAMILY/status; curl -gs http://[::1]:$PORT_FAMILY/status
Ingested entries: $(short "$OUT")/   Passwords: $(short "$AUTH")/
Logs: $(short "$LOG")/
EOF
manual_hold

relay_log="$LOG/relay.out"
curl_args=(-g -s --max-time 5 --noproxy '*')
answered_by() { # url -> the instance whose /status answered, empty if refused
	curl "${curl_args[@]}" "$1/status" 2>/dev/null | grep -o '"instance_id":"[^"]*"' | cut -d'"' -f4
}

section "Scenario 1: chain links and viewers over [::1]"

# 1. Both chain transports deliver; the http_chain edge logged in at
# https://[::1]:PORT/auth first
wait_until 20 has_entry tcp_chain 'edge-01/'
n=$(ingested tcp_chain | grep -c 'edge-01/')
check "tcp_chain: entries from the edge dialing [::1] reached the relay ($n lines)" $((n >= 1))
wait_until 20 has_entry http_chain 'edge-01/'
n=$(ingested http_chain | grep -c 'edge-01/')
check "http_chain: entries from the edge dialing [::1] reached the relay ($n lines)" $((n >= 1))

# The logger quotes a value holding brackets
n=$(grep -cF "addr \"[::1]:$PORT_TCP_CHAIN\"" "$relay_log")
check "relay logged its listener as [::1]:$PORT_TCP_CHAIN ($n)" $((n >= 1))

# 2. HTTP sink: lw auth token at an IPv6 URL, the token carried by curl -g
token="$("$BIN" auth token -url "https://[::1]:$PORT_HTTP_SINK" -user viewer-01 \
	-password-file "$AUTH/viewer-01.pass" -ca-file "$PKI/ca.crt" 2>>"$LOG/auth-cli.out")"
check "http sink: lw auth token -url https://[::1]:$PORT_HTTP_SINK issued a token" $(is_set "$token")

code="$(curl "${curl_args[@]}" -o /dev/null -w '%{http_code}' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") "https://[::1]:$PORT_HTTP_SINK/status" 2>/dev/null || true)"
check "http sink: curl -g https://[::1]:$PORT_HTTP_SINK/status with the token (HTTP $code)" $(is "$code" 200)

sse="$(timeout 4 curl -gsN --noproxy '*' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") \
	"https://[::1]:$PORT_HTTP_SINK/stream" 2>/dev/null || true)"
n=$(grep -c '^data:.*edge-01/' <<<"$sse")
check "http sink: /stream delivered SSE events over [::1] ($n events)" $((n >= 1))

# 3. TCP sink: lw auth stream at an IPv6 address
timeout 4 "$BIN" auth stream -addr "[::1]:$PORT_TCP_SINK" -user viewer-01 \
	-password-file "$AUTH/viewer-01.pass" -ca-file "$PKI/ca.crt" \
	>"$RUN/stream.out" 2>"$LOG/stream.err"
n=$(grep -c 'edge-01/' "$RUN/stream.out")
check "tcp sink: lw auth stream -addr [::1]:$PORT_TCP_SINK streamed entries ($n lines)" $((n >= 1))

section "Scenario 2: each listener keeps to its address family"

# 4. :: is IPv6-only: it takes [::1] and leaves IPv4, and its port, alone
who="$(answered_by "http://[::1]:$PORT_FAMILY")"
check ":: listener accepts [::1] (answered by ${who:-nobody})" $(is "$who" any6)
who="$(answered_by "http://127.0.0.1:$PORT_FAMILY")"
check ":: listener refuses 127.0.0.1 (answered by ${who:-nobody})" $(is "$who" "")

start_daemon any4 any4.toml
wait_port $PORT_FAMILY 127.0.0.1
who="$(answered_by "http://127.0.0.1:$PORT_FAMILY")"
check "0.0.0.0 binds the same port beside :: and takes 127.0.0.1 (answered by ${who:-nobody})" $(is "$who" any4)

# 5. 0.0.0.0 is IPv4-only: with :: gone, [::1] finds nobody
kill -TERM "$ANY6_PID"
wait "$ANY6_PID" 2>/dev/null
who="$(answered_by "http://[::1]:$PORT_FAMILY")"
check "0.0.0.0 listener refuses [::1] (answered by ${who:-nobody})" $(is "$who" "")

summary
