#!/usr/bin/env bash
# logwisp IPv6 test: a relay on ::1 takes both chain transports and serves
# viewers over TLS with IPv6 SANs, and listeners keep to their address family;
# the guide printed below maps the ports.
# Usage: ./ipv6-test.sh [--auto [--keep]]   manual mode keeps the daemons up;
#   --auto runs the checks and tears down, --keep skips that on success.
# Requires: bash 5+, openssl, curl, an IPv6 loopback. Linux dev host only.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${LOGWISP_BIN:-$SCRIPT_DIR/../bin/lw}"
RUN="$SCRIPT_DIR/run-ipv6"
CONF="$RUN/conf"
LOG="$RUN/log"
PKI="$RUN/pki"
AUTH="$RUN/auth"
OUT="$RUN/out"
USERS="$AUTH/users.toml"

PORT_TCP_CHAIN=15851
PORT_HTTP_CHAIN=15852
PORT_TCP_SINK=15853
PORT_HTTP_SINK=15854
PORT_FAMILY=15855

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
		echo "--- teardown: stopping ${#PIDS[@]} process(es)"
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

port_open() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && exec 3>&-; } # host port

wait_port() { # host port timeout_s
	local i; for (( i=0; i < $3 * 10; i++ )); do
		port_open "$1" "$2" && return 0
		sleep 0.1
	done
	return 1
}

wait_until() { # timeout_s command...
	local deadline=$(( SECONDS + $1 )); shift
	until "$@"; do
		(( SECONDS >= deadline )) && return 1
		sleep 0.2
	done
}

start_daemon() { # name conf
	"$BIN" -c "$CONF/$2" > "$LOG/$1.out" 2>&1 &
	PIDS+=($!)
	echo "started $1 (pid $!)"
}

# --- Preflight ---
if ! grep -qs '^0\{31\}1 ' /proc/net/if_inet6; then
	echo "SKIP: this host has no IPv6 loopback (::1); nothing to test"
	exit 0
fi
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (build: go build -o bin/lw ./cmd/lw)" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK $PORT_FAMILY; do
	for h in 127.0.0.1 ::1; do
		port_open "$h" "$p" && { echo "port $p already in use on $h" >&2; exit 1; }
	done
done
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$AUTH" "$OUT"

# --- PKI ---
gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

echo "--- generating test PKI in $PKI"
gen_key "$PKI/ca.key"
openssl req -x509 -new -key "$PKI/ca.key" -days 2 -out "$PKI/ca.crt" \
	-subj "/CN=LogWisp Test CA" 2>/dev/null
# The relay certificate names only ::1: every dialer verifies an IPv6 SAN
gen_key "$PKI/relay.key"
openssl req -new -key "$PKI/relay.key" -out "$PKI/relay.csr" -subj "/CN=relay.internal" 2>/dev/null
printf 'extendedKeyUsage=serverAuth\nsubjectAltName=IP:::1\n' > "$PKI/relay.ext"
openssl x509 -req -in "$PKI/relay.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
	-CAcreateserial -out "$PKI/relay.crt" -days 2 -extfile "$PKI/relay.ext" 2>/dev/null
[[ -s "$PKI/relay.crt" ]] || { echo "PKI generation failed" >&2; exit 1; }

# --- Credentials ---
echo "--- adding users in $USERS"
for u in edge-01 viewer-01; do
	"$BIN" auth add-user -credentials "$USERS" -user "$u" -password-file "$AUTH/$u.pass" \
		2>>"$LOG/auth-cli.out" || { echo "add-user $u failed (see $LOG/auth-cli.out)" >&2; exit 1; }
done

# --- Config generation ---
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
	relay_pipeline relay_tcp  tcp_chain  $PORT_TCP_CHAIN  tcp  $PORT_TCP_SINK
	relay_pipeline relay_http http_chain $PORT_HTTP_CHAIN http $PORT_HTTP_SINK
} > "$CONF/relay.toml"

edge_conf() { # name sink_type port
	cat > "$CONF/$1.toml" <<EOF
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
edge_conf edge_tcp  tcp_chain  $PORT_TCP_CHAIN
edge_conf edge_http http_chain $PORT_HTTP_CHAIN

# Plain http sinks whose /status names the listener that answered
family_conf() { # name host
	cat > "$CONF/$1.toml" <<EOF
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

# --- Guide ---
cat <<EOF
================================================================
 logwisp IPv6 test — port map (relay on ::1, TLS with SAN IP:::1, scram)
   $PORT_TCP_CHAIN  relay ingest (tcp_chain)    <- edge_tcp dials [::1]
   $PORT_HTTP_CHAIN  relay ingest (http_chain)   <- edge_http dials [::1]
   $PORT_TCP_SINK  TCP sink
   $PORT_HTTP_SINK  HTTP sink
   $PORT_FAMILY  plain http sinks: any6 on ::, any4 on 0.0.0.0, side by side

 Read the TCP sink as viewer-01:
   $BIN auth stream -addr [::1]:$PORT_TCP_SINK -user viewer-01 \\
     -password-file $AUTH/viewer-01.pass -ca-file $PKI/ca.crt
 Read the HTTP sink (the token stays off argv; -g keeps curl off the brackets):
   token=\$($BIN auth token -url https://[::1]:$PORT_HTTP_SINK -user viewer-01 \\
     -password-file $AUTH/viewer-01.pass -ca-file $PKI/ca.crt)
   curl -gN --noproxy '*' --cacert $PKI/ca.crt \\
     -H @<(printf 'Authorization: Bearer %s\n' "\$token") https://[::1]:$PORT_HTTP_SINK/stream
 Which listener answers on $PORT_FAMILY:
   curl -s http://127.0.0.1:$PORT_FAMILY/status; curl -gs http://[::1]:$PORT_FAMILY/status

 Ingested entries land in $OUT/. Passwords: $AUTH/   Logs: $LOG/
================================================================
EOF

# --- Startup ---
start_daemon relay relay.toml
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK; do
	wait_port ::1 "$p" 10 || { echo "FAIL: relay port $p not listening on ::1 (see $LOG/relay.out)"; exit 1; }
done
start_daemon edge_tcp edge_tcp.toml
start_daemon edge_http edge_http.toml
start_daemon any6 any6.toml
ANY6_PID=${PIDS[-1]}
wait_port ::1 $PORT_FAMILY 10 || { echo "FAIL: any6 not listening on [::1]:$PORT_FAMILY (see $LOG/any6.out)"; exit 1; }

if (( AUTO == 0 )); then
	start_daemon any4 any4.toml
	echo "--- daemons running; Ctrl-C to stop"
	while :; do sleep 1; done
fi

fail=0
check() { # label condition_result
	if (( $2 )); then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

relay_log="$LOG/relay.out"
ingested() { cat "$OUT"/${1}* 2>/dev/null; }
has_entry() { ingested "$1" | grep -q -- "$2"; } # file_prefix pattern

curl_args=(-g -s --max-time 5 --noproxy '*')
answered_by() { # url -> the instance whose /status answered, empty if refused
	curl "${curl_args[@]}" "$1/status" 2>/dev/null | grep -o '"instance_id":"[^"]*"' | cut -d'"' -f4
}

echo "=== Scenario 1: chain links and viewers over [::1] ==="

# 1. Both chain transports deliver; the http_chain edge logged in at
# https://[::1]:PORT/auth first
wait_until 20 has_entry tcp_chain 'edge-01/'
n=$(ingested tcp_chain | grep -c 'edge-01/')
check "tcp_chain: entries from the edge dialing [::1] reached the relay ($n lines)" $(( n >= 1 ))
wait_until 20 has_entry http_chain 'edge-01/'
n=$(ingested http_chain | grep -c 'edge-01/')
check "http_chain: entries from the edge dialing [::1] reached the relay ($n lines)" $(( n >= 1 ))

n=$(grep -cF "addr \"[::1]:$PORT_TCP_CHAIN\"" "$relay_log")
check "relay logged its listener as [::1]:$PORT_TCP_CHAIN ($n)" $(( n >= 1 ))

# 2. HTTP sink: lw auth token at an IPv6 URL, the token carried by curl -g
token="$("$BIN" auth token -url "https://[::1]:$PORT_HTTP_SINK" -user viewer-01 \
	-password-file "$AUTH/viewer-01.pass" -ca-file "$PKI/ca.crt" 2>>"$LOG/auth-cli.out")"
check "http sink: lw auth token -url https://[::1]:$PORT_HTTP_SINK issued a token" $([[ -n $token ]] && echo 1 || echo 0)

code="$(curl "${curl_args[@]}" -o /dev/null -w '%{http_code}' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") "https://[::1]:$PORT_HTTP_SINK/status" 2>/dev/null || true)"
check "http sink: curl -g https://[::1]:$PORT_HTTP_SINK/status with the token (HTTP $code)" $([[ $code == 200 ]] && echo 1 || echo 0)

sse="$(timeout 4 curl -gsN --noproxy '*' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") \
	"https://[::1]:$PORT_HTTP_SINK/stream" 2>/dev/null || true)"
n=$(grep -c '^data:.*edge-01/' <<< "$sse")
check "http sink: /stream delivered SSE events over [::1] ($n events)" $(( n >= 1 ))

# 3. TCP sink: lw auth stream at an IPv6 address
timeout 4 "$BIN" auth stream -addr "[::1]:$PORT_TCP_SINK" -user viewer-01 \
	-password-file "$AUTH/viewer-01.pass" -ca-file "$PKI/ca.crt" \
	> "$RUN/stream.out" 2>"$LOG/stream.err"
n=$(grep -c 'edge-01/' "$RUN/stream.out")
check "tcp sink: lw auth stream -addr [::1]:$PORT_TCP_SINK streamed entries ($n lines)" $(( n >= 1 ))

echo "=== Scenario 2: each listener keeps to its address family ==="

# 4. :: is IPv6-only: it takes [::1] and leaves IPv4, and its port, alone
who="$(answered_by "http://[::1]:$PORT_FAMILY")"
check ":: listener accepts [::1] (answered by ${who:-nobody})" $([[ $who == any6 ]] && echo 1 || echo 0)
who="$(answered_by "http://127.0.0.1:$PORT_FAMILY")"
check ":: listener refuses 127.0.0.1 (answered by ${who:-nobody})" $([[ -z $who ]] && echo 1 || echo 0)

start_daemon any4 any4.toml
wait_port 127.0.0.1 $PORT_FAMILY 10
who="$(answered_by "http://127.0.0.1:$PORT_FAMILY")"
check "0.0.0.0 binds the same port beside :: and takes 127.0.0.1 (answered by ${who:-nobody})" $([[ $who == any4 ]] && echo 1 || echo 0)

# 5. 0.0.0.0 is IPv4-only: with :: gone, [::1] finds nobody
kill -TERM "$ANY6_PID"
wait "$ANY6_PID" 2>/dev/null
who="$(answered_by "http://[::1]:$PORT_FAMILY")"
check "0.0.0.0 listener refuses [::1] (answered by ${who:-nobody})" $([[ -z $who ]] && echo 1 || echo 0)

echo "================================================================"
if (( fail == 0 )); then
	echo "RESULT: ALL PASS"
	(( KEEP )) && { echo "--keep: daemons left running (pids: ${PIDS[*]})"; PIDS=(); }
else
	echo "RESULT: FAILURES — inspect $LOG/*.out"
fi
exit "$fail"
