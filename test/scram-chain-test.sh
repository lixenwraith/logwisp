#!/usr/bin/env bash
# logwisp SCRAM authentication test: chain edges and sink viewers log in with
# passwords managed by `lw auth`; the guide printed below maps the ports.
# Usage: ./scram-chain-test.sh [--auto [--keep]]   manual mode keeps the daemons
#   up; --auto runs the checks and tears down, --keep skips that on success.
# Requires: bash 5+, coreutils (timeout), openssl, curl. Linux dev host only.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${LOGWISP_BIN:-$SCRIPT_DIR/../bin/lw}"
RUN="$SCRIPT_DIR/run-scram"
CONF="$RUN/conf"
LOG="$RUN/log"
PKI="$RUN/pki"
AUTH="$RUN/auth"
OUT="$RUN/out"
USERS="$AUTH/users.toml"

PORT_TCP_CHAIN=15821
PORT_HTTP_CHAIN=15822
PORT_TCP_SINK=15823
PORT_HTTP_SINK=15824
PORT_BOUND=15825

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

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3>&-; }

wait_port() { # port timeout_s
	local i; for (( i=0; i < $2 * 10; i++ )); do
		port_open "$1" && return 0
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
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (build: go build -o bin/lw ./cmd/lw)" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK $PORT_BOUND; do
	port_open "$p" && { echo "port $p already in use" >&2; exit 1; }
done
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$AUTH" "$OUT"

# --- PKI ---
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
gen_leaf relay   relay.internal serverAuth "IP:127.0.0.1"
gen_leaf edge-01 edge-01        clientAuth
gen_leaf edge-02 edge-02        clientAuth
[[ -s "$PKI/edge-02.crt" ]] || { echo "PKI generation failed" >&2; exit 1; }

# --- Credentials, through the CLI only ---
echo "--- adding users in $USERS"
for u in edge-01 edge-02 viewer-01; do
	"$BIN" auth add-user -credentials "$USERS" -user "$u" -password-file "$AUTH/$u.pass" \
		2>>"$LOG/auth-cli.out" || { echo "add-user $u failed (see $LOG/auth-cli.out)" >&2; exit 1; }
done
# A password no user has, for the wrong-password and unknown-user edges
(umask 077; openssl rand -base64 24 > "$AUTH/wrong.pass")

# --- Config generation ---
# One credentials file serves every listener, so revoking viewer-01 leaves the
# file with users (the CLI refuses to remove the last one).
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
[pipelines.plugin_sources.config.auth]
type = "scram"
credentials_file = "$USERS"
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
[pipelines.plugin_sinks.config.auth]
type = "scram"
credentials_file = "$USERS"

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
[pipelines.plugin_sources.config.auth]
type = "scram"
credentials_file = "$USERS"

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
[pipelines.plugin_sinks.config.auth]
type = "scram"
credentials_file = "$USERS"

[[pipelines]]
name = "relay_bound"
[pipelines.flow.format]
type = "json"
sanitizer_policy = "json"

# identity binds the certificate to the user: a peer needs its own of both
[[pipelines.plugin_sources]]
id = "in_bound"
type = "tcp_chain"
[pipelines.plugin_sources.config]
host = "127.0.0.1"
port = $PORT_BOUND
[pipelines.plugin_sources.config.tls]
enabled = true
cert_file = "$PKI/relay.crt"
key_file = "$PKI/relay.key"
client_auth = true
client_ca_file = "$PKI/ca.crt"
[pipelines.plugin_sources.config.auth]
type = "scram"
credentials_file = "$USERS"
identity = "cn"

[[pipelines.plugin_sinks]]
id = "file_bound"
type = "file"
[pipelines.plugin_sinks.config]
directory = "$OUT"
name = "bound"
flush_interval_ms = 200
EOF

edge_conf() { # name sink_type port node user password_file [client_cert]
	local name=$1 type=$2 port=$3 node=$4 user=$5 pass=$6 cert=${7:-}
	{
		cat <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "info"

[[pipelines]]
name = "$name"
[[pipelines.plugin_sources]]
id = "rand"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 200
format = "txt"
length = 24
[[pipelines.plugin_sinks]]
id = "to_relay"
type = "$type"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $port
node = "$node"
[pipelines.plugin_sinks.config.tls]
enabled = true
ca_file = "$PKI/ca.crt"
EOF
		[[ -n $cert ]] && printf 'cert_file = "%s"\nkey_file = "%s"\n' "$PKI/$cert.crt" "$PKI/$cert.key"
		[[ -n $user ]] && printf '[pipelines.plugin_sinks.config.auth]\ntype = "scram"\nusername = "%s"\npassword_file = "%s"\n' "$user" "$pass"
	} > "$CONF/$name.toml"
}

# edge_tcp declares node "edge-tcp": node_binding = "force" must relabel it edge-01.
# Under force a refused edge that got through would carry its username, so
# edge-02 and edge-99 entries in the edge-01 sinks would expose it.
edge_conf edge_tcp     tcp_chain  $PORT_TCP_CHAIN  edge-tcp     edge-01 "$AUTH/edge-01.pass"
edge_conf edge_http    http_chain $PORT_HTTP_CHAIN edge-http    edge-01 "$AUTH/edge-01.pass"
edge_conf edge_wrongpw tcp_chain  $PORT_TCP_CHAIN  edge-wrongpw edge-02 "$AUTH/wrong.pass"
edge_conf edge_unknown tcp_chain  $PORT_TCP_CHAIN  edge-unknown edge-99 "$AUTH/wrong.pass"
edge_conf edge_noauth  tcp_chain  $PORT_TCP_CHAIN  edge-noauth  ""      ""
edge_conf edge_bound   tcp_chain  $PORT_BOUND      edge-bound   edge-01 "$AUTH/edge-01.pass" edge-01
edge_conf edge_cross   tcp_chain  $PORT_BOUND      edge-cross   edge-02 "$AUTH/edge-02.pass" edge-01

# --- Guide ---
cat <<EOF
================================================================
 logwisp SCRAM auth test — port map
   $PORT_TCP_CHAIN  relay ingest (tcp_chain,  scram, node_binding = force)
   $PORT_HTTP_CHAIN  relay ingest (http_chain, scram)
   $PORT_TCP_SINK  TCP sink     (scram)
   $PORT_HTTP_SINK  HTTP sink    (scram)
   $PORT_BOUND  relay ingest (tcp_chain, client_auth + scram, certificate CN = user)

 Edges: edge_tcp and edge_http log in as edge-01 and deliver; edge_wrongpw,
 edge_unknown and edge_noauth are refused on $PORT_TCP_CHAIN; on $PORT_BOUND
 edge_bound (edge-01 cert, user edge-01) delivers and edge_cross (edge-01
 cert, user edge-02) is refused; $PKI/edge-02.crt pairs with user edge-02.

 Read the TCP sink as viewer-01:
   $BIN auth stream -addr 127.0.0.1:$PORT_TCP_SINK -user viewer-01 \\
     -password-file $AUTH/viewer-01.pass -ca-file $PKI/ca.crt
 Read the HTTP sink (the token stays off argv):
   token=\$($BIN auth token -url https://127.0.0.1:$PORT_HTTP_SINK -user viewer-01 \\
     -password-file $AUTH/viewer-01.pass -ca-file $PKI/ca.crt)
   curl -N --noproxy '*' --cacert $PKI/ca.crt \\
     -H @<(printf 'Authorization: Bearer %s\n' "\$token") https://127.0.0.1:$PORT_HTTP_SINK/stream
 Revoke: $BIN auth remove-user -credentials $USERS -user viewer-01
   then kill -HUP the relay.

 Ingested entries land in $OUT/ (node label forced to the username).
 Passwords and credentials: $AUTH/   Logs: $LOG/
================================================================
EOF

# --- Startup ---
start_daemon relay relay.toml
RELAY_PID=${PIDS[-1]}
for p in $PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK $PORT_BOUND; do
	wait_port "$p" 10 || { echo "FAIL: relay port $p not listening (see $LOG/relay.out)"; exit 1; }
done
for e in edge_tcp edge_http edge_wrongpw edge_unknown edge_noauth edge_bound edge_cross; do
	start_daemon "$e" "$e.toml"
done

if (( AUTO == 0 )); then
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

logged() { # log_name pattern [min_count]
	local n; n=$(grep -c -- "$2" "$LOG/$1.out" 2>/dev/null)
	(( ${n:-0} >= ${3:-1} ))
}

token_for() { # user -> token on stdout; the exit status is the CLI's
	"$BIN" auth token -url "https://127.0.0.1:$PORT_HTTP_SINK" -user "$1" \
		-password-file "$AUTH/$1.pass" -ca-file "$PKI/ca.crt" 2>>"$LOG/auth-cli.out"
}

http_get() { # path [token] -> http_code; the header goes through a pipe, never argv
	local url="https://127.0.0.1:$PORT_HTTP_SINK$1"
	local args=(-s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' --cacert "$PKI/ca.crt")
	if [[ -n ${2:-} ]]; then
		curl "${args[@]}" -H @<(printf 'Authorization: Bearer %s\n' "$2") "$url" 2>/dev/null || true
	else
		curl "${args[@]}" "$url" 2>/dev/null || true
	fi
}

echo "=== Scenario 1: chained instances over SCRAM ==="

# 1. An edge with the right password delivers on both transports
wait_until 20 has_entry tcp_chain 'edge-01/'
tcp_file="$(ingested tcp_chain)"
n=$(grep -c 'edge-01/' <<< "$tcp_file")
check "tcp_chain: edge-01 entries reached the file sink ($n lines)" $(( n >= 1 ))

wait_until 20 has_entry http_chain 'edge-01/'
http_file="$(ingested http_chain)"
n=$(grep -c 'edge-01/' <<< "$http_file")
check "http_chain: edge-01 entries reached the file sink ($n lines)" $(( n >= 1 ))

# 2. node_binding = "force" replaced the label the sender configured
n=$(grep -c 'edge-tcp/' <<< "$tcp_file")
check "node binding: sender's own label \"edge-tcp\" was not honored ($n lines)" $(( n == 0 ))
n=$(grep -c 'edge-http/' <<< "$http_file")
check "node binding: sender's own label \"edge-http\" was not honored ($n lines)" $(( n == 0 ))

# 3. Wrong password, unknown user and no credentials are all refused
wait_until 20 logged edge_wrongpw 'Chain connect refused'
n=$(grep -c 'Chain connect refused' "$LOG/edge_wrongpw.out")
check "wrong password: edge-02 with a bad password was refused ($n refusals)" $(( n >= 1 ))

wait_until 20 logged edge_unknown 'Chain connect refused'
n=$(grep -c 'Chain connect refused' "$LOG/edge_unknown.out")
check "unknown user: edge-99 was refused ($n refusals)" $(( n >= 1 ))

wait_until 20 logged relay 'peer offered no credentials'
n=$(grep -c 'peer offered no credentials' "$relay_log")
check "no auth: relay refused an edge that offered no credentials ($n refusals)" $(( n >= 1 ))

wait_until 20 logged edge_noauth 'Chain link refused'
n=$(grep -c 'Chain link refused' "$LOG/edge_noauth.out")
check "no auth: the edge read the refusal instead of writing into a closed link ($n)" $(( n >= 1 ))

failed_login='Connection rejected by auth policy.*instance_id in_tcp .*invalid credentials'
wait_until 20 logged relay "$failed_login" 2
n=$(grep -c "$failed_login" "$relay_log")
check "relay logged the failed logins on :$PORT_TCP_CHAIN ($n rejections)" $(( n >= 2 ))

tcp_file="$(ingested tcp_chain)"
n=$(grep -vc 'edge-01/' <<< "$tcp_file")
check "refused edges: nothing but edge-01 entries was ingested ($n foreign lines)" $(( n == 0 ))

# 4. Certificate bound to the user: edge-01's certificate admits only edge-01
wait_until 20 has_entry bound 'edge-01/'
n=$(ingested bound | grep -c 'edge-01/')
check "certificate binding: edge-01 certificate + user edge-01 delivered ($n lines)" $(( n >= 1 ))

wait_until 20 logged edge_cross 'Chain connect refused'
n=$(grep -c 'Chain connect refused' "$LOG/edge_cross.out")
check "certificate binding: edge-01 certificate + user edge-02 was refused ($n refusals)" $(( n >= 1 ))
wait_until 20 logged relay 'does not match user \\"edge-02\\"'
n=$(grep -c 'does not match user \\"edge-02\\"' "$relay_log")
check "certificate binding: relay logged the certificate/user mismatch ($n)" $(( n >= 1 ))
n=$(ingested bound | grep -vc 'edge-01/')
check "certificate binding: the cross-bound edge delivered nothing ($n foreign lines)" $(( n == 0 ))

echo "=== Scenario 2: viewers on SCRAM-gated sinks ==="

# 5. TCP sink: a logged-in viewer keeps streaming past the 10 s exchange
# deadline; a TLS client that sends no hello gets nothing and is dropped at it
"$BIN" auth stream -addr "127.0.0.1:$PORT_TCP_SINK" -user viewer-01 \
	-password-file "$AUTH/viewer-01.pass" -ca-file "$PKI/ca.crt" \
	> "$RUN/stream.out" 2>"$LOG/stream.err" &
stream_pid=$!
PIDS+=($stream_pid)
timeout 12 openssl s_client -quiet -connect "127.0.0.1:$PORT_TCP_SINK" \
	-CAfile "$PKI/ca.crt" </dev/null >"$RUN/raw.out" 2>/dev/null &
raw_pid=$!
sleep 11
n1=$(grep -c 'edge-01/' "$RUN/stream.out")
sleep 2
n2=$(grep -c 'edge-01/' "$RUN/stream.out")
kill -TERM "$stream_pid" 2>/dev/null
wait "$stream_pid" "$raw_pid" 2>/dev/null
check "tcp sink: viewer-01 streamed entries through lw auth stream ($n1 lines at 11 s)" $(( n1 >= 1 ))
check "tcp sink: stream still live after the exchange deadline ($n1 -> $n2 lines, 11 s -> 13 s)" $(( n2 > n1 ))
n=$(wc -c < "$RUN/raw.out")
check "tcp sink: a TLS client with no hello received nothing ($n bytes)" $(( n == 0 ))
n=$(grep 'component tcp_sink' "$relay_log" | grep -c 'read hello')
check "tcp sink: relay dropped the silent client at the exchange deadline ($n)" $(( n >= 1 ))

# 6. HTTP sink: a bearer token from lw auth token, carried by curl
token="$(token_for viewer-01)"
check "http sink: lw auth token issued a token for viewer-01" $([[ -n $token ]] && echo 1 || echo 0)

code="$(http_get /status "$token")"
check "http sink: /status served with the token (HTTP $code)" $([[ $code == 200 ]] && echo 1 || echo 0)

sse="$(timeout 4 curl -sN --noproxy '*' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") \
	"https://127.0.0.1:$PORT_HTTP_SINK/stream" 2>/dev/null || true)"
n=$(grep -c '^data:.*edge-01/' <<< "$sse")
check "http sink: /stream delivered SSE events with the token ($n events)" $(( n >= 1 ))

code="$(http_get /status)"
check "http sink: /status refused without a token (HTTP $code)" $([[ $code == 401 ]] && echo 1 || echo 0)
code="$(http_get /stream not.a.token)"
check "http sink: /stream refused with a garbage token (HTTP $code)" $([[ $code == 401 ]] && echo 1 || echo 0)

# 7. Revocation: remove-user + SIGHUP kills the token and the login
reloads=$(grep -c 'Configuration hot reload completed successfully' "$relay_log")
reloaded() { (( $(grep -c 'Configuration hot reload completed successfully' "$relay_log") > reloads )); }
"$BIN" auth remove-user -credentials "$USERS" -user viewer-01 2>>"$LOG/auth-cli.out"
rc=$?
check "revocation: lw auth remove-user removed viewer-01 (exit $rc)" $(( rc == 0 ))
kill -HUP "$RELAY_PID"
wait_until 20 reloaded && wait_port "$PORT_HTTP_SINK" 10
rc=$?
check "revocation: relay reloaded on SIGHUP" $(( rc == 0 ))

code="$(http_get /status "$token")"
check "revocation: the old token is refused after the reload (HTTP $code)" $([[ $code == 401 ]] && echo 1 || echo 0)
token_for viewer-01 >/dev/null
rc=$?
check "revocation: lw auth token for viewer-01 now fails (exit $rc)" $(( rc == 1 ))

# 8. Throttling, last: it leaves this address throttled on the http sink.
# At most 4 exchanges may be unfinished per address, so hellos that are
# never completed reach 429 within a few requests.
codes=()
for i in $(seq 1 12); do
	hello="$(printf '{"logwisp":1,"scram":{"username":"edge-01","client_nonce":"probe%d"}}' "$i")"
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' --cacert "$PKI/ca.crt" \
		-H 'Content-Type: application/json' --data "$hello" \
		"https://127.0.0.1:$PORT_HTTP_SINK/auth" 2>/dev/null || true)"
	codes+=("$code")
	[[ $code == 429 ]] && break
done
check "throttling: /auth answered 429 after ${#codes[@]} rapid hellos (${codes[*]})" \
	$([[ $code == 429 ]] && (( ${#codes[@]} <= 6 )) && echo 1 || echo 0)

echo "================================================================"
if (( fail == 0 )); then
	echo "RESULT: ALL PASS"
	(( KEEP )) && { echo "--keep: daemons left running (pids: ${PIDS[*]})"; PIDS=(); }
else
	echo "RESULT: FAILURES — inspect $LOG/*.out"
fi
exit "$fail"
