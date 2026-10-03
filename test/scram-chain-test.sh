#!/usr/bin/env bash
# logwisp SCRAM test: chain edges and sink viewers log in with passwords
# managed by `lw auth`: wrong and missing credentials, a certificate bound to
# its user, a stream past the exchange deadline, revocation and throttling.
# Requires: bash 5+, coreutils (timeout), openssl, curl. Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run-scram
PKI=$RUN/pki
AUTH=$RUN/auth
OUT=$RUN/out
USERS=$AUTH/users.toml
PORT_TCP_CHAIN=15821
PORT_HTTP_CHAIN=15822
PORT_TCP_SINK=15823
PORT_HTTP_SINK=15824
PORT_BOUND=15825
PORTS="$PORT_TCP_CHAIN $PORT_HTTP_CHAIN $PORT_TCP_SINK $PORT_HTTP_SINK $PORT_BOUND"
e2e_init "$@"

section "Setup"
need openssl curl
ports_free $PORTS
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$AUTH" "$OUT"

pki_ca
pki_leaf relay relay.internal serverAuth "IP:127.0.0.1"
pki_leaf edge-01 edge-01 clientAuth
pki_leaf edge-02 edge-02 clientAuth
info "test PKI in $(short "$PKI")/: ca, relay, edge-01, edge-02"

# Credentials through the CLI only, and a password no user has, for the
# wrong-password and unknown-user edges
add_users "$USERS" edge-01 edge-02 viewer-01
(umask 077; openssl rand -base64 24 >"$AUTH/wrong.pass")
info "users edge-01, edge-02, viewer-01 in $(short "$USERS")"

# One credentials file serves every listener, so revoking viewer-01 leaves the
# file with users (the CLI refuses to remove the last one).
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
	} >"$CONF/$name.toml"
}

# edge_tcp declares node "edge-tcp": node_binding = "force" must relabel it edge-01.
# Under force a refused edge that got through would carry its username, so
# edge-02 and edge-99 entries in the edge-01 sinks would expose it.
edge_conf edge_tcp tcp_chain $PORT_TCP_CHAIN edge-tcp edge-01 "$AUTH/edge-01.pass"
edge_conf edge_http http_chain $PORT_HTTP_CHAIN edge-http edge-01 "$AUTH/edge-01.pass"
edge_conf edge_wrongpw tcp_chain $PORT_TCP_CHAIN edge-wrongpw edge-02 "$AUTH/wrong.pass"
edge_conf edge_unknown tcp_chain $PORT_TCP_CHAIN edge-unknown edge-99 "$AUTH/wrong.pass"
edge_conf edge_noauth tcp_chain $PORT_TCP_CHAIN edge-noauth "" ""
edge_conf edge_bound tcp_chain $PORT_BOUND edge-bound edge-01 "$AUTH/edge-01.pass" edge-01
edge_conf edge_cross tcp_chain $PORT_BOUND edge-cross edge-02 "$AUTH/edge-02.pass" edge-01
info "configurations in $(short "$CONF")/"

section "Startup"
start_daemon relay relay.toml
RELAY_PID=${PIDS[-1]}
for p in $PORTS; do
	wait_port "$p" || abort "relay port $p is not listening" relay
done
for e in edge_tcp edge_http edge_wrongpw edge_unknown edge_noauth edge_bound edge_cross; do
	start_daemon "$e" "$e.toml"
done
daemons_up
write_env LW="$BIN" CA="$PKI/ca.crt" PW="$AUTH/viewer-01.pass" USERS="$USERS" RELAY="$RELAY_PID"

guide "logwisp SCRAM test" <<EOF
Ports:
  $PORT_TCP_CHAIN  relay tcp_chain ingest, scram, node_binding = force
  $PORT_HTTP_CHAIN  relay http_chain ingest, scram
  $PORT_TCP_SINK  tcp sink, scram
  $PORT_HTTP_SINK  http sink, scram
  $PORT_BOUND  relay tcp_chain ingest, client_auth + scram, certificate CN = user
Edges: edge_tcp and edge_http log in as edge-01 and deliver; edge_wrongpw,
edge_unknown and edge_noauth are refused on $PORT_TCP_CHAIN. On $PORT_BOUND edge_bound
(edge-01 certificate and user) delivers, edge_cross (user edge-02) is refused.
Shell setup (LW, CA, PW: viewer-01's password file, USERS, RELAY: its pid):
> . $(short "$RUN")/env
Read the tcp sink as viewer-01:
> \$LW auth stream -addr 127.0.0.1:$PORT_TCP_SINK -user viewer-01 -password-file \$PW -ca-file \$CA
Read the http sink (bearer keeps the token off argv):
> token=\$(\$LW auth token -url https://127.0.0.1:$PORT_HTTP_SINK -user viewer-01 -password-file \$PW -ca-file \$CA)
> curl -N --cacert \$CA -H @<(bearer) https://127.0.0.1:$PORT_HTTP_SINK/stream
Revoke viewer-01:
> \$LW auth remove-user -credentials \$USERS -user viewer-01 && kill -HUP \$RELAY
Ingested entries (node label forced to the username): $(short "$OUT")/
Passwords: $(short "$AUTH")/   Logs: $(short "$LOG")/
EOF
manual_hold

relay_log="$LOG/relay.out"

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

section "Scenario 1: chained instances over SCRAM"

# 1. An edge with the right password delivers on both transports
wait_until 20 has_entry tcp_chain 'edge-01/'
tcp_file="$(ingested tcp_chain)"
n=$(grep -c 'edge-01/' <<<"$tcp_file")
check "tcp_chain: edge-01 entries reached the file sink ($n lines)" $((n >= 1))

wait_until 20 has_entry http_chain 'edge-01/'
http_file="$(ingested http_chain)"
n=$(grep -c 'edge-01/' <<<"$http_file")
check "http_chain: edge-01 entries reached the file sink ($n lines)" $((n >= 1))

# 2. node_binding = "force" replaced the label the sender configured
n=$(grep -c 'edge-tcp/' <<<"$tcp_file")
check "node binding: sender's own label \"edge-tcp\" was not honored ($n lines)" $((n == 0))
n=$(grep -c 'edge-http/' <<<"$http_file")
check "node binding: sender's own label \"edge-http\" was not honored ($n lines)" $((n == 0))

# 3. Wrong password, unknown user and no credentials are all refused
wait_until 20 logged edge_wrongpw 'Chain connect refused'
n=$(count edge_wrongpw 'Chain connect refused')
check "wrong password: edge-02 with a bad password was refused ($n refusals)" $((n >= 1))

wait_until 20 logged edge_unknown 'Chain connect refused'
n=$(count edge_unknown 'Chain connect refused')
check "unknown user: edge-99 was refused ($n refusals)" $((n >= 1))

wait_until 20 logged relay 'peer offered no credentials'
n=$(count relay 'peer offered no credentials')
check "no auth: relay refused an edge that offered no credentials ($n refusals)" $((n >= 1))

wait_until 20 logged edge_noauth 'Chain link refused'
n=$(count edge_noauth 'Chain link refused')
check "no auth: the edge read the refusal instead of writing into a closed link ($n)" $((n >= 1))

failed_login='Connection rejected by auth policy.*instance_id in_tcp .*invalid credentials'
wait_until 20 logged relay "$failed_login" 2
n=$(count relay "$failed_login")
check "relay logged the failed logins on :$PORT_TCP_CHAIN ($n rejections)" $((n >= 2))

tcp_file="$(ingested tcp_chain)"
n=$(grep -vc 'edge-01/' <<<"$tcp_file")
check "refused edges: nothing but edge-01 entries was ingested ($n foreign lines)" $((n == 0))

# 4. Certificate bound to the user: edge-01's certificate admits only edge-01
wait_until 20 has_entry bound 'edge-01/'
n=$(ingested bound | grep -c 'edge-01/')
check "certificate binding: edge-01 certificate + user edge-01 delivered ($n lines)" $((n >= 1))

wait_until 20 logged edge_cross 'Chain connect refused'
n=$(count edge_cross 'Chain connect refused')
check "certificate binding: edge-01 certificate + user edge-02 was refused ($n refusals)" $((n >= 1))
wait_until 20 logged relay 'does not match user \\"edge-02\\"'
n=$(count relay 'does not match user \\"edge-02\\"')
check "certificate binding: relay logged the certificate/user mismatch ($n)" $((n >= 1))
n=$(ingested bound | grep -vc 'edge-01/')
check "certificate binding: the cross-bound edge delivered nothing ($n foreign lines)" $((n == 0))

section "Scenario 2: viewers on SCRAM-gated sinks"

# 5. TCP sink: a logged-in viewer keeps streaming past the 10 s exchange
# deadline; a TLS client that sends no hello gets nothing and is dropped at it
info "streaming as viewer-01 beside a silent TLS client, 13 s"
"$BIN" auth stream -addr "127.0.0.1:$PORT_TCP_SINK" -user viewer-01 \
	-password-file "$AUTH/viewer-01.pass" -ca-file "$PKI/ca.crt" \
	>"$RUN/stream.out" 2>"$LOG/stream.err" &
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
check "tcp sink: viewer-01 streamed entries through lw auth stream ($n1 lines at 11 s)" $((n1 >= 1))
check "tcp sink: stream still live after the exchange deadline ($n1 -> $n2 lines, 11 s -> 13 s)" $((n2 > n1))
n=$(wc -c <"$RUN/raw.out")
check "tcp sink: a TLS client with no hello received nothing ($n bytes)" $((n == 0))
n=$(grep 'component tcp_sink' "$relay_log" | grep -c 'read hello')
check "tcp sink: relay dropped the silent client at the exchange deadline ($n)" $((n >= 1))

# 6. HTTP sink: a bearer token from lw auth token, carried by curl
token="$(token_for viewer-01)"
check "http sink: lw auth token issued a token for viewer-01" $(is_set "$token")

code="$(http_get /status "$token")"
check "http sink: /status served with the token (HTTP $code)" $(is "$code" 200)

sse="$(timeout 4 curl -sN --noproxy '*' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") \
	"https://127.0.0.1:$PORT_HTTP_SINK/stream" 2>/dev/null || true)"
n=$(grep -c '^data:.*edge-01/' <<<"$sse")
check "http sink: /stream delivered SSE events with the token ($n events)" $((n >= 1))

code="$(http_get /status)"
check "http sink: /status refused without a token (HTTP $code)" $(is "$code" 401)
code="$(http_get /stream not.a.token)"
check "http sink: /stream refused with a garbage token (HTTP $code)" $(is "$code" 401)

# 7. Revocation: remove-user + SIGHUP kills the token and the login
reloads=$(count relay 'Configuration hot reload completed successfully')
reloaded() { (($(count relay 'Configuration hot reload completed successfully') > reloads)); }
"$BIN" auth remove-user -credentials "$USERS" -user viewer-01 2>>"$LOG/auth-cli.out"
rc=$?
check "revocation: lw auth remove-user removed viewer-01 (exit $rc)" $((rc == 0))
kill -HUP "$RELAY_PID"
wait_until 20 reloaded && wait_port "$PORT_HTTP_SINK"
rc=$?
check "revocation: relay reloaded on SIGHUP" $((rc == 0))

code="$(http_get /status "$token")"
check "revocation: the old token is refused after the reload (HTTP $code)" $(is "$code" 401)
token_for viewer-01 >/dev/null
rc=$?
check "revocation: lw auth token for viewer-01 now fails (exit $rc)" $((rc == 1))

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
	$([[ $code == 429 ]] && ((${#codes[@]} <= 6)) && echo 1 || echo 0)

summary
