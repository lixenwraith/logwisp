#!/usr/bin/env bash
# logwisp preset test: colors, presets, --dump, lw tls, listeners that make
# their certificate (self-signed and pinned, or issued), the serve preset's
# browser viewer, and the http and tcp sinks writing a finite input whole.
# One-shot: both modes run the checks.
# Ports: 15890-15896 on 127.0.0.1.
# Requires: bash 5+, coreutils, curl, openssl. Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run/preset
e2e_init "$@"

section "Setup"
need curl openssl
ports_free 15890 15891 15892 15893 15894 15895 15896
rm -rf "$RUN"
mkdir -p "$RUN/out" "$LOG"
cd "$RUN" || abort "no run directory"
# no configuration file or LOGWISP_ variable applies
for v in $(compgen -e LOGWISP_); do unset "$v"; done
export HOME=$RUN
lw() { "$BIN" "$@"; }
seq 1 300 | sed 's/^/edge line /' >"$RUN/edge.log"
info "runs lw in $(short "$RUN") with no configuration file"

section "Color"
red=$'\e[0;1;31m'
check "--color paints the level name" "$(is "$(printf 'a ERROR b\n' | lw --color)" "a ${red}ERROR"$'\e[0m b')"
check "--color never, and auto on a pipe, leave it plain" \
	"$(is "$(printf 'a ERROR b\n' | lw --color never)$(printf 'a ERROR b\n' | lw)" "a ERROR ba ERROR b")"
check "LOGWISP_COLOR=always, a sink's own color=never wins" \
	"$(is "$(printf 'x WARN\n' | LOGWISP_COLOR=always lw --sink console,color=never)" "x WARN")"

section "Presets"
seq 1 5000 >"$RUN/seq.txt"
lw --preset pipe <"$RUN/seq.txt" >"$RUN/pipe.out"
check "--preset pipe copies stdin line for line" "$(cmp -s "$RUN/seq.txt" "$RUN/pipe.out" && echo 1 || echo 0)"
out=$(timeout 3 "$BIN" --preset "tail,path=$RUN/edge.log,from=start" </dev/null 2>/dev/null | head -2 | tr '\n' '|')
check "--preset tail follows a file" "$(is "$out" "edge line 1|edge line 2|")"
lw --preset "serve,path=$RUN/edge.log,listen=127.0.0.1:15890,tls=self,hosts=logs.example" --color --dump >"$RUN/dump.toml"
lw -c "$RUN/dump.toml" --dump >"$RUN/dump2.toml"
check "--dump prints a file that reads back to the same dump" "$(cmp -s "$RUN/dump.toml" "$RUN/dump2.toml" && echo 1 || echo 0)"
check "lw --check builds the dumped preset" "$(lw --check -c "$RUN/dump.toml" 2>"$LOG/check.err" | grep -q 'configuration ok' && echo 1 || echo 0)"
lw preset edge -to 127.0.0.1:1 >/dev/null 2>"$LOG/edge-noauth.err"
rc=$?
check "an edge without credentials is a usage error ($rc)" "$( ((rc == 2)) && grep -q 'never sends unauthenticated' "$LOG/edge-noauth.err" && echo 1 || echo 0)"

section "Certificates"
lw tls ca -dir "$RUN/pki" 2>"$LOG/tls.out" &&
	lw tls cert -ca-dir "$RUN/pki" -name logs.example -server -host 127.0.0.1,logs.example 2>>"$LOG/tls.out"
check "lw tls ca and cert issue a chain openssl verifies" \
	"$(openssl verify -CAfile "$RUN/pki/ca.crt" "$RUN/pki/logs.example.crt" 2>/dev/null | grep -q ': OK$' && echo 1 || echo 0)"
check "keys are private" "$(is "$(stat -c %a "$RUN/pki/ca.key" "$RUN/pki/logs.example.key" | tr '\n' ' ')" "600 600 ")"
lw tls ca -dir "$RUN/pki" 2>/dev/null
check "an existing CA is never replaced" "$(( $? == 1 ))"

AUTH=$RUN
add_users "$RUN/users.toml" edge-01
# pin DAEMON: the pin_sha256 a self-signed listener logged
pin() { wait_until 5 logged "$1" pin_sha256 && grep -o 'pin_sha256 "sha256//[^"]*"' "$LOG/$1.out" | head -1 | cut -d'"' -f2; }
received() { cat "$RUN/out/$1"/aggregate*.log 2>/dev/null | grep -c 'edge line'; }

spawn agg-self "$BIN" --preset "aggregator,listen=127.0.0.1:15893,users=$RUN/users.toml,out=$RUN/out/self"
wait_port 15893 || abort "the self-signed aggregator did not listen" agg-self
PIN=$(pin agg-self)
check "a self-signed aggregator logs its pin" "$(is_set "$PIN")"
spawn edge-pin "$BIN" --preset "edge,path=$RUN/edge.log,from=start,to=127.0.0.1:15893,pin=$PIN,user=edge-01,password_file=$RUN/edge-01.pass"
spawn edge-wrong "$BIN" --preset "edge,path=$RUN/edge.log,from=start,to=127.0.0.1:15893,pin=sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,user=edge-01,password_file=$RUN/edge-01.pass"
wait_until 10 eval '(( $(received self) >= 300 ))'
check "an edge pinning it delivers every line over SCRAM ($(received self))" "$(( $(received self) == 300 ))"
wait_until 10 logged edge-wrong 'matches no tls.pin_sha256'
check "an edge with another pin is refused before it logs in" "$(logged edge-wrong 'matches no tls.pin_sha256' && echo 1 || echo 0)"

spawn agg-issuer "$BIN" --preset "aggregator,listen=127.0.0.1:15894,transport=http,tls=issuer,issuer_cert=$RUN/pki/ca.crt,issuer_key=$RUN/pki/ca.key,users=$RUN/users.toml,out=$RUN/out/issuer"
wait_port 15894 || abort "the issuing aggregator did not listen" agg-issuer
spawn edge-ca "$BIN" --preset "edge,path=$RUN/edge.log,from=start,to=127.0.0.1:15894,transport=http,ca=$RUN/pki/ca.crt,user=edge-01,password_file=$RUN/edge-01.pass"
wait_until 10 eval '(( $(received issuer) >= 300 ))'
check "an aggregator signing its own certificate is verified by the CA ($(received issuer))" "$(( $(received issuer) == 300 ))"

spawn serve "$BIN" --preset "serve,path=$RUN/edge.log,listen=127.0.0.1:15895,tls=self"
wait_port 15895 || abort "the serve preset did not listen" serve
SERVE_PIN=$(pin serve)
check "curl --pinnedpubkey reads a self-signed stream's status" \
	"$(curl -sk --pinnedpubkey "$SERVE_PIN" https://127.0.0.1:15895/status | grep -q '"tls":true' && echo 1 || echo 0)"
curl -sk --pinnedpubkey "$PIN" -o /dev/null https://127.0.0.1:15895/status
check "curl with another listener's pin is refused" "$(( $? != 0 ))"
check "a browser at the self-signed root lands on the viewer" \
	"$(curl -sLk --pinnedpubkey "$SERVE_PIN" https://127.0.0.1:15895/ | grep -q 'name="logwisp-login" content="none"' && echo 1 || echo 0)"

section "Viewer"
spawn serve-plain "$BIN" --preset "serve,path=$RUN/edge.log,listen=127.0.0.1:15896"
wait_port 15896 || abort "the plain serve preset did not listen" serve-plain
root=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1:15896/)
check "GET / sends a browser to the viewer, which needs no login over plain http ($root)" \
	"$( [[ $root == '303 http://127.0.0.1:15896/auth/view' ]] && curl -sL http://127.0.0.1:15896/ | grep -q 'name="logwisp-login" content="none"' && echo 1 || echo 0)"

section "Flush at exit"
# feed SECONDS PORT: the lines, once a client had time to connect
feed() { wait_port "$2"; sleep "$1"; seq 1 20000 | sed 's/^/flush /'; }
queues='buffer_size=20000,client_buffer_size=20000'
feed 1 15891 | lw --sink "tcp,host=127.0.0.1,port=15891,$queues" 2>"$LOG/flush-tcp.err" &
fpid=$!
wait_port 15891
n=$(tcp_read 15891 15 | grep -c '^flush ')
wait "$fpid"
check "a tcp client gets all 20000 lines of a finite input ($n)" "$((n == 20000))"
feed 1 15892 | lw --sink "http,host=127.0.0.1,port=15892,$queues" 2>"$LOG/flush-http.err" &
fpid=$!
wait_port 15892
curl -sN --max-time 15 http://127.0.0.1:15892/stream >"$RUN/flush-http.out"
wait "$fpid"
n=$(grep -c '^data: flush ' "$RUN/flush-http.out")
check "an http stream gets all 20000 lines, then the disconnect event ($n)" \
	"$( ((n == 20000)) && tail -3 "$RUN/flush-http.out" | grep -q '^event: disconnect' && echo 1 || echo 0)"

summary
