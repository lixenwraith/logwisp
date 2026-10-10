#!/usr/bin/env bash
# logwisp preset test: colors, presets, --dump, lw tls, listeners that make
# their certificate (self-signed and pinned, or issued), the serve preset's
# browser viewer, the network sinks delivering a finite input whole, and a
# temporary pipe: one SCRAM user whose password is on no disk.
# One-shot: both modes run the checks.
# Ports: 15890-15898 on 127.0.0.1.
# Requires: bash 5+, coreutils, curl, openssl; script(1) for the terminal
# checks. Linux dev host only.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run/preset
e2e_init "$@"

section "Setup"
need curl openssl
ports_free 15890 15891 15892 15893 15894 15895 15896 15897 15898
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
	"$(is "$(printf 'x WARN\n' | LOGWISP_COLOR=always lw --sink console:color=never)" "x WARN")"

section "Presets"
seq 1 5000 >"$RUN/seq.txt"
lw --preset pipe <"$RUN/seq.txt" >"$RUN/pipe.out"
check "--preset pipe copies stdin line for line" "$(cmp -s "$RUN/seq.txt" "$RUN/pipe.out" && echo 1 || echo 0)"
out=$(timeout 3 "$BIN" --preset "tail:path=$RUN/edge.log,from=start" </dev/null 2>/dev/null | head -2 | tr '\n' '|')
check "--preset tail follows a file" "$(is "$out" "edge line 1|edge line 2|")"
lw --preset "serve:path=$RUN/edge.log,listen=127.0.0.1:15890,tls=self,hosts=logs.example" --color --dump >"$RUN/dump.toml"
lw -c "$RUN/dump.toml" --dump >"$RUN/dump2.toml"
check "--dump prints a file that reads back to the same dump" "$(cmp -s "$RUN/dump.toml" "$RUN/dump2.toml" && echo 1 || echo 0)"
check "lw --check builds the dumped preset" "$(lw --check -c "$RUN/dump.toml" 2>"$LOG/check.err" | grep -q 'configuration ok' && echo 1 || echo 0)"
lw preset edge -to 127.0.0.1:1 >/dev/null 2>"$LOG/edge-noauth.err"
rc=$?
check "an edge without credentials is a usage error ($rc)" "$( ((rc == 2)) && grep -q 'never sends unauthenticated' "$LOG/edge-noauth.err" && echo 1 || echo 0)"
lw tail </dev/null 2>"$LOG/stray.err"
rc=$?
check "a word no option takes is a usage error ($rc)" "$( ((rc == 2)) && grep -q 'unexpected argument "tail"' "$LOG/stray.err" && echo 1 || echo 0)"

section "Certificates"
lw tls ca -dir "$RUN/pki" 2>"$LOG/tls.out" &&
	lw tls cert -ca-dir "$RUN/pki" -name logs.example -server -hosts 127.0.0.1,logs.example 2>>"$LOG/tls.out"
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

spawn agg-self "$BIN" --preset "aggregator:listen=127.0.0.1:15893,users=$RUN/users.toml,out=$RUN/out/self"
wait_port 15893 || abort "the self-signed aggregator did not listen" agg-self
PIN=$(pin agg-self)
check "a self-signed aggregator logs its pin" "$(is_set "$PIN")"
spawn edge-pin "$BIN" --preset "edge:path=$RUN/edge.log,from=start,to=127.0.0.1:15893,pin=$PIN,user=edge-01,password_file=$RUN/edge-01.pass"
spawn edge-wrong "$BIN" --preset "edge:path=$RUN/edge.log,from=start,to=127.0.0.1:15893,pin=sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,user=edge-01,password_file=$RUN/edge-01.pass"
wait_until 10 eval '(( $(received self) >= 300 ))'
check "an edge pinning it delivers every line over SCRAM ($(received self))" "$(( $(received self) == 300 ))"
wait_until 10 logged edge-wrong 'matches no tls.pin_sha256'
check "an edge with another pin is refused before it logs in" "$(logged edge-wrong 'matches no tls.pin_sha256' && echo 1 || echo 0)"

spawn agg-issuer "$BIN" --preset "aggregator:listen=127.0.0.1:15894,transport=http,tls=issuer,issuer_cert=$RUN/pki/ca.crt,issuer_key=$RUN/pki/ca.key,users=$RUN/users.toml,out=$RUN/out/issuer"
wait_port 15894 || abort "the issuing aggregator did not listen" agg-issuer
spawn edge-ca "$BIN" --preset "edge:path=$RUN/edge.log,from=start,to=127.0.0.1:15894,transport=http,ca=$RUN/pki/ca.crt,user=edge-01,password_file=$RUN/edge-01.pass"
wait_until 10 eval '(( $(received issuer) >= 300 ))'
check "an aggregator signing its own certificate is verified by the CA ($(received issuer))" "$(( $(received issuer) == 300 ))"

spawn serve "$BIN" --preset "serve:path=$RUN/edge.log,listen=127.0.0.1:15895,tls=self"
wait_port 15895 || abort "the serve preset did not listen" serve
SERVE_PIN=$(pin serve)
check "curl --pinnedpubkey reads a self-signed stream's status" \
	"$(curl -sk --pinnedpubkey "$SERVE_PIN" https://127.0.0.1:15895/status | grep -q '"tls":true' && echo 1 || echo 0)"
curl -sk --pinnedpubkey "$PIN" -o /dev/null https://127.0.0.1:15895/status
check "curl with another listener's pin is refused" "$(( $? != 0 ))"
check "a browser at the self-signed root lands on the viewer" \
	"$(curl -sLk --pinnedpubkey "$SERVE_PIN" https://127.0.0.1:15895/ | grep -q 'name="logwisp-login" content="none"' && echo 1 || echo 0)"

section "Viewer"
spawn serve-plain "$BIN" --preset "serve:path=$RUN/edge.log,listen=127.0.0.1:15896"
wait_port 15896 || abort "the plain serve preset did not listen" serve-plain
root=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1:15896/)
check "GET / sends a browser to the viewer, which needs no login over plain http ($root)" \
	"$( [[ $root == '303 http://127.0.0.1:15896/auth/view' ]] && curl -sL http://127.0.0.1:15896/ | grep -q 'name="logwisp-login" content="none"' && echo 1 || echo 0)"

section "Flush at exit"
# feed SECONDS PORT: the lines, once a client had time to connect
feed() { wait_port "$2"; sleep "$1"; seq 1 20000 | sed 's/^/flush /'; }
queues='buffer_size=20000,client_buffer_size=20000'
feed 1 15891 | lw --sink "tcp:host=127.0.0.1,port=15891,$queues" 2>"$LOG/flush-tcp.err" &
fpid=$!
wait_port 15891
n=$(tcp_read 15891 15 | grep -c '^flush ')
wait "$fpid"
check "a tcp client gets all 20000 lines of a finite input ($n)" "$((n == 20000))"
feed 1 15892 | lw --sink "http:host=127.0.0.1,port=15892,$queues" 2>"$LOG/flush-http.err" &
fpid=$!
wait_port 15892
curl -sN --max-time 15 http://127.0.0.1:15892/stream >"$RUN/flush-http.out"
wait "$fpid"
n=$(grep -c '^data: flush ' "$RUN/flush-http.out")
check "an http stream gets all 20000 lines, then the disconnect event ($n)" \
	"$( ((n == 20000)) && tail -3 "$RUN/flush-http.out" | grep -q '^event: disconnect' && echo 1 || echo 0)"
# 1000 lines: the chain sink's queue, which holds them until the link is up
flushed() { cat "$RUN/out/$1"/aggregate*.log 2>/dev/null | grep -c '"flush '; }
seq 1 1000 | sed 's/^/flush /' | lw --preset "edge:to=127.0.0.1:15893,pin=$PIN,user=edge-01,password_file=$RUN/edge-01.pass" 2>"$LOG/flush-tcp-chain.err"
wait_until 5 eval '(( $(flushed self) >= 1000 ))'
check "a tcp_chain edge delivers all 1000 lines before it exits ($(flushed self))" "$(( $(flushed self) == 1000 ))"
seq 1 1000 | sed 's/^/flush /' | lw --preset "edge:to=127.0.0.1:15894,transport=http,ca=$RUN/pki/ca.crt,user=edge-01,password_file=$RUN/edge-01.pass" 2>"$LOG/flush-http-chain.err"
wait_until 5 eval '(( $(flushed issuer) >= 1000 ))'
check "an http_chain edge delivers all 1000 lines before it exits ($(flushed issuer))" "$(( $(flushed issuer) == 1000 ))"

section "Temporary pipe"
# One user on both ends, its password through a descriptor; printf is a
# builtin, so the password is in no argv either
PW=$(head -c 18 /dev/urandom | base64 | tr '+/' '-_')
pw() { printf '%s\n' "$1"; }
piped() { cat "$RUN/out/pipe"/aggregate*.log 2>/dev/null | grep -c '^pipe line'; }
piped_line() { cat "$RUN/out/pipe"/aggregate*.log 2>/dev/null | grep -qx "pipe line $1"; }
seq 1 100 | sed 's/^/pipe line /' >"$RUN/pipe.log"
spawn agg-pipe "$BIN" --logging.level=info --preset "aggregator:listen=127.0.0.1:15897,user=pipe,password_file=/dev/fd/3,format=raw,out=$RUN/out/pipe" 3< <(pw "$PW")
AGG_PIPE=${PIDS[-1]}
wait_port 15897 || abort "the pipe aggregator did not listen" agg-pipe
PIPE_PIN=$(pin agg-pipe)
spawn edge-pipe "$BIN" --logging.level=info --preset "edge:path=$RUN/pipe.log,from=start,to=127.0.0.1:15897,pin=$PIPE_PIN,user=pipe,password_file=/dev/fd/3" 3< <(pw "$PW")
EDGE_PIPE=${PIDS[-1]}
spawn edge-pipe-wrong "$BIN" --preset "edge:path=$RUN/pipe.log,from=start,to=127.0.0.1:15897,pin=$PIPE_PIN,user=pipe,password_file=/dev/fd/3" 3< <(pw another-password)
wait_until 10 eval '(( $(piped) >= 100 ))'
check "an aggregator and an edge given one password on /dev/fd/3 deliver every line ($(piped))" "$(( $(piped) == 100 ))"
wait_until 10 logged edge-pipe-wrong 'authentication failed'
check "an edge with another password is refused" "$(logged edge-pipe-wrong 'authentication failed' && echo 1 || echo 0)"
check "the descriptor, read and closed, draws no permission warning" "$(logged agg-pipe 'readable by all users' && echo 0 || echo 1)"
reloaded() { logged agg-pipe 'hot reload completed' && logged edge-pipe 'hot reload completed'; }
kill -HUP "$AGG_PIPE" "$EDGE_PIPE"
wait_until 10 reloaded
check "SIGHUP reloads both, the password kept from the first read" "$(reloaded && echo 1 || echo 0)"
seq 101 150 | sed 's/^/pipe line /' >>"$RUN/pipe.log"
wait_until 10 piped_line 150
check "a second batch is delivered after the reload" "$(piped_line 150 && echo 1 || echo 0)"
leaks=$(grep -rlF -- "$PW" "$RUN"; for p in "$AGG_PIPE" "$EDGE_PIPE"; do tr '\0' '\n' <"/proc/$p/cmdline"; tr '\0' '\n' <"/proc/$p/environ"; done | grep -F -- "$PW")
check "the password is in no file of the run directory, no argv and no environment" "$(is "$leaks" "")"

if command -v script >/dev/null && command -v setsid >/dev/null; then
	setsid -w "$BIN" --check --preset aggregator:listen=127.0.0.1:15898,user=gen </dev/null >"$LOG/no-tty.out" 2>&1
	check "with no terminal to ask on, a listener's user fails closed" "$(grep -q 'no terminal to ask on' "$LOG/no-tty.out" && echo 1 || echo 0)"
	# script(1) is lw's terminal, what lw shows there lands in agg-gen-tty.out;
	# not spawn, whose background command would read /dev/null, not the Enter
	script -qefc "$(printf '%q ' "$BIN" --preset "aggregator:listen=127.0.0.1:15898,transport=http,user=gen,format=raw,out=$RUN/out/gen")2>$(printf %q "$LOG/agg-gen.out")" /dev/null \
		< <(printf '\n') >"$LOG/agg-gen-tty.out" 2>&1 &
	PIDS+=($!) DAEMONS+=(agg-gen-tty)
	wait_until 10 logged agg-gen-tty 'generated password'
	GEN=$(grep -o 'shown once: [A-Z2-7]*' "$LOG/agg-gen-tty.out" | cut -d' ' -f3)
	check "Enter alone at a listener's prompt shows a generated password on its terminal" "$(is_set "$GEN")"
	wait_port 15898 || abort "the generating aggregator did not listen" agg-gen-tty
	GEN_PIN=$(pin agg-gen)
	check "and not in lw's log or stderr" "$([[ -n $GEN ]] && ! grep -qF -- "$GEN" "$LOG/agg-gen.out" && echo 1 || echo 0)"
	generated() { cat "$RUN/out/gen"/aggregate*.log 2>/dev/null | grep -c '^edge line'; }
	spawn edge-gen "$BIN" --preset "edge:path=$RUN/edge.log,from=start,to=127.0.0.1:15898,transport=http,pin=$GEN_PIN,user=gen,password_file=/dev/fd/3" 3< <(pw "$GEN")
	wait_until 10 eval '(( $(generated) >= 300 ))'
	check "an edge given the generated password delivers every line ($(generated))" "$(( $(generated) == 300 ))"
	token=$(pw "$GEN" | script -qefc "$(printf '%q ' "$BIN" auth token --url https://127.0.0.1:15898 -u gen --pin-sha256 "$GEN_PIN")" /dev/null | tr -d '\r' | tail -1)
	check "lw auth token asks on the terminal without --password-file" "$([[ $token =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] && echo 1 || echo 0)"
else
	skip "the terminal checks: no script(1) or setsid(1)"
fi

summary
