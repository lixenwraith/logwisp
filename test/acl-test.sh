#!/usr/bin/env bash
# logwisp acl test: each listener kind admits or refuses peers by address
# before TLS, counts and warns of refusals, rejects rules it can never apply,
# and still hands a finite input whole to the clients it admits. One-shot.
# Ports: 15881-15889 on 127.0.0.1. Requires: bash 5+, curl, nc; Linux.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run/acl
AUTH=$RUN
e2e_init "$@"

section "Setup"
need curl nc
ports_free 15881 15882 15884 15885 15889
rm -rf "$RUN"
mkdir -p "$RUN/out" "$LOG"
cd "$RUN" || abort "no run directory"
for v in $(compgen -e LOGWISP_); do unset "$v"; done
export HOME=$RUN
lw() { "$BIN" "$@"; }
get() { curl -s --noproxy '*' --max-time 3 "$@"; } # curl ARGS...: never through a proxy
# exit 45: curl could not bind the address; 7, it bound and found 15889 closed
get --interface 127.0.0.2 http://127.0.0.1:15889/
(($? == 45)) && skip_all "this host cannot send from 127.0.0.2"
seq 1 300 | sed 's/^/edge line /' >"$RUN/edge.log"
add_users "$RUN/users.toml" edge-01

section "Rules"
# rejects SINK PATTERN: lw --check fails on SINK with PATTERN in its error
rejects() { ! lw --check --source null --sink "$1" >/dev/null 2>"$LOG/check.err" && grep -q -- "$2" "$LOG/check.err" && echo 1 || echo 0; }
# warns SINK PATTERN: lw --check builds SINK and WARNs PATTERN
warns() { lw --check --source null --sink "$1" 2>&1 >/dev/null | grep ' WARN ' | grep -q -- "$2" && echo 1 || echo 0; }
check "an IPv4 entry on an IPv6 listener is refused" "$(rejects 'tcp,host=::1,port=15881,acl.allow=10.0.0.0/8' "not of the listener's family")"
check "an acl on a dialer is refused" "$(rejects 'tcp_chain,host=127.0.0.1,port=15881,acl.deny=10.0.0.1' 'unknown key "acl"')"
check "a CIDR with host bits warns, naming the network it matches" "$(warns 'tcp,host=127.0.0.1,port=15881,acl.allow=10.0.0.1/8' 'network 10.0.0.0/8')"
check "a deny list alone on a wildcard listener warns" "$(warns 'tcp,port=15881,acl.deny=10.0.0.1' 'admits all that acl.deny does not list')"
check "an allow entry of a whole family warns" "$(warns 'tcp,port=15881,acl.allow=0.0.0.0/0' 'admits every address of its family')"

section "HTTP sink"
spawn serve "$BIN" --preset "serve,path=$RUN/edge.log,listen=127.0.0.1:15881,allow=127.0.0.0/8,deny=127.0.0.2"
wait_port 15881 || abort "the serve preset did not listen" serve
check "a client the allow list names reads the status" "$(get http://127.0.0.1:15881/status | grep -q '"acl":"allow=1 deny=1"' && echo 1 || echo 0)"
get --interface 127.0.0.2 -o /dev/null http://127.0.0.1:15881/status
rc=$?
check "a denied client is closed before a byte of HTTP (curl exit $rc)" "$( ((rc == 52 || rc == 56)) && echo 1 || echo 0)"
get --interface 127.0.0.2 http://127.0.0.1:15881/status
get --interface 127.0.0.2 http://127.0.0.1:15881/status
check "the status counts every refusal" "$(get http://127.0.0.1:15881/status | grep -q '"acl_denied":3' && echo 1 || echo 0)"
check "and the log warns of them once ($(count serve 'refused by acl'))" \
	"$( [[ $(count serve 'refused by acl') == 1 ]] && logged serve 'remote_addr 127.0.0.2:' && echo 1 || echo 0)"

section "TCP sink"
# the lines of a finite input, once the clients had time to connect
seq 1 20000 | sed 's/^/flush /' >"$RUN/flush.in"
{ wait_port 15882; sleep 1; cat "$RUN/flush.in"; } |
	lw --sink "tcp,host=127.0.0.1,port=15882,acl.allow=127.0.0.1,buffer_size=20000,client_buffer_size=20000" 2>"$LOG/tcp.err" &
fpid=$!
wait_port 15882
tcp_read 15882 15 >"$RUN/flush.out" &
rpid=$!
denied=$(timeout 3 nc -s 127.0.0.2 127.0.0.1 15882 </dev/null | wc -c)
wait "$rpid" "$fpid"
n=$(grep -c '^flush ' "$RUN/flush.out")
check "a client the acl admits gets all 20000 lines of a finite input ($n)" "$((n == 20000))"
check "one it denies gets nothing ($denied bytes) and is logged" \
	"$( ((denied == 0)) && grep -q 'refused by acl.* remote_addr 127.0.0.2:' "$LOG/tcp.err" && echo 1 || echo 0)"

section "Chain sources"
# pin DAEMON: the pin_sha256 a self-signed listener logged
pin() { wait_until 5 logged "$1" pin_sha256 && grep -o 'pin_sha256 "sha256//[^"]*"' "$LOG/$1.out" | head -1 | cut -d'"' -f2; }
received() { cat "$RUN/out/$1"/aggregate*.log 2>/dev/null | grep -c 'edge line'; }
edge() { spawn "$1" "$BIN" --preset "edge,path=$RUN/edge.log,from=start,to=127.0.0.1:$2,transport=$3,pin=$4,user=edge-01,password_file=$RUN/edge-01.pass"; }
spawn agg-allow "$BIN" --preset "aggregator,listen=127.0.0.1:15884,allow=127.0.0.1,users=$RUN/users.toml,out=$RUN/out/allow"
spawn agg-deny "$BIN" --preset "aggregator,listen=127.0.0.1:15885,transport=http,deny=127.0.0.0/8,users=$RUN/users.toml,out=$RUN/out/deny"
wait_port 15884 && wait_port 15885 || abort "an aggregator did not listen" agg-allow
edge edge-allow 15884 tcp "$(pin agg-allow)"
edge edge-deny 15885 http "$(pin agg-deny)"
timeout 3 nc -s 127.0.0.2 127.0.0.1 15884 </dev/null
wait_until 10 eval '(( $(received allow) >= 300 ))'
check "a tcp_chain source admits an edge its allow list names ($(received allow)), and refuses 127.0.0.2" \
	"$( (($(received allow) == 300)) && logged agg-allow 'refused by acl.* remote_addr 127.0.0.2:' && echo 1 || echo 0)"
wait_until 10 logged agg-deny 'refused by acl'
check "an http_chain source refuses a denied edge, which delivers nothing ($(received deny))" \
	"$(logged agg-deny 'refused by acl' && (($(received deny) == 0)) && echo 1 || echo 0)"

summary
