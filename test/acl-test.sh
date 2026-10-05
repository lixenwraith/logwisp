#!/usr/bin/env bash
# logwisp acl test: each listener kind admits or refuses peers by address
# before TLS, or by the client a PROXY header or a proxy's X-Forwarded-For
# names (stub proxy, nginx if installed), counts and warns of refusals, and
# caps connections, requests and logins per client.
# One-shot. Ports: 15881-15889 on 127.0.0.1, the proxies' on 127.0.0.11-14.
# Requires: bash 5+, curl, nc, go; Linux.

set -u
. "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RUN=$E2E_DIR/run/acl
AUTH=$RUN
e2e_init "$@"

section "Setup"
need curl nc go
ports_free 15881 15882 15883 15884 15885 15886 15887 15888 15889
rm -rf "$RUN"
mkdir -p "$RUN/out" "$RUN/proxy" "$LOG"
cd "$RUN" || abort "no run directory"
# Each ROUTE is LISTEN,BACKEND,VERSION,CLIENT: a connection to LISTEN reaches
# BACKEND behind a PROXY header of VERSION naming CLIENT, with its own port
cat >"$RUN/proxy/main.go" <<'EOF'
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
)

func main() {
	for _, route := range os.Args[1:] {
		f := strings.Split(route, ",")
		ln, err := net.Listen("tcp4", f[0])
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					log.Fatal(err)
				}
				go relay(c, f[1], f[2], netip.MustParseAddr(f[3]))
			}
		}()
	}
	fmt.Println("ready")
	select {}
}

func relay(c net.Conn, backend, version string, client netip.Addr) {
	defer c.Close()
	b, err := net.Dial("tcp4", backend)
	if err != nil {
		return
	}
	defer b.Close()
	src := netip.AddrPortFrom(client, c.RemoteAddr().(*net.TCPAddr).AddrPort().Port())
	dst := b.RemoteAddr().(*net.TCPAddr).AddrPort()
	if version == "1" {
		fmt.Fprintf(b, "PROXY TCP4 %s %s %d %d\r\n", src.Addr(), dst.Addr(), src.Port(), dst.Port())
	} else {
		h := append([]byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c"), src.Addr().AsSlice()...)
		h = binary.BigEndian.AppendUint16(append(h, dst.Addr().AsSlice()...), src.Port())
		b.Write(binary.BigEndian.AppendUint16(h, dst.Port()))
	}
	go func() { io.Copy(b, c); b.(*net.TCPConn).CloseWrite() }()
	io.Copy(c, b)
}
EOF
if ! (cd "$RUN/proxy" && go build -o proxy main.go) >"$LOG/proxy-build.out" 2>&1; then
	tail -n 5 "$LOG/proxy-build.out" | sed 's/^/        /'
	abort "the stub proxy did not build"
fi
for v in $(compgen -e LOGWISP_); do unset "$v"; done
export HOME=$RUN
lw() { "$BIN" "$@"; }
get() { curl -s --noproxy '*' --max-time 3 "$@"; } # curl ARGS...: never through a proxy
# exit 45: curl could not bind the address; 7, it bound and found 15889 closed
get --interface 127.0.0.2 http://127.0.0.1:15889/
(($? == 45)) && skip_all "this host cannot send from 127.0.0.2"
seq 1 300 | sed 's/^/edge line /' >"$RUN/edge.log"
add_users "$RUN/users.toml" edge-01 viewer-01
echo wrong >"$RUN/wrong.pass"

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
check "a proxy_from entry reaching public addresses warns" \
	"$(warns 'tcp,host=127.0.0.1,port=15881,acl.proxy_protocol=optional,acl.proxy_from=203.0.113.0/24' 'proxy_from reaches public addresses')"
check "a request rate on a tcp listener is refused" \
	"$(rejects 'tcp,host=127.0.0.1,port=15881,acl.requests_per_second_per_client=5' 'applies only to HTTP listeners')"
check "a connection cap behind trusted_proxies, which would count the proxy, is refused" \
	"$(rejects "http,host=127.0.0.1,port=15881,auth.type=scram,auth.credentials_file=$RUN/users.toml,auth.trusted_proxies=127.0.0.1,acl.max_connections_per_client=2" 'behind trusted_proxies')"
check "optional proxy_protocol warns that a headerless client passes as the proxy" \
	"$(warns 'tcp,host=127.0.0.1,port=15881,acl.proxy_protocol=optional,acl.proxy_from=127.0.0.1' 'passes as the proxy')"

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

section "Behind an L7 proxy"
# proxy mode over plaintext loopback: curl is the proxy, its headers name the client
spawn web-proxied "$BIN" --source null --sink "http,host=127.0.0.1,port=15882,auth.type=scram,auth.credentials_file=$RUN/users.toml,auth.trusted_proxies=127.0.0.1,acl.deny=198.51.100.5,acl.deny=2001:db8::/32,acl.requests_per_second_per_client=1"
wait_port 15882 || abort "the proxy-mode http sink did not listen" web-proxied
# as CLIENT [PATH [CURL ARGS]]: the status of a request forwarded for CLIENT,
# GET /status by default; there 401 is past the acl, short of a login
as() { get -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" -H 'X-Forwarded-Proto: https' "${@:3}" "http://127.0.0.1:15882${2:-/status}"; }
codes="$(as 198.51.100.5) $(as 2001:db8::5)"
wait_until 5 logged web-proxied 'Request refused by acl.* remote_addr 198.51.100.5 .*address rules'
check "forwarded clients the acl denies, of either family, are refused per request, and logged once ($codes)" \
	"$( [[ $codes == '403 403' && $(count web-proxied 'refused by acl') == 1 ]] && echo 1 || echo 0)"
codes="$(as 198.51.100.7) $(as 198.51.100.7)"
check "a forwarded client past requests_per_second_per_client gets 429 ($codes)" "$(is "$codes" '401 429')"
code=$(as 198.51.100.8)
check "while another behind the same proxy is not ($code)" "$(is "$code" 401)"
hello=(-H 'Content-Type: application/json' -d '{"logwisp":1,"scram":{"username":"edge-01","client_nonce":"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"}}')
codes="$(as 198.51.100.9 /auth "${hello[@]}") $(as 198.51.100.9 /auth "${hello[@]}")"
check "the SCRAM exchange, which its throttling limits, is not counted in the rate ($codes)" "$(is "$codes" '200 200')"

section "Chain sources"
# pin DAEMON: the pin_sha256 a self-signed listener logged
pin() { wait_until 5 logged "$1" pin_sha256 && grep -o 'pin_sha256 "sha256//[^"]*"' "$LOG/$1.out" | head -1 | cut -d'"' -f2; }
received() { cat "$RUN/out/$1"/aggregate*.log 2>/dev/null | grep -c 'edge line'; }
edge() { spawn "$1" "$BIN" --preset "edge,path=$RUN/edge.log,from=start,to=$2,transport=$3,pin=$4,user=edge-01,password_file=$RUN/edge-01.pass"; }
spawn agg-allow "$BIN" --preset "aggregator,listen=127.0.0.1:15884,allow=127.0.0.1,users=$RUN/users.toml,out=$RUN/out/allow"
spawn agg-deny "$BIN" --preset "aggregator,listen=127.0.0.1:15885,transport=http,deny=127.0.0.0/8,users=$RUN/users.toml,out=$RUN/out/deny"
wait_port 15884 && wait_port 15885 || abort "an aggregator did not listen" agg-allow
edge edge-allow 127.0.0.1:15884 tcp "$(pin agg-allow)"
edge edge-deny 127.0.0.1:15885 http "$(pin agg-deny)"
timeout 3 nc -s 127.0.0.2 127.0.0.1 15884 </dev/null
wait_until 10 eval '(( $(received allow) >= 300 ))'
check "a tcp_chain source admits an edge its allow list names ($(received allow)), and refuses 127.0.0.2" \
	"$( (($(received allow) == 300)) && logged agg-allow 'refused by acl.* remote_addr 127.0.0.2:' && echo 1 || echo 0)"
wait_until 10 logged agg-deny 'refused by acl'
check "an http_chain source refuses a denied edge, which delivers nothing ($(received deny))" \
	"$(logged agg-deny 'refused by acl' && (($(received deny) == 0)) && echo 1 || echo 0)"

section "Behind a PROXY header"
# Every listener here takes headers from 127.0.0.1 only, where the proxies
# connect from; each is up before a proxy shares its port on another address
behind=acl.proxy_protocol=required,acl.proxy_from=127.0.0.1
scram="tls.enabled=true,tls.self_signed=true,auth.type=scram,auth.credentials_file=$RUN/users.toml"
spawn sink-behind "$BIN" --logging.level=info --source null --sink "http,host=127.0.0.1,port=15886,$scram,$behind,acl.deny=198.51.100.2"
spawn tcp-capped "$BIN" --source null --sink "tcp,host=127.0.0.1,port=15889,$behind,acl.max_connections_per_client=2"
for t in tcp http; do
	spawn "agg-$t-behind" "$BIN" --logging.level=info \
		--source "${t}_chain,host=127.0.0.1,port=$([[ $t == tcp ]] && echo 15888 || echo 15883),$scram,$behind" \
		--sink "file,directory=$RUN/out/$t-behind,name=aggregate"
done
# the tcp sink sends its input once the clients connected
{ wait_until 30 test -e "$RUN/feed"; seq 1 100 | sed 's/^/behind /'; } |
	lw --sink "tcp,host=127.0.0.1,port=15887,$behind,acl.deny=198.51.100.2,acl.deny=127.0.0.6" 2>"$LOG/tcp-behind.out" &
fpid=$!
for p in 15883 15886 15887 15888 15889; do wait_port $p || abort "a listener behind the proxy did not listen on $p" sink-behind; done
spawn proxy "$RUN/proxy/proxy" 127.0.0.11:15886,127.0.0.1:15886,1,198.51.100.1 \
	127.0.0.12:15886,127.0.0.1:15886,2,198.51.100.2 127.0.0.13:15886,127.0.0.1:15886,2,198.51.100.3 \
	127.0.0.11:15887,127.0.0.1:15887,2,198.51.100.1 127.0.0.12:15887,127.0.0.1:15887,1,198.51.100.2 \
	127.0.0.11:15888,127.0.0.1:15888,1,198.51.100.1 127.0.0.13:15883,127.0.0.1:15883,2,198.51.100.3 \
	127.0.0.11:15889,127.0.0.1:15889,1,198.51.100.1 127.0.0.12:15889,127.0.0.1:15889,2,198.51.100.2
wait_until 10 logged proxy ready || abort "the stub proxy did not start" proxy
NGINX=0
if command -v nginx >/dev/null; then
	mkdir -p "$RUN/nginx/logs"
	# a dynamic stream module loads by its absolute path; a built-in has none
	so=$(nginx -V 2>&1 | grep -o -- '--modules-path=[^ ]*' | cut -d= -f2)/ngx_stream_module.so
	modules=$([[ -f $so ]] && echo "load_module $so;")
	cat >"$RUN/nginx/nginx.conf" <<EOF
daemon off;
pid $RUN/nginx/nginx.pid;
error_log $RUN/nginx/logs/error.log;
$modules
events {}
stream {
    server {
        listen 127.0.0.14:15887;
        proxy_pass 127.0.0.1:15887;
        proxy_protocol on;
    }
}
EOF
	spawn nginx nginx -p "$RUN/nginx" -c "$RUN/nginx/nginx.conf"
	wait_until 5 test -s "$RUN/nginx/nginx.pid" && NGINX=1
fi

# tcp sink: one client per route, then the input
listen_via() { timeout 10 nc "${@:2}" 15887 < <(sleep 12) >"$RUN/$1.out"; }
listen_via admitted 127.0.0.11 &
pids=($!)
listen_via denied 127.0.0.12 &
pids+=($!)
if ((NGINX)); then
	listen_via nginx -s 127.0.0.5 127.0.0.14 &
	pids+=($!)
	listen_via nginx-denied -s 127.0.0.6 127.0.0.14 &
	pids+=($!)
fi
sleep 1
touch "$RUN/feed"
wait "$fpid" "${pids[@]}"
lines() { grep -c '^behind ' "$RUN/$1.out"; }
check "a tcp sink streams to the client a v2 header names ($(lines admitted) lines)" "$(($(lines admitted) == 100))"
# the WARN names whichever denied client came first, the stub's or nginx's
check "and refuses one a v1 header names, logging both addresses ($(lines denied) lines)" \
	"$( (($(lines denied) == 0)) && grep -Eq 'refused by acl.* remote_addr (198.51.100.2|127.0.0.6):.*peer_addr 127.0.0.1:' "$LOG/tcp-behind.out" && echo 1 || echo 0)"
if ((NGINX)); then
	check "nginx stream with proxy_protocol on names its clients ($(lines nginx) lines, $(lines nginx-denied) to a denied one)" \
		"$( (($(lines nginx) == 100 && $(lines nginx-denied) == 0)) && echo 1 || echo 0)"
else
	skip "nginx stream with proxy_protocol on (nginx with its stream module is not available)"
fi

# tcp sink capped at two connections per client: two held, then a third and another client's
held() { timeout 2 nc "$@" 15889 </dev/null >/dev/null; (($? == 124)) && echo 1 || echo 0; } # NC_ARGS... ADDR
pids=()
for from in 127.0.0.11 127.0.0.11 '-s 127.0.0.2 127.0.0.1' '-s 127.0.0.2 127.0.0.1'; do
	# shellcheck disable=SC2086 # NC_ARGS
	timeout 6 nc $from 15889 </dev/null >/dev/null &
	pids+=($!)
done
sleep 1
third=$(held 127.0.0.11) other=$(held 127.0.0.12)
check "a third connection from the client a header names is closed, another client's held ($third, $other)" \
	"$( ((!third && other)) && grep -q 'refused by acl.* remote_addr 198.51.100.1:.*max_connections_per_client.*peer_addr 127.0.0.1:' "$LOG/tcp-capped.out" && echo 1 || echo 0)"
third=$(held -s 127.0.0.2 127.0.0.1) other=$(held -s 127.0.0.3 127.0.0.1)
check "and so for direct peers, outside proxy_from ($third, $other)" "$( ((!third && other)) && echo 1 || echo 0)"
wait "${pids[@]}"

# http sink: each client its own login budget behind the one proxy address
PIN=$(pin sink-behind)
token() { lw auth token --url "https://$1:15886" -u viewer-01 --password-file "$2" --pin-sha256 "$PIN" 2>&1; }
token 127.0.0.12 "$RUN/viewer-01.pass" >/dev/null
check "an http sink refuses the client a v2 header names, logging both addresses" \
	"$(logged sink-behind 'refused by acl.* remote_addr 198.51.100.2:.*peer_addr 127.0.0.1:' && echo 1 || echo 0)"
for ((i = 1; i <= 30; i++)); do
	token 127.0.0.11 "$RUN/wrong.pass" >/dev/null
	logged sink-behind ' throttled' && break
done
check "wrong passwords throttle a client by the address its v1 header names ($i attempts)" \
	"$(logged sink-behind 'Login rejected.* remote_addr 198.51.100.1:.* 198.51.100.1 throttled' && echo 1 || echo 0)"
check "while another behind the same proxy still logs in" \
	"$(token 127.0.0.13 "$RUN/viewer-01.pass" >/dev/null && logged sink-behind 'Login accepted.* remote_addr 198.51.100.3:' && echo 1 || echo 0)"

# chain sources: an edge through the proxy is the client its header names
edge edge-tcp-behind 127.0.0.11:15888 tcp "$(pin agg-tcp-behind)"
edge edge-http-behind 127.0.0.13:15883 http "$(pin agg-http-behind)"
printf 'PROXY TCP4 198.51.100.9 127.0.0.1 40000 15888\r\n' | timeout 3 nc -s 127.0.0.2 127.0.0.1 15888
wait_until 10 eval '(( $(received tcp-behind) >= 300 && $(received http-behind) >= 300 ))'
check "a tcp_chain source takes an edge as the client a v1 header names ($(received tcp-behind))" \
	"$( (($(received tcp-behind) == 300)) && logged agg-tcp-behind 'Chain connection established.* remote_addr 198.51.100.1:' && echo 1 || echo 0)"
check "an http_chain source takes one as the client a v2 header names ($(received http-behind))" \
	"$( (($(received http-behind) == 300)) && logged agg-http-behind 'Login accepted.* remote_addr 198.51.100.3:' && echo 1 || echo 0)"
check "a header from a peer outside proxy_from is refused" \
	"$(logged agg-tcp-behind 'refused by acl.* remote_addr 127.0.0.2:.* reason "PROXY header from a peer outside proxy_from"' && echo 1 || echo 0)"

summary
