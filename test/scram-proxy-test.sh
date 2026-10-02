#!/usr/bin/env bash
# logwisp browser login test: an http sink in proxy mode (auth.trusted_proxies)
# behind a TLS-terminating reverse proxy that mounts it under /logs/. Headless
# Chromium logs in through the shipped pages, with cookies and with a profile
# that blocks them (the viewer's token mode); the CLI logs in unbound.
# Usage: ./scram-proxy-test.sh [--auto [--keep]]   manual mode keeps the daemons
#   up; --auto runs the checks and tears down, --keep skips that on success.
# Requires: bash 5+, go, openssl, curl; node with playwright for the browser
# checks (skipped, and reported, without it). Linux dev host only.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${LOGWISP_BIN:-$SCRIPT_DIR/../bin/lw}"
RUN="$SCRIPT_DIR/run-proxy"
CONF="$RUN/conf"
LOG="$RUN/log"
PKI="$RUN/pki"
AUTH="$RUN/auth"
PROXY_SRC="$RUN/proxy"
USERS="$AUTH/users.toml"

PORT_PROXY=15831 # the site: TLS ends here, logwisp is under /logs/
PORT_SINK=15832  # logwisp http sink, plaintext, only for 127.0.0.2
PROXY_ADDR=127.0.0.2
SITE="https://127.0.0.1:$PORT_PROXY"

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

# --- Preflight ---
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (build: go build -o bin/lw ./cmd/lw)" >&2; exit 1; }
for tool in go openssl curl; do
	command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 1; }
done
for p in $PORT_PROXY $PORT_SINK; do
	port_open "$p" && { echo "port $p already in use" >&2; exit 1; }
done
BROWSER=0
command -v node >/dev/null && node -e 'require.resolve("playwright")' 2>/dev/null && BROWSER=1
rm -rf "$RUN"
mkdir -p "$CONF" "$LOG" "$PKI" "$AUTH" "$PROXY_SRC"

# --- PKI: the site's certificate; logwisp holds none ---
echo "--- generating the site certificate in $PKI"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PKI/ca.key" 2>/dev/null
openssl req -x509 -new -key "$PKI/ca.key" -days 2 -out "$PKI/ca.crt" -subj "/CN=LogWisp Test CA" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PKI/site.key" 2>/dev/null
openssl req -new -key "$PKI/site.key" -out "$PKI/site.csr" -subj "/CN=site.internal" 2>/dev/null
printf 'extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n' > "$PKI/site.ext"
openssl x509 -req -in "$PKI/site.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
	-out "$PKI/site.crt" -days 2 -extfile "$PKI/site.ext" 2>/dev/null
[[ -s "$PKI/site.crt" ]] || { echo "PKI generation failed" >&2; exit 1; }

# --- Credentials, through the CLI only (the default 64 MiB profile) ---
"$BIN" auth add-user -credentials "$USERS" -user viewer-01 -password-file "$AUTH/viewer-01.pass" \
	2>>"$LOG/auth-cli.out" || { echo "add-user failed (see $LOG/auth-cli.out)" >&2; exit 1; }

# --- The site's reverse proxy ---
# /logs/ forwards to logwisp from $PROXY_ADDR; /plain/ forwards the same way
# but says the site was reached over http, which logwisp must refuse.
cat > "$PROXY_SRC/main.go" <<'EOF'
package main

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	listen, upstream, from, cert, key := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatal(err)
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}}
	transport := &http.Transport{DialContext: dialer.DialContext}
	route := func(prefix, proto string) http.Handler {
		return &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(target)
				r.Out.URL.Path = "/" + strings.TrimPrefix(r.In.URL.Path, prefix)
				r.Out.URL.RawPath = ""
				r.SetXForwarded()
				r.Out.Header.Set("X-Forwarded-Proto", proto)
			},
			Transport:     transport,
			FlushInterval: -1, // server-sent events
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/logs/", route("/logs/", "https"))
	mux.Handle("/plain/", route("/plain/", "http"))
	log.Fatal(http.ListenAndServeTLS(listen, cert, key, mux))
}
EOF
(cd "$PROXY_SRC" && go build -o proxy main.go) || { echo "proxy build failed" >&2; exit 1; }

# --- Config ---
cat > "$CONF/logwisp.toml" <<EOF
status_reporter = false
[logging]
output = "stdout"
level = "info"

[[pipelines]]
name = "site"
[[pipelines.plugin_sources]]
id = "rand"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 200
format = "txt"
length = 24

[[pipelines.plugin_sinks]]
id = "web"
type = "http"
[pipelines.plugin_sinks.config]
host = "127.0.0.1"
port = $PORT_SINK
login_page = true
viewer_page = true
[pipelines.plugin_sinks.config.auth]
type = "scram"
credentials_file = "$USERS"
trusted_proxies = ["$PROXY_ADDR"]
EOF

cat > "$RUN/browser.cjs" <<'EOF'
// Signs in through the shipped pages, as a person would; prints key=value lines.
// cookie: a fresh browser. dropped: the session cookie never arrives. blocked:
// a profile that refuses every cookie; it also reloads logwisp (pid) mid-stream.
const { chromium } = require("playwright");
const fs = require("fs");
const [mode, base, user, passFile, profile, pid] = process.argv.slice(2);
const password = fs.readFileSync(passFile, "utf8").replace(/\n+$/, "");
const out = { csp_violations: 0 };

const lines = (page) => page.evaluate(() => document.querySelectorAll("#log > div").length);
const linesAtLeast = (page, n) =>
  page.waitForFunction((n) => document.querySelectorAll("#log > div").length >= n, n, { timeout: 15000 });
const statusText = (page) => page.evaluate(() => document.getElementById("status").textContent);
const statusIs = (page, re) =>
  page.waitForFunction((re) => new RegExp(re).test(document.getElementById("status").textContent), re.source, { timeout: 30000 });
const signIn = async (page, pass) => {
  await page.fill('#login input[name="username"]', user);
  await page.fill('#login input[name="password"]', pass);
  await page.click('#login button[type="submit"]');
};
const inlineLogin = (page) => page.waitForSelector("#login:not([hidden])", { timeout: 30000 });

const scenarios = {
  async cookie(context, page) {
    await page.goto(base + "auth/view");
    await page.waitForURL(/\/auth\/login\?next=view%23signed-in$/, { timeout: 10000 });
    out.redirected_to_login = 1;
    await signIn(page, "not-the-password");
    await statusIs(page, /refused/);
    out.wrong_password_refused = 1;

    const started = Date.now();
    await signIn(page, password);
    await page.waitForURL(/\/auth\/view$/, { timeout: 30000 }).catch(async (e) => { throw new Error(`${e.message}: ${await statusText(page)}`); });
    out.login_ms = Date.now() - started;
    await linesAtLeast(page, 3);
    out.events = await lines(page);
    out.inline_login = await page.evaluate(() => !document.getElementById("login").hidden);

    const c = (await context.cookies()).find((c) => c.name === "logwisp_session");
    out.cookie = c ? `path=${c.path};httponly=${c.httpOnly};secure=${c.secure};samesite=${c.sameSite}` : "none";
    out.document_cookie = JSON.stringify(await page.evaluate(() => document.cookie));

    await page.click("#logout");
    await page.waitForURL(/\/auth\/login$/, { timeout: 10000 });
    out.cookie_after_logout = (await context.cookies()).some((c) => c.name === "logwisp_session") ? 1 : 0;
    out.status_after_logout = await page.evaluate(async (b) => (await fetch(b + "status")).status, base);
  },

  // As if the browser dropped the cookie silently: the viewer must not send
  // the person back to the login page in a loop
  async dropped(context, page) {
    await context.route(/\/auth$/, async (route) => {
      const response = await route.fetch();
      await context.clearCookies(); // route.fetch shares the context's cookie jar
      const headers = response.headers();
      delete headers["set-cookie"];
      await route.fulfill({ response, headers });
    });
    await page.goto(base + "auth/view");
    await page.waitForURL(/\/auth\/login\?next=/, { timeout: 10000 });
    await signIn(page, password);
    await page.waitForURL(/\/auth\/view$/, { timeout: 30000 });
    await inlineLogin(page);
    out.inline_login = 1;
    out.url = page.url();
  },

  async blocked(context, page) {
    await page.goto(base + "auth/login");
    out.cookie_enabled = await page.evaluate(() => navigator.cookieEnabled);
    out.document_cookie_kept = JSON.stringify(await page.evaluate(() => { document.cookie = "t=1"; return document.cookie; }));
    await page.waitForSelector('#status a[href="view"]', { timeout: 10000 });
    out.login_page_disabled = await page.evaluate(() => document.querySelector("#login button").disabled);
    await page.click('#status a[href="view"]');
    await inlineLogin(page);
    out.inline_login = 1;

    const streamed = page.waitForRequest(/\/stream$/, { timeout: 30000 });
    await signIn(page, password);
    const bearer = (await streamed).headers().authorization ?? "";
    out.stream_bearer = /^Bearer \S+$/.test(bearer) ? 1 : 0;
    await linesAtLeast(page, 3);
    out.events = await lines(page);
    out.cookies_stored = (await context.cookies()).length;
    const statusWith = () => page.evaluate(async ([b, h]) =>
      (await fetch(b + "status", { headers: { Authorization: h } })).status, [base, bearer]);
    out.token_status = await statusWith();

    await page.click("#logout");
    await statusIs(page, /^Signed out\.$/);
    await inlineLogin(page);
    out.token_status_after_logout = await statusWith();

    // A reload ends the open stream and every token; the reconnect's 401 asks again
    await signIn(page, password);
    await page.waitForFunction(() => document.getElementById("state").textContent === "live", null, { timeout: 30000 });
    process.kill(Number(pid), "SIGHUP");
    await statusIs(page, /session ended/);
    await inlineLogin(page);
    out.expired_asks_again = 1;
  },
};

(async () => {
  let context;
  try {
    if (mode === "blocked") {
      // Full Chromium: the headless shell ignores a profile's Preferences
      context = await chromium.launchPersistentContext(profile, { ignoreHTTPSErrors: true, channel: "chromium" });
    } else {
      context = await (await chromium.launch()).newContext({ ignoreHTTPSErrors: true });
    }
    const page = await context.newPage();
    page.on("console", (m) => { if (/Content Security Policy/i.test(m.text())) out.csp_violations++; });
    await scenarios[mode](context, page);
  } catch (e) {
    out.error = JSON.stringify(e.message.split("\n")[0]);
  } finally {
    await (context?.browser() ?? context)?.close();
  }
  for (const [k, v] of Object.entries(out)) console.log(`${k}=${v}`);
})();
EOF

# --- Guide ---
cat <<EOF
================================================================
 logwisp browser login test — port map
   $PORT_PROXY  the site: TLS-terminating reverse proxy, logwisp under /logs/
   $PORT_SINK  logwisp http sink, plaintext, trusted_proxies = ["$PROXY_ADDR"]

 Open $SITE/logs/auth/view (CA: $PKI/ca.crt) and sign in as viewer-01
 with the password in $AUTH/viewer-01.pass.
 CLI, unbound through the proxy (the token stays off argv):
   token=\$($BIN auth token -unbound -url $SITE/logs -user viewer-01 \\
     -password-file $AUTH/viewer-01.pass -ca-file $PKI/ca.crt)
   curl -N --noproxy '*' --cacert $PKI/ca.crt \\
     -H @<(printf 'Authorization: Bearer %s\n' "\$token") $SITE/logs/stream
 Logs: $LOG/
================================================================
EOF

# --- Startup ---
"$BIN" -c "$CONF/logwisp.toml" > "$LOG/logwisp.out" 2>&1 &
PIDS+=($!)
"$PROXY_SRC/proxy" "127.0.0.1:$PORT_PROXY" "http://127.0.0.1:$PORT_SINK" "$PROXY_ADDR" \
	"$PKI/site.crt" "$PKI/site.key" > "$LOG/proxy.out" 2>&1 &
PIDS+=($!)
for p in $PORT_SINK $PORT_PROXY; do
	wait_port "$p" 10 || { echo "FAIL: port $p not listening (see $LOG/)"; exit 1; }
done

if (( AUTO == 0 )); then
	echo "--- daemons running; Ctrl-C to stop"
	while :; do sleep 1; done
fi

fail=0
check() { # label condition_result
	if (( $2 )); then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}
is() { [[ $1 == "$2" ]] && echo 1 || echo 0; } # actual expected -> 1 or 0
is_set() { [[ -n $1 ]] && echo 1 || echo 0; }

code_of() { # url [token] -> http_code; the header goes through a pipe, never argv
	local args=(-s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' --cacert "$PKI/ca.crt")
	if [[ -n ${2:-} ]]; then
		curl "${args[@]}" -H @<(printf 'Authorization: Bearer %s\n' "$2") "$1" 2>/dev/null || true
	else
		curl "${args[@]}" "$1" 2>/dev/null || true
	fi
}

browser() { # mode: runs browser.cjs, whose key=value lines val reads
	timeout 120 node "$RUN/browser.cjs" "$1" "$SITE/logs/" viewer-01 "$AUTH/viewer-01.pass" \
		"$RUN/profile" "${PIDS[0]}" > "$LOG/browser-$1.out" 2> "$LOG/browser-$1.err"
	browser_out="$(cat "$LOG/browser-$1.out")"
	[[ -n $(val error) ]] && echo "browser error ($1): $(val error)"
}
val() { sed -n "s/^$1=//p" <<< "$browser_out"; }

echo "=== Scenario 1: a person in a browser ==="
if (( BROWSER )); then
	browser cookie
	check "browser: an unauthenticated viewer is sent to the login page" $(is "$(val redirected_to_login)" 1)
	check "browser: a wrong password is refused on the page" $(is "$(val wrong_password_refused)" 1)
	check "browser: login (Argon2 in the page, $(val login_ms) ms) opened the viewer" $(is_set "$(val login_ms)")
	n=$(val events)
	check "browser: the viewer showed events through EventSource (${n:-0} lines)" $(( ${n:-0} >= 3 ))
	check "browser: with the cookie working the viewer shows no sign-in form" $(is "$(val inline_login)" false)
	check "browser: session cookie $(val cookie)" \
		$(is "$(val cookie)" "path=/logs;httponly=true;secure=true;samesite=Strict")
	check "browser: page scripts cannot read the session (document.cookie $(val document_cookie))" \
		$(is "$(val document_cookie)" '""')
	check "browser: sign out cleared the cookie" $(is "$(val cookie_after_logout)" 0)
	check "browser: status refused after sign out (HTTP $(val status_after_logout))" $(is "$(val status_after_logout)" 401)
	check "browser: no CSP violations ($(val csp_violations))" $(is "$(val csp_violations)" 0)
	n=$(grep 'Login accepted' "$LOG/logwisp.out" | grep -c 'remote_addr 127.0.0.1')
	check "logwisp logged the forwarded client, not the proxy ($n logins from 127.0.0.1)" $(( n >= 1 ))
	browser dropped
	check "browser: a session cookie the browser dropped brings the viewer's own sign-in form, not a loop" \
		$(is "$(val inline_login)" 1)
else
	echo "SKIP: browser checks (node with playwright not found)"
fi

echo "=== Scenario 2: a browser that keeps no cookies ==="
if (( BROWSER )); then
	mkdir -p "$RUN/profile/Default"
	echo '{"profile": {"default_content_setting_values": {"cookies": 2}}}' > "$RUN/profile/Default/Preferences"
	browser blocked
	check "no cookies: the profile blocks cookies (document.cookie kept $(val document_cookie_kept); navigator.cookieEnabled $(val cookie_enabled))" \
		$(is "$(val document_cookie_kept)" '""')
	check "no cookies: the login page says so, links to the viewer and stays disabled" \
		$(is "$(val login_page_disabled)" true)
	check "no cookies: the viewer shows its own sign-in form" $(is "$(val inline_login)" 1)
	n=$(val events)
	check "no cookies: the viewer streamed events with a bearer token (${n:-0} lines)" \
		$(( ${n:-0} >= 3 && $(is "$(val stream_bearer)" 1) ))
	check "no cookies: the browser stored no cookie ($(val cookies_stored))" $(is "$(val cookies_stored)" 0)
	check "no cookies: the page's token opened status (HTTP $(val token_status))" $(is "$(val token_status)" 200)
	check "no cookies: sign out revoked it (HTTP $(val token_status_after_logout))" \
		$(is "$(val token_status_after_logout)" 401)
	check "no cookies: a reload ended the session and the viewer asked to sign in again" \
		$(is "$(val expired_asks_again)" 1)
	check "no cookies: no CSP violations ($(val csp_violations))" $(is "$(val csp_violations)" 0)
else
	echo "SKIP: browser checks (node with playwright not found)"
fi

echo "=== Scenario 3: the CLI through the proxy ==="
token="$("$BIN" auth token -unbound -url "$SITE/logs" -user viewer-01 -password-file "$AUTH/viewer-01.pass" \
	-ca-file "$PKI/ca.crt" 2>>"$LOG/auth-cli.out")"
check "cli: lw auth token -unbound logged in through the proxy" $(is_set "$token")
code="$(code_of "$SITE/logs/status" "$token")"
check "cli: /logs/status served with the token (HTTP $code)" $(is "$code" 200)
sse="$(timeout 3 curl -sN --noproxy '*' --cacert "$PKI/ca.crt" \
	-H @<(printf 'Authorization: Bearer %s\n' "$token") "$SITE/logs/stream" 2>/dev/null || true)"
n=$(grep -c '^data:' <<< "$sse")
check "cli: /logs/stream delivered SSE events with the token ($n events)" $(( n >= 1 ))
code="$(code_of "$SITE/logs/status")"
check "cli: /logs/status refused without a token (HTTP $code)" $(is "$code" 401)
"$BIN" auth token -url "$SITE/logs" -user viewer-01 -password-file "$AUTH/viewer-01.pass" \
	-ca-file "$PKI/ca.crt" >/dev/null 2>>"$LOG/auth-cli.out"
rc=$?
check "cli: a path without -unbound is a usage error (exit $rc)" $(( rc == 2 ))

echo "=== Scenario 4: around the proxy ==="
code="$(code_of "http://127.0.0.1:$PORT_SINK/auth/login")"
check "direct: the login page refuses a peer that is not the proxy (HTTP $code)" $(is "$code" 403)
code="$(code_of "http://127.0.0.1:$PORT_SINK/status" "$token")"
check "direct: a valid token does not open the sink around the proxy (HTTP $code)" $(is "$code" 403)
code="$(code_of "$SITE/plain/status" "$token")"
check "plaintext site: a request the proxy received over http is refused (HTTP $code)" $(is "$code" 403)

echo "================================================================"
if (( fail == 0 )); then
	echo "RESULT: ALL PASS"
	(( KEEP )) && { echo "--keep: daemons left running (pids: ${PIDS[*]})"; PIDS=(); }
else
	echo "RESULT: FAILURES — inspect $LOG/*"
fi
exit "$fail"
