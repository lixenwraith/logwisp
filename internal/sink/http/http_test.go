package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/testutil"

	"github.com/lixenwraith/auth"
	"github.com/lixenwraith/log"
)

func TestStatusReportsQueueAndConnectionBounds(t *testing.T) {
	httpSink, _ := newTestHTTPSink(t, map[string]any{
		"buffer_size":        int64(4096),
		"client_buffer_size": int64(512),
		"max_connections":    int64(32),
	})

	recorder := httptest.NewRecorder()
	httpSink.handleStatus(recorder, httptest.NewRequest("GET", "/status", nil))
	if recorder.Code != 200 {
		t.Fatalf("status code = %d", recorder.Code)
	}
	var response struct {
		Server map[string]any `json:"server"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"buffer_size":        4096,
		"client_buffer_size": 512,
		"max_connections":    32,
		"write_timeout_ms":   5000,
	} {
		if got := response.Server[key]; got != want {
			t.Errorf("server.%s = %v, want %v", key, got, want)
		}
	}

	stats := httpSink.GetStats()
	details := stats.Details
	for key, want := range map[string]int64{
		"buffer_size":        4096,
		"client_buffer_size": 512,
		"max_connections":    32,
		"write_timeout_ms":   5000,
	} {
		if got := details[key]; got != want {
			t.Errorf("details[%q] = %v, want %v", key, got, want)
		}
	}

	var _ sink.Sink = httpSink
}

// A stream carrying nothing still refreshes its session. Log traffic is what
// bumps activity otherwise, so a quiet source would idle-expire a healthy client
// and the broker would evict it on the next entry.
func TestQuietStreamRefreshesItsSession(t *testing.T) {
	httpSink, manager := newTestHTTPSink(t, nil)
	httpSink.keepalive = 100 * time.Millisecond
	client, baseURL := serveTestHTTPSink(t, httpSink)
	resp, err := client.Get(baseURL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	activity := func() time.Time {
		for _, s := range manager.GetActiveSessions() {
			return s.LastActivity
		}
		t.Fatal("no session for the connected client")
		return time.Time{}
	}

	before := activity()
	if before.IsZero() {
		t.Fatal("stream session was not registered")
	}
	scanner := bufio.NewScanner(resp.Body)
	heartbeats := 0
	for heartbeats < 2 && scanner.Scan() {
		if scanner.Text() == ":" {
			heartbeats++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if heartbeats != 2 {
		t.Fatal("stream ended before two keepalives")
	}
	if after := activity(); !after.After(before) {
		t.Fatalf("last activity %v did not advance after keepalives from %v", after, before)
	}
}

// HEAD on the stream path is refused rather than served from the GET pattern:
// its body writes are discarded, so the client it would register never reads.
func TestHeadOnStreamPathIsRefused(t *testing.T) {
	httpSink, manager := newTestHTTPSink(t, nil)
	client, baseURL := serveTestHTTPSink(t, httpSink)
	resp, err := client.Head(baseURL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD /stream = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow = %q, want %q", got, http.MethodGet)
	}
	if n := manager.GetSessionCount(); n != 0 {
		t.Errorf("sessions after HEAD = %d, want 0", n)
	}
}

// A stream gated by an auth policy is not offered to every web origin; an
// open stream keeps the wildcard so browser dashboards still work.
func TestWildcardCORSOnlyWithoutAuth(t *testing.T) {
	pki := testutil.NewPKI(t, "viewer-01")
	open, _ := newTestHTTPSink(t, nil)
	gated, _ := newTestHTTPSink(t, map[string]any{
		"tls": map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey,
			"client_auth": true, "client_ca_file": pki.CA},
		"auth": map[string]any{"type": "mtls", "allow": []any{"viewer-01"}},
	})
	for _, tc := range []struct {
		name string
		sink *HTTPSink
		want string
	}{{"open", open, "*"}, {"gated", gated, ""}} {
		client, baseURL := serveTestHTTPSink(t, tc.sink)
		if tc.sink.tlsConfig != nil {
			baseURL = trustPKI(t, client, baseURL, pki, true)
		}
		resp, err := client.Get(baseURL + "/stream")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: GET /stream = %d", tc.name, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != tc.want {
			t.Errorf("%s: Access-Control-Allow-Origin = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Under scram the login endpoint sits outside the gate it opens: a hello
// earns a challenge without a token, while stream and status demand one.
func TestLoginEndpointBypassesTheGate(t *testing.T) {
	pki := testutil.NewPKI(t, "viewer-01")
	creds := scramCredentials(t)
	gated, _ := newTestHTTPSink(t, map[string]any{
		"tls":  map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey},
		"auth": map[string]any{"type": "scram", "credentials_file": creds},
	})
	client, baseURL := serveTestHTTPSink(t, gated)
	baseURL = trustPKI(t, client, baseURL, pki, false)

	hello := `{"logwisp":1,"scram":{"username":"viewer-01","client_nonce":"abcdefgh"}}`
	resp, err := client.Post(baseURL+"/auth", "application/json", strings.NewReader(hello))
	if err != nil {
		t.Fatal(err)
	}
	var step struct {
		Challenge *auth.ServerFirstMessage `json:"challenge"`
	}
	json.NewDecoder(resp.Body).Decode(&step)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || step.Challenge == nil {
		t.Fatalf("POST /auth without a token = %d, challenge %v", resp.StatusCode, step.Challenge)
	}
	for _, path := range []string{"/status", "/stream"} {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d, want 401", path, resp.StatusCode)
		}
	}
}

// proxied sends what a TLS-terminating proxy would: the client and https
func proxied(req *http.Request) *http.Request {
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	return req
}

func proxySink(t *testing.T, proxies []any, overrides map[string]any) *HTTPSink {
	t.Helper()
	opts := map[string]any{"auth": map[string]any{"type": "scram", "credentials_file": scramCredentials(t), "trusted_proxies": proxies}}
	maps.Copy(opts, overrides)
	h, _ := newTestHTTPSink(t, opts)
	return h
}

// Behind a proxy the sink serves the client library and the enabled pages
// under /auth/, each with its type and the pages' CSP; the viewer learns a
// custom status path from its meta tag.
func TestProxyModeServesBrowserFiles(t *testing.T) {
	h := proxySink(t, []any{"127.0.0.1"}, map[string]any{"login_page": true, "viewer_page": true, "status_path": "/api/status"})
	if !slices.Contains(h.Capabilities(), core.CapProxyTLS) {
		t.Fatal("a proxy-mode sink does not report proxy_tls")
	}
	client, baseURL := serveTestHTTPSink(t, h)
	for file, ctype := range map[string]string{
		"scram.js": "text/javascript", "login": "text/html", "login.js": "text/javascript",
		"style.css": "text/css", "view": "text/html", "view.js": "text/javascript", "favicon.svg": "image/svg+xml",
	} {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/auth/"+file, nil)
		resp, err := client.Do(proxied(req))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), ctype) ||
			!strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self';") {
			t.Errorf("/auth/%s: %d %q %q", file, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Security-Policy"))
		}
		if file == "view" && !bytes.Contains(body, []byte(`content="api/status"`)) {
			t.Error("the viewer page does not carry the custom status path")
		}
	}
}

// The root leads to the page a browser can use: the viewer, needing no login
// without auth and under mtls; in proxy mode the viewer, or else the login
// page; nothing under direct scram, which a browser cannot log in to; and an
// endpoint at "/" keeps the root.
func TestRootLeadsToThePageABrowserCanUse(t *testing.T) {
	pki := testutil.NewPKI(t, "viewer-01")
	tlsOn := map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey}
	mtlsOn := map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey,
		"client_auth": true, "client_ca_file": pki.CA}
	creds := scramCredentials(t)
	proxy := map[string]any{"type": "scram", "credentials_file": creds, "trusted_proxies": []any{"127.0.0.1"}}
	for _, tc := range []struct {
		name         string
		opts         map[string]any
		code         int
		target, mode string // the root's Location, and that page's logwisp-login
	}{
		{"no auth", nil, http.StatusSeeOther, "auth/view", "none"},
		{"mtls", map[string]any{"tls": mtlsOn, "auth": map[string]any{"type": "mtls"}}, http.StatusSeeOther, "auth/view", "none"},
		{"proxy, viewer", map[string]any{"auth": proxy, "login_page": true, "viewer_page": true}, http.StatusSeeOther, "auth/view", "scram"},
		{"proxy, login page", map[string]any{"auth": proxy, "login_page": true}, http.StatusSeeOther, "auth/login", ""},
		{"direct scram", map[string]any{"tls": tlsOn, "auth": map[string]any{"type": "scram", "credentials_file": creds}}, http.StatusUnauthorized, "", ""},
		{"status at the root", map[string]any{"status_path": "/"}, http.StatusOK, "", ""},
	} {
		h, _ := newTestHTTPSink(t, tc.opts)
		client, baseURL := serveTestHTTPSink(t, h)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		if h.tlsConfig != nil {
			baseURL = trustPKI(t, client, baseURL, pki, h.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert)
		}
		get := func(path string) (*http.Response, string) {
			req, _ := http.NewRequest(http.MethodGet, baseURL+path, nil)
			resp, err := client.Do(proxied(req))
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp, string(body)
		}
		resp, _ := get("/")
		if resp.StatusCode != tc.code || resp.Header.Get("Location") != tc.target {
			t.Errorf("%s: GET / = %d to %q, want %d to %q", tc.name, resp.StatusCode, resp.Header.Get("Location"), tc.code, tc.target)
		}
		for _, file := range []string{tc.target + ".js", "auth/scram.js", "auth/style.css"} {
			if resp, _ := get("/" + file); tc.target != "" && resp.StatusCode != http.StatusOK {
				t.Errorf("%s: /%s = %d, which its page loads", tc.name, file, resp.StatusCode)
			}
		}
		if tc.mode == "" {
			continue
		}
		resp, page := get("/" + tc.target)
		if want := `name="logwisp-login" content="` + tc.mode + `"`; resp.StatusCode != http.StatusOK || !strings.Contains(page, want) {
			t.Errorf("%s: /%s = %d, without %s", tc.name, tc.target, resp.StatusCode, want)
		}
	}
}

// A path ending in "/" matches itself only: a stream at the root does not
// answer every other path, a browser's favicon request included
func TestEndpointPathsMatchExactly(t *testing.T) {
	h, manager := newTestHTTPSink(t, map[string]any{"stream_path": "/"})
	client, baseURL := serveTestHTTPSink(t, h)
	for path, want := range map[string]int{"/favicon.ico": http.StatusNotFound, "/auth/view": http.StatusOK} {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
	if n := manager.GetSessionCount(); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
}

// Behind a proxy nothing answers a peer outside trusted_proxies, not even the
// login page or the challenge.
func TestProxyModeRefusesDirectPeers(t *testing.T) {
	h := proxySink(t, []any{"192.0.2.1"}, map[string]any{"login_page": true})
	client, baseURL := serveTestHTTPSink(t, h)
	for _, target := range []struct{ method, path string }{
		{http.MethodGet, "/auth/login"}, {http.MethodGet, "/status"}, {http.MethodPost, "/auth"},
	} {
		req, _ := http.NewRequest(target.method, baseURL+target.path, strings.NewReader(`{"logwisp":1}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(proxied(req))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s from an untrusted peer: %d, want 403", target.method, target.path, resp.StatusCode)
		}
	}
}

// A PROXY header names the client a stream's session records; the proxy
// stays as its peer_addr
func TestProxiedStreamSessionKeepsTheProxy(t *testing.T) {
	h, manager := newTestHTTPSink(t, map[string]any{"acl": map[string]any{"proxy_protocol": "required", "proxy_from": []any{"127.0.0.1"}}})
	_, baseURL := serveTestHTTPSink(t, h)
	conn, err := net.Dial("tcp4", strings.TrimPrefix(baseURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprint(conn, "PROXY TCP4 198.51.100.7 127.0.0.1 40000 8081\r\nGET /stream HTTP/1.1\r\nHost: logwisp\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil { // its body is the stream
		t.Fatal(err)
	}
	sessions := manager.GetActiveSessions()
	if len(sessions) != 1 || sessions[0].RemoteAddr != "198.51.100.7:40000" || sessions[0].Metadata["peer_addr"] != conn.LocalAddr().String() {
		t.Fatalf("sessions %+v, proxy %s", sessions, conn.LocalAddr())
	}
}

// The constructor refuses what it cannot serve: the login pages outside
// scram's proxy mode, a viewer without the login page, a path under /auth, and
// a path ServeMux or a URL would not take literally, which panicked at Start.
func TestUnservableOptionsAreRefused(t *testing.T) {
	scram := map[string]any{"type": "scram", "credentials_file": scramCredentials(t)}
	pki := testutil.NewPKI(t, "viewer-01")
	tlsOn := map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey}
	proxy := map[string]any{"type": "scram", "credentials_file": scram["credentials_file"], "trusted_proxies": []any{"127.0.0.1"}}
	for name, opts := range map[string]map[string]any{
		"login page without proxies": {"tls": tlsOn, "auth": scram, "login_page": true},
		"viewer without login":       {"auth": proxy, "viewer_page": true},
		"stream under /auth":         {"auth": proxy, "stream_path": "/auth/stream"},
		"wildcard brace in a path":   {"stream_path": "/a{b"},
		"unclean path":               {"status_path": "//status"},
		"escape aliasing a path":     {"stream_path": "/x", "status_path": "/%78"},
		"query in a path":            {"status_path": "/a?b"},
	} {
		maps.Copy(opts, map[string]any{"host": "127.0.0.1", "port": int64(8081)})
		if _, err := NewHTTPSinkPlugin("stream", opts, log.NewLogger(), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every line break SSE recognises, a lone CR included, starts another data:
// line: an entry cannot inject an event:, retry: or id: field.
func TestSSEFramesEveryLineAsData(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeSSE(rec, []byte("a\revent: disconnect\r\nretry: 99999999\nid: x\r")); err != nil {
		t.Fatal(err)
	}
	want := "data: a\ndata: event: disconnect\ndata: retry: 99999999\ndata: id: x\n\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("framed %q, want %q", got, want)
	}
}

// Stop writes what is queued, in the sink and per stream, then the
// disconnect event, to a client that keeps reading, whatever another that
// stopped reading does; Stop returns at the flush bound.
func TestStopWritesQueuedEventsToReadingStreams(t *testing.T) {
	const n = 2000 // of 8 KiB: more than a silent peer's socket buffers hold
	httpSink, _ := newTestHTTPSink(t, map[string]any{"buffer_size": int64(n), "client_buffer_size": int64(64), "write_timeout_ms": int64(2000)})
	client, baseURL := serveTestHTTPSink(t, httpSink)
	var scanners []*bufio.Scanner
	for range 2 {
		resp, err := client.Get(baseURL + "/stream")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(nil, 64*1024)
		for scanner.Scan() && scanner.Text() != "event: connected" {
		}
		scanners = append(scanners, scanner)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		httpSink.clientsMu.Lock()
		registered := len(httpSink.clients)
		httpSink.clientsMu.Unlock()
		if registered == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("streams never registered")
		}
	}
	type result struct {
		lines      int
		disconnect bool
	}
	done := make(chan result)
	go func() {
		var r result
		for scanners[0].Scan() {
			switch line := scanners[0].Text(); {
			case strings.HasPrefix(line, "data: line "):
				r.lines++
			case line == "event: disconnect":
				r.disconnect = true
			}
		}
		done <- r
	}()
	// Held, the lock keeps the input queued until Stop has begun its flush
	httpSink.clientsMu.Lock()
	padding := strings.Repeat("x", 8192)
	for i := range n {
		httpSink.Input() <- core.TransportEvent{Payload: fmt.Appendf(nil, "line %d %s\n", i, padding)}
	}
	stopped := make(chan time.Duration)
	go func() {
		start := time.Now()
		httpSink.Stop()
		stopped <- time.Since(start)
	}()
	time.Sleep(100 * time.Millisecond)
	httpSink.clientsMu.Unlock()
	if d := <-stopped; d > 3500*time.Millisecond {
		t.Errorf("Stop took %v past a 2 s flush bound", d)
	}
	if r := <-done; r.lines != n || !r.disconnect {
		t.Fatalf("reading stream received %d of %d lines, disconnect %v", r.lines, n, r.disconnect)
	}
}

// A stream that connects late gets the last replay_lines entries after its
// connected event, then the live ones, none twice
func TestLateStreamGetsTheBacklog(t *testing.T) {
	httpSink, _ := newTestHTTPSink(t, map[string]any{"replay_lines": int64(2)})
	client, baseURL := serveTestHTTPSink(t, httpSink)
	until := func(cond func() bool) {
		for deadline := time.Now().Add(2 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("timed out")
			}
		}
	}
	for i := range 3 {
		httpSink.Input() <- core.TransportEvent{Payload: fmt.Appendf(nil, "line %d\n", i)}
	}
	until(func() bool { return httpSink.totalProcessed.Load() == 3 })
	resp, err := client.Get(baseURL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() && scanner.Text() != "event: connected" {
	}
	scanner.Scan() // its data
	until(func() bool {
		httpSink.clientsMu.Lock()
		defer httpSink.clientsMu.Unlock()
		return len(httpSink.clients) == 1
	})
	httpSink.Input() <- core.TransportEvent{Payload: []byte("line 3\n")}
	var got []string
	for len(got) < 3 && scanner.Scan() {
		if line, ok := strings.CutPrefix(scanner.Text(), "data: "); ok {
			got = append(got, line)
		}
	}
	if !slices.Equal(got, []string{"line 1", "line 2", "line 3"}) {
		t.Fatalf("stream got %q", got)
	}
}
