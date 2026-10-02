package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"logwisp/internal/chain"
	"logwisp/internal/config"

	"github.com/lixenwraith/auth"
)

// forwarding is the proxy's half of every request: the client and https
type forwarding struct{ next http.RoundTripper }

func (f forwarding) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	return f.next.RoundTrip(r)
}

// proxyListener is a plaintext http sink policy behind a proxy on loopback
func (f *fixture) proxyListener(t *testing.T) (*Policy, *httptest.Server) {
	t.Helper()
	l := f.listener(t, config.AuthOptions{TrustedProxies: []string{"127.0.0.1"}}, nil, RoleListener, HTTP)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+chain.AuthPath, func(w http.ResponseWriter, r *http.Request) { l.ServeAuth(w, r) })
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		if _, status, err := l.AuthorizeRequest(r); err != nil {
			Refuse(w, status)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return l, srv
}

// Behind trusted proxies only they may connect, only requests they received
// over https pass, and the client is the rightmost forwarded hop that is not
// a proxy: hops to its left are the client's own claims.
func TestProxyModeTrustsOnlyItsProxies(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{TrustedProxies: []string{"127.0.0.1", "10.0.0.0/8"}}, nil, RoleListener, HTTP)
	for _, tc := range []struct{ name, peer, xff, proto, want string }{
		{"untrusted peer", "192.0.2.1:5000", "203.0.113.7", "https", ""},
		{"no proto", "127.0.0.1:5000", "203.0.113.7", "", ""},
		{"plaintext site", "127.0.0.1:5000", "203.0.113.7", "http", ""},
		{"one plaintext hop", "127.0.0.1:5000", "203.0.113.7", "https, http", ""},
		{"no client", "127.0.0.1:5000", "", "https", ""},
		{"malformed client", "127.0.0.1:5000", "not-an-address", "https", ""},
		{"spoofed hop", "127.0.0.1:5000", "198.51.100.1, 203.0.113.7", "https", "203.0.113.7"},
		{"proxy chain", "127.0.0.1:5000", "203.0.113.7, 10.1.2.3", "https", "203.0.113.7"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if tc.proto != "" {
			r.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		got, err := l.ClientAddr(r)
		switch {
		case tc.want == "" && !errors.Is(err, ErrRefused):
			t.Errorf("%s: client %q, %v; want a refusal", tc.name, got, err)
		case tc.want != "" && (err != nil || got != tc.want):
			t.Errorf("%s: client %q, %v; want %s", tc.name, got, err, tc.want)
		}
	}
}

// A browser logs in unbound and gets its session only as a cookie that
// scopes itself to the mount; the cookie opens the endpoints until logout
// revokes it. Outside proxy mode a cookie session is refused.
func TestBrowserSessionBehindProxy(t *testing.T) {
	f := newFixture(t)
	l, srv := f.proxyListener(t)
	client := &http.Client{Transport: forwarding{http.DefaultTransport}}
	post := func(url string, body any, cookie *http.Cookie) (*http.Response, authStep) {
		data, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, url+chain.AuthPath, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var step authStep
		json.NewDecoder(resp.Body).Decode(&step)
		return resp, step
	}
	login := func(url string) (*http.Response, authStep) {
		c := auth.NewScramClient("edge-01", "edge-01-secret", auth.WithMinArgonCost(1, 64))
		first, _ := c.StartAuthentication()
		scram, _ := json.Marshal(first)
		_, step := post(url, chain.Hello{LogWisp: chain.ProtocolVersion, Scram: scram}, nil)
		if step.Challenge == nil {
			t.Fatalf("no challenge: %q", step.Error)
		}
		proof, err := c.ProcessServerFirstMessage(*step.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		return post(url, authStep{Proof: &proof, Session: "cookie"}, nil)
	}
	open := func(cookie *http.Cookie) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	resp, step := login(srv.URL)
	cookies := resp.Cookies()
	if resp.StatusCode != http.StatusOK || step.Token != "" || len(cookies) != 1 {
		t.Fatalf("login: %d, body token %q, %d cookies", resp.StatusCode, step.Token, len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookie || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode ||
		c.Path != "" || c.MaxAge != int(DefaultTokenLifetime.Seconds()) {
		t.Fatalf("session cookie %+v", c)
	}
	if got := open(c); got != http.StatusOK {
		t.Fatalf("with the cookie: %d", got)
	}
	resp, _ = post(srv.URL, authStep{Logout: true}, c)
	if cleared := resp.Cookies(); resp.StatusCode != http.StatusNoContent || len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("logout: %d, cookies %+v", resp.StatusCode, cleared)
	}
	if got := open(c); got != http.StatusUnauthorized {
		t.Fatalf("after logout: %d, want 401", got)
	}
	if l.allowed.Load() != 1 {
		t.Fatalf("logins = %d", l.allowed.Load())
	}

	direct := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	ds, _ := f.httpListener(t, direct, f.serverTLS)
	client = f.httpClient(f.dialer(t, "edge-01", "edge-01-secret"))
	if resp, _ := post(ds.URL, authStep{Logout: true}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("logout outside proxy mode: %d, want 400", resp.StatusCode)
	}
}

// Behind a proxy logwisp never sees the certificate a client binds to, so
// only unbound proofs (logwisp auth token -unbound) log in; the dialer still
// pins the proxy's certificate across its two requests.
func TestOnlyUnboundLoginsBehindProxy(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{TrustedProxies: []string{"127.0.0.1"}}, f.serverTLS, RoleListener, HTTP)
	srv, _ := f.httpListener(t, l, f.serverTLS)
	for _, unbound := range []bool{false, true} {
		d := f.dialer(t, "edge-01", "edge-01-secret")
		if unbound {
			d.Unbind()
		}
		client := f.httpClient(d)
		client.Transport = forwarding{client.Transport}
		_, err := d.Token(t.Context(), client, srv.URL)
		if unbound != (err == nil) {
			t.Errorf("unbound %v: %v", unbound, err)
		}
	}
	if l.allowed.Load() != 1 || l.Rejected() != 1 {
		t.Fatalf("logins %d, refusals %d; want 1 and 1", l.allowed.Load(), l.Rejected())
	}
}

// /auth takes only JSON: a cross-origin page cannot send it without a
// preflight nobody answers, so it cannot drive a login or logout.
func TestAuthTakesOnlyJSON(t *testing.T) {
	f := newFixture(t)
	_, srv := f.proxyListener(t)
	client := &http.Client{Transport: forwarding{http.DefaultTransport}}
	resp, err := client.Post(srv.URL+chain.AuthPath, "text/plain", strings.NewReader(`{"logout":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain /auth: %d, want 415", resp.StatusCode)
	}
}
