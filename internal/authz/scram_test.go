package authz

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/testutil"

	"github.com/lixenwraith/auth"
)

func TestMain(m *testing.M) {
	minArgonTime, minArgonMemory = 1, 64 // test verifiers use a cheap profile
	os.Exit(m.Run())
}

type fixture struct {
	pki       *testutil.PKI
	dir       string
	creds     string // credentials file holding edge-01 and edge-02
	serverTLS *tls.Config
	clientTLS *tls.Config
}

func cheapCredential(t *testing.T, user, password string) *auth.Credential {
	t.Helper()
	c, err := auth.NewCredential(user, password, auth.WithTime(1), auth.WithMemory(64), auth.WithThreads(1))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{pki: testutil.NewPKI(t, "edge-01"), dir: t.TempDir()}
	data, err := (&Credentials{
		DecoyKey: bytes.Repeat([]byte{1}, 32),
		Users:    []*auth.Credential{cheapCredential(t, "edge-01", "edge-01-secret"), cheapCredential(t, "edge-02", "edge-02-secret")},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f.creds = f.write(t, "users.toml", string(data))
	f.serverTLS = &tls.Config{Certificates: []tls.Certificate{f.keyPair(t, f.pki.ServerCert, f.pki.ServerKey)}, ClientCAs: f.pool(t)}
	f.clientTLS = &tls.Config{RootCAs: f.pool(t), ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{f.keyPair(t, f.pki.ClientCert, f.pki.ClientKey)}}
	return f
}

func (f *fixture) write(t *testing.T, name, contents string) string {
	path := filepath.Join(f.dir, name)
	testutil.WriteFile(t, path, contents)
	return path
}

func (f *fixture) keyPair(t *testing.T, cert, key string) tls.Certificate {
	kp, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// serverLeaf is another server certificate from the same CA
func (f *fixture) serverLeaf(t *testing.T, name string) tls.Certificate {
	cert, key := f.pki.Leaf(t, name, name+".internal", false)
	return f.keyPair(t, cert, key)
}

func (f *fixture) pool(t *testing.T) *x509.CertPool {
	pem, err := os.ReadFile(f.pki.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return pool
}

func (f *fixture) listener(t *testing.T, o config.AuthOptions, tlsCfg *tls.Config, role Role, transport Transport) *Policy {
	t.Helper()
	o.Type, o.CredentialsFile = MethodSCRAM, f.creds
	p, err := New(&o, tlsCfg, role, transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func (f *fixture) dialer(t *testing.T, user, password string) *Policy {
	t.Helper()
	pw := f.write(t, user+"-"+strings.ReplaceAll(password, "/", "_")+".pass", password+"\n")
	p, err := New(&config.AuthOptions{Type: MethodSCRAM, Username: user, PasswordFile: pw}, f.clientTLS, RoleDialer, TCP)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type admitted struct {
	adm *Admission
	err error
}

// connect runs a TLS pair over net.Pipe: the server side admits with
// listener and hands the admission to decide (default Accept); the client
// side greets.
func (f *fixture) connect(t *testing.T, listener *Policy, serverTLS *tls.Config, dialer *Policy, decide func(*Admission)) (admitted, *bufio.Reader, error) {
	t.Helper()
	if decide == nil {
		decide = func(a *Admission) { a.Accept() }
	}
	sc, cc := net.Pipe()
	server, client := tls.Server(sc, serverTLS), tls.Client(cc, f.clientTLS)
	// Raw ends: a tls.Conn would wait out close_notify on a pipe nobody reads
	t.Cleanup(func() { sc.Close(); cc.Close() })
	done := make(chan admitted, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			done <- admitted{err: err}
			return
		}
		cs := server.ConnectionState()
		adm, err := listener.Admit(server, &cs, true, 5*time.Second)
		if err == nil && decide != nil {
			decide(adm)
		}
		done <- admitted{adm, err}
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	r, err := dialer.Greet(t.Context(), client, "declared-node")
	if err != nil || dialer == nil || dialer.dialer == nil {
		cc.Close() // a dialer that does not read must not block the server's answer
	}
	return <-done, r, err
}

// A full TCP exchange admits the user, and bytes arriving in the same read
// as the final message reach the dialer through the reader Greet returns.
func TestTCPExchangeAdmitsAndKeepsTheStream(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleChainListener, TCP)
	res, r, err := f.connect(t, l, f.serverTLS, f.dialer(t, "edge-01", "edge-01-secret"), func(a *Admission) {
		a.final = append(a.final, "first entry\n"...) // as TCP would coalesce them
		if err := a.Accept(); err != nil {
			t.Error(err)
		}
	})
	if err != nil || res.err != nil {
		t.Fatalf("exchange: dialer %v, listener %v", err, res.err)
	}
	if res.adm.Identity != (Identity{Name: "edge-01", Method: MethodSCRAM}) || res.adm.Hello.Node != "declared-node" {
		t.Fatalf("admission = %+v / %+v", res.adm.Identity, res.adm.Hello)
	}
	line, err := r.ReadString('\n')
	if err != nil || line != "first entry\n" {
		t.Fatalf("stream after the exchange = %q, %v", line, err)
	}
}

// A wrong password and an unknown user fail identically on the wire, so a
// probe cannot tell which accounts exist.
func TestTCPExchangeRefusesWrongPasswordAndUnknownUserAlike(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, TCP)
	var seen []string
	for _, d := range []*Policy{f.dialer(t, "edge-01", "not-the-secret"), f.dialer(t, "edge-99", "edge-01-secret")} {
		res, _, err := f.connect(t, l, f.serverTLS, d, nil)
		if !errors.Is(err, ErrRefused) || !errors.Is(res.err, ErrRefused) {
			t.Fatalf("dialer %v, listener %v; want both refused", err, res.err)
		}
		seen = append(seen, err.Error())
	}
	if seen[0] != seen[1] {
		t.Fatalf("wrong password and unknown user differ: %q vs %q", seen[0], seen[1])
	}
}

// A proof bound to a certificate other than the listener's own fails, even
// though that certificate chains to the trusted CA, and the listener counts
// the mismatch so interception is not mistaken for a wrong password.
func TestTCPExchangeRefusesAnotherCertificate(t *testing.T) {
	f := newFixture(t)
	other := f.serverTLS.Clone()
	other.Certificates = []tls.Certificate{f.serverLeaf(t, "relay-b")}
	l := f.listener(t, config.AuthOptions{}, other, RoleListener, TCP) // binds to relay-b
	res, _, err := f.connect(t, l, f.serverTLS, f.dialer(t, "edge-01", "edge-01-secret"), nil)
	if !errors.Is(err, ErrRefused) || !errors.Is(res.err, ErrRefused) {
		t.Fatalf("dialer %v, listener %v; want both refused", err, res.err)
	}
	if n := l.listener.bindingMismatch.Load(); n != 1 {
		t.Fatalf("binding mismatches = %d, want 1", n)
	}
}

// A scram listener refuses a hello without credentials, and a listener
// without scram answers credentials instead of leaving the dialer waiting.
func TestHelloAndPolicyMustAgree(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleChainListener, TCP)
	if res, _, _ := f.connect(t, l, f.serverTLS, nil, nil); !errors.Is(res.err, ErrRefused) {
		t.Fatalf("scram listener admitted a plain hello: %v", res.err)
	}
	if _, _, err := f.connect(t, nil, f.serverTLS, f.dialer(t, "edge-01", "edge-01-secret"), nil); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("dialer against a plain listener: %v", err)
	}
}

// The dialer's exchange ends when its context does, so a silent server never
// holds a sink's Stop.
func TestGreetEndsWithContext(t *testing.T) {
	f := newFixture(t)
	sc, cc := net.Pipe()
	server, client := tls.Server(sc, f.serverTLS), tls.Client(cc, f.clientTLS)
	t.Cleanup(func() { sc.Close(); cc.Close() })
	go func() {
		server.Handshake()
		bufio.NewReader(server).ReadString('\n') // swallow the hello, never answer
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.dialer(t, "edge-01", "edge-01-secret").Greet(ctx, client, ""); err == nil {
		t.Fatal("Greet succeeded against a silent server")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Greet took %v after its context ended", d)
	}
}

// An exchange abandoned after its challenge leaves the auth handshake table
// and the limiter at once instead of holding a slot until it times out.
func TestAbandonedExchangeReleasesItsSlot(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, TCP)
	sc, cc := net.Pipe()
	server, client := tls.Server(sc, f.serverTLS), tls.Client(cc, f.clientTLS)
	t.Cleanup(func() { sc.Close(); cc.Close() })
	done := make(chan error, 1)
	go func() {
		server.Handshake()
		cs := server.ConnectionState()
		_, err := l.Admit(server, &cs, false, 5*time.Second)
		done <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	first, err := auth.NewScramClient("edge-01", "edge-01-secret").StartAuthentication()
	if err != nil {
		t.Fatal(err)
	}
	scram, _ := json.Marshal(first)
	hello, _ := chain.EncodeHello(chain.Hello{Scram: scram})
	client.Write(hello)
	step, err := readStep(bufio.NewReader(client))
	if err != nil || step.Challenge == nil {
		t.Fatalf("challenge: %+v, %v", step, err)
	}
	cc.Close()
	if err := <-done; err == nil {
		t.Fatal("abandoned exchange was admitted")
	}
	if _, err := l.listener.server.Load().ProcessClientFinalMessage(step.Challenge.FullNonce, "AAAA"); !errors.Is(err, auth.ErrSCRAMInvalidNonce) {
		t.Fatalf("abandoned handshake still pending: %v", err)
	}
	lim := &l.listener.limit
	lim.mu.Lock()
	defer lim.mu.Unlock()
	if pl := lim.peers["pipe"]; pl == nil || len(pl.pending) != 0 || pl.reserved != 0 {
		t.Fatalf("limiter still holds the abandoned exchange: %+v", pl)
	}
}

// A refusal after authentication, such as node binding, reaches the dialer as
// a reason and never as a final message it could take for admission.
func TestRejectAfterExchangeSendsReason(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleChainListener, TCP)
	_, _, err := f.connect(t, l, f.serverTLS, f.dialer(t, "edge-01", "edge-01-secret"), func(a *Admission) {
		a.Reject("node label rejected")
	})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "node label rejected") {
		t.Fatalf("dialer after Reject: %v", err)
	}
}

// With identity set under scram, the client certificate must name the user:
// a peer needs its own certificate and its own password, and a token works
// only with the certificate of its login.
func TestCertificateBindsToUser(t *testing.T) {
	f := newFixture(t)
	mtls := f.serverTLS.Clone()
	mtls.ClientAuth = tls.RequireAndVerifyClientCert
	l := f.listener(t, config.AuthOptions{Identity: "cn"}, mtls, RoleListener, TCP)
	if res, _, err := f.connect(t, l, mtls, f.dialer(t, "edge-01", "edge-01-secret"), nil); err != nil || res.err != nil {
		t.Fatalf("own certificate and password: dialer %v, listener %v", err, res.err)
	}
	if res, _, _ := f.connect(t, l, mtls, f.dialer(t, "edge-02", "edge-02-secret"), nil); !errors.Is(res.err, ErrRefused) {
		t.Fatalf("edge-01's certificate admitted user edge-02: %v", res.err)
	}

	h := f.listener(t, config.AuthOptions{Identity: "cn"}, mtls, RoleListener, HTTP)
	srv, _ := f.httpListener(t, h, mtls)
	d := f.dialer(t, "edge-01", "edge-01-secret")
	token, err := d.Token(t.Context(), f.httpClient(d), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	other := f.clientTLS.Clone()
	cert, key := f.pki.Leaf(t, "edge-02", "edge-02", true)
	other.Certificates = []tls.Certificate{f.keyPair(t, cert, key)}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: other}}
	resp := get(t, client, srv.URL+"/protected", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) })
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("edge-01's token with edge-02's certificate: %d, want 403", resp.StatusCode)
	}
}

// An unknown user's challenge salt comes from the file's decoy key, so it is
// the same after a restart and a prober learns nothing from restarts.
func TestUnknownUserSaltSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	var salts []string
	for range 2 {
		l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, TCP)
		c, err := l.listener.server.Load().ProcessClientFirstMessage("nobody", strings.Repeat("n", 32))
		if err != nil {
			t.Fatal(err)
		}
		salts = append(salts, c.Salt)
	}
	if salts[0] != salts[1] {
		t.Fatalf("unknown user salts differ across restarts: %q, %q", salts[0], salts[1])
	}
}

// Unauthenticated peers get 4 KiB: a longer hello line or /auth body is
// refused before it is parsed.
func TestPreAuthInputIsCapped(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, TCP)
	sc, cc := net.Pipe()
	server, client := tls.Server(sc, f.serverTLS), tls.Client(cc, f.clientTLS)
	t.Cleanup(func() { sc.Close(); cc.Close() })
	done := make(chan error, 1)
	go func() {
		server.Handshake()
		cs := server.ConnectionState()
		_, err := l.Admit(server, &cs, true, 5*time.Second)
		done <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	go client.Write(bytes.Repeat([]byte("x"), 2*maxAuthLine))
	if err := <-done; err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized hello: %v", err)
	}

	h := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	srv, _ := f.httpListener(t, h, f.serverTLS)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: f.clientTLS}}
	resp, err := hc.Post(srv.URL+chain.AuthPath, "application/json", bytes.NewReader(bytes.Repeat([]byte(" "), 2*maxAuthLine)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized /auth body: %d, want 413", resp.StatusCode)
	}
}

// A dialer refuses a challenge below its Argon2 floor before computing a
// proof, so a hostile server cannot obtain a cheaply guessable one.
func TestDialerRefusesACheapChallenge(t *testing.T) {
	f := newFixture(t) // verifiers at t=1, m=64 KiB
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, TCP)
	d := f.dialer(t, "edge-01", "edge-01-secret")
	minArgonTime, minArgonMemory = auth.DefaultArgonTime, auth.DefaultArgonMemory
	t.Cleanup(func() { minArgonTime, minArgonMemory = 1, 64 })
	if _, _, err := f.connect(t, l, f.serverTLS, d, nil); !errors.Is(err, auth.ErrSCRAMParamsTooSmall) {
		t.Fatalf("cheap challenge: %v", err)
	}
	if n := l.allowed.Load(); n != 0 {
		t.Fatalf("logins = %d, want 0", n)
	}
}

// Link-local peers share one budget per link, not one across every link: the
// zone names the link and stays in the key.
func TestLinkLocalBudgetIsPerLink(t *testing.T) {
	a, b, other := throttleKey("fe80::1%eth0"), throttleKey("fe80::2%eth0"), throttleKey("fe80::1%eth1")
	if a != b || a == other {
		t.Fatalf("keys %q, %q on one link, %q on another", a, b, other)
	}
}

// Only failed attempts drain an address's budget; beyond it the listener
// answers "too many attempts" without running the exchange.
func TestOnlyFailedAttemptsAreThrottled(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, TCP)
	right := f.dialer(t, "edge-01", "edge-01-secret")
	for i := range limitBurst + 1 {
		if _, _, err := f.connect(t, l, f.serverTLS, right, nil); err != nil {
			t.Fatalf("successful login %d: %v", i, err)
		}
	}
	wrong := f.dialer(t, "edge-01", "not-the-secret")
	for range limitBurst {
		f.connect(t, l, f.serverTLS, wrong, nil)
	}
	_, _, err := f.connect(t, l, f.serverTLS, right, nil)
	if err == nil || !strings.Contains(err.Error(), "too many attempts") || l.listener.throttled.Load() != 1 {
		t.Fatalf("attempt over budget: %v, throttled %d", err, l.listener.throttled.Load())
	}
}

// Successes are refunded; unfinished exchanges are capped per address from
// the moment they start, so concurrent hellos cannot all pass; a full table
// refuses new addresses, and the sweep frees addresses whose challenges were
// abandoned.
func TestLimiterBounds(t *testing.T) {
	var l limiter
	for i := range 2 * limitBurst {
		if !l.start("10.0.0.1") {
			t.Fatalf("successful attempt %d throttled", i)
		}
		l.track("10.0.0.1", "n")
		l.done("10.0.0.1", "n")
		l.succeeded("10.0.0.1")
	}
	for i := range limitPending {
		if !l.start("10.0.0.2") {
			t.Fatalf("pending exchange %d throttled", i)
		}
	}
	if l.start("10.0.0.2") {
		t.Fatal("an exchange beyond the pending cap was admitted before any challenge")
	}
	l.release("10.0.0.2")
	if !l.start("10.0.0.2") {
		t.Fatal("a released reservation still counts")
	}
	for i := len(l.peers); i < limitPeers; i++ {
		l.peers[net.IPv4(10, 1, byte(i>>8), byte(i)).String()] = &peerLimit{
			seen: time.Now(), pending: map[string]time.Time{"abandoned": time.Now().Add(time.Second)},
		}
	}
	if l.start("192.0.2.1") {
		t.Fatal("a full table admitted a new address")
	}
	l.sweep(time.Now().Add(2 * limitIdle))
	if len(l.peers) != 1 { // 10.0.0.2 still holds its reservations
		t.Fatalf("%d addresses left after their challenges expired, want 1", len(l.peers))
	}
}

// httpListener serves /auth and one protected endpoint over TLS
func (f *fixture) httpListener(t *testing.T, p *Policy, tlsCfg *tls.Config) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+chain.AuthPath, func(w http.ResponseWriter, r *http.Request) { p.ServeAuth(w, r) })
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if _, status, err := p.AuthorizeRequest(r); err != nil {
			Refuse(w, status)
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &hits
}

func (f *fixture) httpClient(d *Policy) *http.Client {
	cfg := f.clientTLS.Clone()
	cfg.VerifyConnection = d.VerifyConnection
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func get(t *testing.T, client *http.Client, url string, prepare func(*http.Request)) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	prepare(req)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// A login over HTTP yields a bearer token the endpoint accepts; a garbage
// token, or one another listener instance issued, gets 401 and a challenge
// header; a refused token can be dropped and replaced by a fresh login.
func TestHTTPTokenFlow(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	srv, _ := f.httpListener(t, l, f.serverTLS)
	d := f.dialer(t, "edge-01", "edge-01-secret")
	client := f.httpClient(d)

	resp := get(t, client, srv.URL+"/protected", func(r *http.Request) {
		if err := d.Prepare(t.Context(), client, srv.URL, r); err != nil {
			t.Fatal(err)
		}
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with a token: %d", resp.StatusCode)
	}
	other := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	foreignSrv, _ := f.httpListener(t, other, f.serverTLS)
	foreign, err := f.dialer(t, "edge-01", "edge-01-secret").Token(t.Context(), f.httpClient(d), foreignSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for name, header := range map[string]string{"garbage": "Bearer not-a-token", "foreign": "Bearer " + foreign, "missing": ""} {
		resp := get(t, client, srv.URL+"/protected", func(r *http.Request) { r.Header.Set("Authorization", header) })
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s token: %d %q", name, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}
	logins := l.allowed.Load()
	if !d.Invalidate(http.StatusUnauthorized, nil) || d.dialer.token.Load() != nil {
		t.Fatal("a refused token was not dropped")
	}
	resp = get(t, client, srv.URL+"/protected", func(r *http.Request) { d.Prepare(t.Context(), client, srv.URL, r) })
	if resp.StatusCode != http.StatusOK || l.allowed.Load() != logins+1 {
		t.Fatalf("after Invalidate: %d, logins %d -> %d", resp.StatusCode, logins, l.allowed.Load())
	}
}

// A server that cannot sign the final message with the user's verifier gets
// no token stored, whatever token it offers.
func TestForgedFinalYieldsNoToken(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+chain.AuthPath, func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		body.ReadFrom(r.Body)
		if bytes.Contains(body.Bytes(), []byte(`"proof"`)) {
			writeJSON(w, http.StatusOK, authStep{Final: &auth.ServerFinalMessage{ServerSignature: "AAAA"}, Token: "forged"})
			return
		}
		r.Body = io.NopCloser(body)
		l.ServeAuth(w, r)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = f.serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	d := f.dialer(t, "edge-01", "edge-01-secret")
	if _, err := d.Token(t.Context(), f.httpClient(d), srv.URL); err == nil {
		t.Fatal("forged final accepted")
	}
	if d.dialer.token.Load() != nil {
		t.Fatal("token stored from a forged final")
	}
}

// After the first answer every connection must present the bound certificate:
// a second, equally CA-valid server never sees the proof, unbound logins
// (through a proxy) included.
func TestPinnedCertificateAcrossConnections(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	a, _ := f.httpListener(t, l, f.serverTLS)
	otherTLS := f.serverTLS.Clone()
	otherTLS.Certificates = []tls.Certificate{f.serverLeaf(t, "relay-b")}
	b, bHits := f.httpListener(t, l, otherTLS)

	for _, unbound := range []bool{false, true} {
		d := f.dialer(t, "edge-01", "edge-01-secret")
		if unbound {
			d.Unbind()
		}
		client := f.httpClient(d)
		var dials atomic.Int64
		tr := client.Transport.(*http.Transport)
		tr.DisableKeepAlives = true
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			target := a.Listener.Addr().String()
			if dials.Add(1) > 1 {
				target = b.Listener.Addr().String() // every later connection lands on b
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		}
		_, err := d.Token(t.Context(), client, a.URL)
		if !errors.Is(err, errPinMismatch) {
			t.Fatalf("unbound %v: login across certificates: %v", unbound, err)
		}
		if !d.Invalidate(0, err) {
			t.Fatalf("unbound %v: a pin mismatch did not drop the login", unbound)
		}
	}
	if bHits.Load() != 0 || l.allowed.Load() != 0 {
		t.Fatal("the proof reached a server with another certificate")
	}
}

// A hello refused after it was admitted, such as a malformed username, frees
// its pending slot: otherwise four of them would lock the address out.
func TestRefusedHellosFreeTheirSlot(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	srv, _ := f.httpListener(t, l, f.serverTLS)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: f.clientTLS}}
	hello := func(user string) int {
		body := fmt.Sprintf(`{"logwisp":1,"scram":{"username":%q,"client_nonce":%q}}`, user, strings.Repeat("n", 32))
		resp, err := client.Post(srv.URL+chain.AuthPath, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for range limitPending + 1 {
		if got := hello("edge,01"); got != http.StatusBadRequest {
			t.Fatalf("malformed username: %d, want 400", got)
		}
	}
	if got := hello("edge-01"); got != http.StatusOK {
		t.Fatalf("a valid hello after refused ones: %d, want 200", got)
	}
}

// Password files from editors and from the CLI read the same.
func TestReadPasswordTrimsOneLineBreak(t *testing.T) {
	f := newFixture(t)
	for _, contents := range []string{"secret", "secret\n", "secret\r\n"} {
		if pw, err := ReadPassword(f.write(t, "pw", contents)); err != nil || pw != "secret" {
			t.Errorf("ReadPassword(%q) = %q, %v", contents, pw, err)
		}
	}
	if _, err := ReadPassword(f.write(t, "pw", "\n")); err == nil {
		t.Error("an empty password was accepted")
	}
}

// A credentials file is validated whole, and Marshal round-trips. Each case
// breaks one rule of an otherwise valid file.
func TestCredentialsFileValidation(t *testing.T) {
	f := newFixture(t)
	data, err := os.ReadFile(f.creds)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCredentials(data)
	if err != nil || len(c.Users) != 2 || c.Users[1].Username != "edge-02" {
		t.Fatalf("round trip: %+v, %v", c, err)
	}
	valid := string(data)
	decoyLine := regexp.MustCompile(`(?m)^decoy_key = .*\n`)
	stronger := cheapCredential(t, "edge-03", "edge-03-secret")
	stronger.ArgonTime = 2
	mixed, _ := (&Credentials{DecoyKey: c.DecoyKey, Users: []*auth.Credential{c.Users[0], stronger}}).Marshal()
	for name, tc := range map[string]struct{ contents, want string }{
		"no decoy key":     {decoyLine.ReplaceAllString(valid, ""), "decoy_key must hold"},
		"short decoy":      {decoyLine.ReplaceAllString(valid, "decoy_key = \"AAAA\"\n"), "decoy_key must hold"},
		"no users":         {decoyLine.FindString(valid), "no users"},
		"duplicate":        {strings.Replace(valid, `"edge-02"`, `"edge-01"`, 1), "duplicate user"},
		"unknown user key": {strings.Replace(valid, "argon_time", "comment = 1\nargon_time", 1), `unknown key "comment"`},
		"unknown file key": {"comment = 1\n" + valid, `unknown key "comment"`},
		"mixed profile":    {string(mixed), "profile differs"},
	} {
		if _, err := ParseCredentials([]byte(tc.contents)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", name, err, tc.want)
		}
	}
}

// A scram listener's Authorize refuses, so a call site that skipped the
// exchange admits nobody rather than everybody.
func TestScramListenerAuthorizeFailsClosed(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{}, f.serverTLS, RoleListener, HTTP)
	if _, err := l.Authorize(&tls.ConnectionState{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("Authorize under scram = %v, want a refusal", err)
	}
}

// A token is renewed ahead of its expiry, so a healthy link never pays a
// refused request each lifetime.
func TestTokenIsRenewedBeforeExpiry(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{TokenLifetimeMS: MinTokenLifetime.Milliseconds()}, f.serverTLS, RoleListener, HTTP)
	srv, _ := f.httpListener(t, l, f.serverTLS)
	d := f.dialer(t, "edge-01", "edge-01-secret")
	client := f.httpClient(d)
	prepare := func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
		if err := d.Prepare(t.Context(), client, srv.URL, req); err != nil {
			t.Fatal(err)
		}
	}
	prepare()
	prepare()
	if n := l.allowed.Load(); n != 1 {
		t.Fatalf("logins within the lifetime = %d, want 1", n)
	}
	ahead := time.Until(time.Unix(0, d.dialer.renewAt.Load()))
	if ahead <= 0 || ahead > MinTokenLifetime-5*time.Second {
		t.Fatalf("renewal scheduled %v ahead, want within lifetime - 5 s", ahead)
	}
	d.dialer.renewAt.Store(time.Now().UnixNano()) // the renewal point arrives
	prepare()
	if n := l.allowed.Load(); n != 2 {
		t.Fatalf("logins after the renewal point = %d, want 2", n)
	}
}

// A renewal put off (throttled, or the server busy) keeps the link sending on
// the token it still holds, and retries soon, but only to the pinned server;
// any other refusal, or the token's expiry, ends it.
func TestPutOffRenewalKeepsTheValidToken(t *testing.T) {
	f := newFixture(t)
	l := f.listener(t, config.AuthOptions{TokenLifetimeMS: MinTokenLifetime.Milliseconds()}, f.serverTLS, RoleListener, HTTP)
	srv, _ := f.httpListener(t, l, f.serverTLS)
	// An impostor with another certificate of the same CA
	var answer, stolen atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+chain.AuthPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, int(answer.Load()), authStep{Error: "no"})
	})
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) { stolen.Add(1) })
	imp := httptest.NewUnstartedServer(mux)
	imp.TLS = f.serverTLS.Clone()
	imp.TLS.Certificates = []tls.Certificate{f.serverLeaf(t, "impostor")}
	imp.StartTLS()
	t.Cleanup(imp.Close)

	d := f.dialer(t, "edge-01", "edge-01-secret")
	client := f.httpClient(d)
	var reroute atomic.Pointer[string]
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if to := reroute.Load(); to != nil {
			addr = *to
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	prepare := func(renew bool) (*http.Request, error) {
		if renew {
			d.dialer.renewAt.Store(time.Now().UnixNano())
		}
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
		return req, d.Prepare(t.Context(), client, srv.URL, req)
	}
	held := func() string {
		req, err := prepare(false)
		if err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Authorization")
	}

	first := held()
	client.CloseIdleConnections()
	to := imp.Listener.Addr().String()
	reroute.Store(&to)
	answer.Store(http.StatusTooManyRequests)
	req, err := prepare(true)
	if err != nil || req.Header.Get("Authorization") != first {
		t.Fatalf("put-off renewal: header %q, %v; want the held token", req.Header.Get("Authorization"), err)
	}
	if ahead := time.Until(time.Unix(0, d.dialer.renewAt.Load())); ahead <= 0 || ahead > 5*time.Second {
		t.Fatalf("next renewal %v ahead, want within 5 s", ahead)
	}
	if _, err := client.Do(req); !errors.Is(err, errPinMismatch) || stolen.Load() != 0 {
		t.Fatalf("the held token went to a server the pin never checked: %v, %d requests", err, stolen.Load())
	}
	answer.Store(http.StatusUnauthorized)
	if _, err := prepare(true); err == nil || d.dialer.token.Load() != nil {
		t.Fatalf("a refused renewal kept the token: %v", err)
	}

	client.CloseIdleConnections()
	reroute.Store(nil)
	first = held()
	l.Close() // every further login answers busy
	if req, err := prepare(true); err != nil || req.Header.Get("Authorization") != first {
		t.Fatalf("busy renewal: %v; want the held token", err)
	}
	d.dialer.expires.Store(time.Now().UnixNano())
	if _, err := prepare(true); err == nil {
		t.Fatal("an expired token was kept after a put-off renewal")
	}
}
