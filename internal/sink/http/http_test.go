package http

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"logwisp/internal/authz"
	"logwisp/internal/sink"
	"logwisp/internal/testutil"

	"github.com/lixenwraith/auth"
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
	caPEM, err := os.ReadFile(pki.CA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	clientCert, err := tls.LoadX509KeyPair(pki.ClientCert, pki.ClientKey)
	if err != nil {
		t.Fatal(err)
	}

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
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}}}
			baseURL = "https" + strings.TrimPrefix(baseURL, "http")
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
	cred, err := auth.NewCredential("viewer-01", "viewer-01-secret")
	if err != nil {
		t.Fatal(err)
	}
	data, err := (&authz.Credentials{DecoyKey: make([]byte, 32), Users: []*auth.Credential{cred}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	creds := t.TempDir() + "/users.toml"
	testutil.WriteFile(t, creds, string(data))
	gated, _ := newTestHTTPSink(t, map[string]any{
		"tls":  map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey},
		"auth": map[string]any{"type": "scram", "credentials_file": creds},
	})
	client, baseURL := serveTestHTTPSink(t, gated)
	caPEM, err := os.ReadFile(pki.CA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	baseURL = "https" + strings.TrimPrefix(baseURL, "http")

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
