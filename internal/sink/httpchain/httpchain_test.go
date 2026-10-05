package httpchain

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/session"
	ingest "github.com/lixenwraith/logwisp/internal/source/httpchain"
	"github.com/lixenwraith/logwisp/internal/testutil"

	"github.com/lixenwraith/auth"
	"github.com/lixenwraith/log"
)

// A redirect is never followed: it would resend the batch wherever the
// response points, plaintext http included.
func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusPermanentRedirect)
	}))
	t.Cleanup(redirector.Close)

	host, port, err := net.SplitHostPort(redirector.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.ParseInt(port, 10, 64)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewHTTPChainSinkPlugin("fwd", map[string]any{"host": host, "port": p},
		log.NewLogger(), session.NewProxy(manager, "fwd"))
	if err != nil {
		t.Fatal(err)
	}
	transient, err := created.(*HTTPChainSink).post(t.Context(), []byte("{}\n"))
	if err == nil || transient {
		t.Fatalf("post = (transient %v, %v), want a permanent error", transient, err)
	}
	if leaked.Load() {
		t.Fatal("the batch followed the redirect")
	}
}

// Under scram a 401 on ingest (an expired token, a reloaded source) logs in
// again, and the held batch is delivered exactly once.
func TestRefusedTokenLogsInAgainAndDeliversOnce(t *testing.T) {
	pki := testutil.NewPKI(t, "edge-01")
	dir := t.TempDir()
	cred, err := auth.NewCredential("edge-01", "edge-01-secret")
	if err != nil {
		t.Fatal(err)
	}
	data, err := (&authz.Credentials{DecoyKey: make([]byte, 32), Users: []*auth.Credential{cred}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	creds, password := filepath.Join(dir, "users.toml"), filepath.Join(dir, "edge-01.pass")
	testutil.WriteFile(t, creds, string(data))
	testutil.WriteFile(t, password, "edge-01-secret\n")

	serverCert, err := tls.LoadX509KeyPair(pki.ServerCert, pki.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{serverCert}}
	listener, err := authz.New(&config.AuthOptions{Type: authz.MethodSCRAM, CredentialsFile: creds}, serverTLS, nil, authz.RoleChainListener, authz.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(listener.Close)

	var refused, delivered atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+chain.AuthPath, func(w http.ResponseWriter, r *http.Request) { listener.ServeAuth(w, r) })
	mux.HandleFunc("POST /ingest", func(w http.ResponseWriter, r *http.Request) {
		if _, status, err := listener.AuthorizeRequest(r); err != nil {
			authz.Refuse(w, status)
			return
		}
		if refused.Add(1) == 1 {
			authz.Refuse(w, http.StatusUnauthorized) // as after a reload
			return
		}
		delivered.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.ParseInt(port, 10, 64)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewHTTPChainSinkPlugin("fwd", map[string]any{
		"host": "127.0.0.1", "port": p, "backoff_min_ms": int64(10),
		"tls":  map[string]any{"enabled": true, "ca_file": pki.CA},
		"auth": map[string]any{"type": "scram", "username": "edge-01", "password_file": password},
	}, log.NewLogger(), session.NewProxy(manager, "fwd"))
	if err != nil {
		t.Fatal(err)
	}
	sink := created.(*HTTPChainSink)
	sink.append(core.TransportEvent{Time: time.Now(), Payload: []byte("entry")})
	sink.flush(t.Context())
	if delivered.Load() != 1 || sink.droppedBatches.Load() != 0 {
		t.Fatalf("delivered %d, dropped %d", delivered.Load(), sink.droppedBatches.Load())
	}
	if logins := listener.Stats()["auth_allowed"]; logins != uint64(2) {
		t.Fatalf("logins = %v, want 2", logins)
	}
}

// The target URL brackets an IPv6 host and escapes its zone: a URL built
// from the raw host could not even form a request.
func TestTargetURLBracketsAnIPv6Host(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	for host, want := range map[string]string{
		"::1":          "http://[::1]:9000/ingest",
		"fe80::1%eth0": "http://[fe80::1%25eth0]:9000/ingest",
	} {
		created, err := NewHTTPChainSinkPlugin("fwd", map[string]any{"host": host, "port": int64(9000)},
			log.NewLogger(), session.NewProxy(manager, "fwd"))
		if err != nil {
			t.Fatal(err)
		}
		if got := created.(*HTTPChainSink).url; got != want {
			t.Errorf("host %q: target %q, want %q", host, got, want)
		}
	}
}

// A link runs over the IPv6 loopback with TLS: the source binds ::1, and the
// sink dials it and verifies the certificate's ::1 address.
func TestLinkOverIPv6LoopbackWithTLS(t *testing.T) {
	testutil.RequireIPv6(t)
	pki := testutil.NewPKI(t, "edge-01")
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	probe.Close()
	p, _ := strconv.ParseInt(port, 10, 64)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)

	src, err := ingest.NewHTTPChainSourcePlugin("in", map[string]any{
		"host": "::1", "port": p,
		"tls": map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey},
	}, log.NewLogger(), session.NewProxy(manager, "in"))
	if err != nil {
		t.Fatal(err)
	}
	entries := src.Subscribe()
	if err := src.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Stop)

	created, err := NewHTTPChainSinkPlugin("fwd", map[string]any{
		"host": "::1", "port": p,
		"tls": map[string]any{"enabled": true, "ca_file": pki.CA},
	}, log.NewLogger(), session.NewProxy(manager, "fwd"))
	if err != nil {
		t.Fatal(err)
	}
	sink := created.(*HTTPChainSink)
	sink.append(core.TransportEvent{Time: time.Now(), Payload: []byte("over IPv6")})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	sink.flush(ctx)
	if sink.droppedBatches.Load() != 0 {
		t.Fatalf("batch not delivered: %d request errors", sink.requestErrors.Load())
	}
	select {
	case e := <-entries:
		if e.Message != "over IPv6" {
			t.Fatalf("message %q", e.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the source published nothing")
	}
}

// Stop delivers what is queued and batched, so the end of a finite input
// reaches the source whole, and returns at the flush bound when the source
// stops answering.
func TestStopDeliversTheQueueWithinTheBound(t *testing.T) {
	const n = 250 // three batches of the default 100
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	// stop queues n entries, starts and stops a sink, and returns how long
	// Stop took and how many entries an answering source received
	stop := func(answering bool) (time.Duration, int64) {
		var received atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if !answering {
				<-r.Context().Done() // the sink gave up
				return
			}
			received.Add(int64(bytes.Count(body, []byte("\n"))))
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		p, _ := strconv.ParseInt(port, 10, 64)
		created, err := NewHTTPChainSinkPlugin("fwd", map[string]any{"host": "127.0.0.1", "port": p},
			log.NewLogger(), session.NewProxy(manager, "fwd"))
		if err != nil {
			t.Fatal(err)
		}
		sink := created.(*HTTPChainSink)
		for range n {
			sink.Input() <- core.TransportEvent{Time: time.Now(), Payload: []byte("entry")}
		}
		if err := sink.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		sink.Stop()
		return time.Since(start), received.Load()
	}
	if _, got := stop(true); got != n {
		t.Fatalf("the source received %d of %d entries", got, n)
	}
	if d, _ := stop(false); d > 3500*time.Millisecond {
		t.Fatalf("Stop took %v past a 2 s flush bound", d)
	}
}
