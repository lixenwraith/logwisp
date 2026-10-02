package httpchain

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"logwisp/internal/session"

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
