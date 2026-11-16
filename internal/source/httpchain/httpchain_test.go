package httpchain

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/session"

	"github.com/lixenwraith/log"
)

// A batch is published whole or not at all: a line over 1 MiB (400) or a body
// over max_body_bytes (413) publishes nothing, a malformed line is skipped
func TestBatchIsPublishedWholeOrNotAtAll(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.ParseInt(port, 10, 64)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewHTTPChainSourcePlugin("in", map[string]any{"host": "127.0.0.1", "port": p, "max_body_bytes": int64(2 << 20)},
		log.NewLogger(), session.NewProxy(manager, "in"))
	if err != nil {
		t.Fatal(err)
	}
	src := created.(*HTTPChainSource)
	entries := src.Subscribe()
	if err := src.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Stop)
	good := `{"msg":"a"}` + "\n" + `{"msg":"b"}` + "\r\n"
	for _, c := range []struct {
		body           string
		status, posted int
	}{
		{good + `not json` + "\n" + `{"msg":"c"}`, http.StatusNoContent, 3},
		{good + `{"msg":"` + strings.Repeat("x", core.MaxLogEntryBytes) + `"}` + "\n", http.StatusBadRequest, 0},
		{good + strings.Repeat(`{"msg":"padding to pass the body cap"}`+"\n", 60000), http.StatusRequestEntityTooLarge, 0},
	} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/ingest", strings.NewReader(c.body))
		req.Header.Set(chain.HeaderProtocol, strconv.Itoa(chain.ProtocolVersion))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.status || len(entries) != c.posted {
			t.Fatalf("%d-byte batch: status %d with %d entries published, want %d with %d",
				len(c.body), resp.StatusCode, len(entries), c.status, c.posted)
		}
		for range c.posted {
			if e := <-entries; !bytes.Contains([]byte("abc"), []byte(e.Message)) {
				t.Fatalf("published %q", e.Message)
			}
		}
	}
	if n := src.parseErrors.Load(); n != 1 {
		t.Fatalf("%d parse errors, want 1", n)
	}
}

// The bodies being read are bounded together, 64 of max_body_bytes: a batch
// past the bound gets 503 while the others are held, and those arrive whole
func TestBodiesInFlightAreBoundedTogether(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.ParseInt(port, 10, 64)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewHTTPChainSourcePlugin("in", map[string]any{"host": "127.0.0.1", "port": p, "max_body_bytes": int64(1000)},
		log.NewLogger(), session.NewProxy(manager, "in"))
	if err != nil {
		t.Fatal(err)
	}
	src := created.(*HTTPChainSource)
	src.Subscribe()
	if err := src.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Stop)
	line := append(bytes.Repeat([]byte("x"), 997), '\n') // not JSON: the count of bytes is what matters
	post := func(body io.Reader) int {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/ingest", body)
		req.Header.Set(chain.HeaderProtocol, strconv.Itoa(chain.ProtocolVersion))
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	finish, held := make(chan struct{}), make(chan int, bodiesInFlight)
	for range bodiesInFlight {
		go func() {
			body, w := io.Pipe()
			go func() {
				w.Write(line[:len(line)-1]) // held one byte short of its end
				<-finish
				w.Write(line[len(line)-1:])
				w.Close()
			}()
			held <- post(body)
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); src.inFlight.Load() < bodiesInFlight*int64(len(line)-1); {
		if time.Sleep(time.Millisecond); time.Now().After(deadline) {
			t.Fatalf("%d bytes in flight, want the %d held", src.inFlight.Load(), bodiesInFlight*(len(line)-1))
		}
	}
	if status := post(bytes.NewReader(line)); status != http.StatusServiceUnavailable {
		t.Fatalf("a batch past the bound got %d, want 503", status)
	}
	close(finish)
	for range bodiesInFlight {
		if status := <-held; status != http.StatusNoContent {
			t.Fatalf("a batch within the bound got %d, want 204", status)
		}
	}
	if n := src.inFlight.Load(); n != 0 {
		t.Fatalf("%d bytes still counted in flight", n)
	}
}

// The session cache drops the keys of sessions the manager has expired, not
// keeping one per address a sender ever came from
func TestExpiredSessionsLeaveTheCache(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	proxy := session.NewProxy(manager, "in")
	src := &HTTPChainSource{proxy: proxy, sessions: map[string]string{}}
	for i := range 1000 {
		proxy.RemoveSession(src.sessionFor("10.0.0."+strconv.Itoa(i), "edge", "", nil, authz.Identity{})) // as idle expiry does
	}
	if n := len(src.sessions); n > 64 {
		t.Fatalf("%d keys cached for no live session", n)
	}
}

// The cache holds maxSessions sessions: a sender past them is served without
// one, however many addresses it comes from, until some expire
func TestTheSessionCacheIsBounded(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	proxy := session.NewProxy(manager, "in")
	src := &HTTPChainSource{proxy: proxy, sessions: map[string]string{}}
	addr := func(i int) string {
		return "10." + strconv.Itoa(i>>16) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255)
	}
	for i := range maxSessions + 100 {
		src.sessionFor(addr(i), "edge", "", nil, authz.Identity{})
	}
	first := src.sessionFor(addr(0), "edge", "", nil, authz.Identity{})
	if n := manager.GetSessionCount(); n != maxSessions || len(src.sessions) != maxSessions || first == "" {
		t.Fatalf("%d sessions, %d keys, the first sender's %q; want %d of each and a session", n, len(src.sessions), first, maxSessions)
	}
	proxy.RemoveSession(first) // as idle expiry does
	src.swept = time.Now().Add(-2 * time.Minute)
	if src.sessionFor("192.0.2.1", "edge", "", nil, authz.Identity{}) == "" {
		t.Fatal("no session for a new sender once one expired")
	}
}

// A session is one address and identity: the node labels a sender declares
// share it, another identity at the address gets its own
func TestSessionIsOneAddressAndIdentity(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	src := &HTTPChainSource{proxy: session.NewProxy(manager, "in"), sessions: map[string]string{}}
	first := src.sessionFor("192.0.2.1", "edge-1", "", nil, authz.Identity{Name: "a"})
	if src.sessionFor("192.0.2.1", "edge-2", "", nil, authz.Identity{Name: "a"}) != first ||
		src.sessionFor("192.0.2.1", "edge-1", "", nil, authz.Identity{Name: "b"}) == first {
		t.Fatal("a session follows the node label, or two identities share one")
	}
}

// A batch whose handler outlives Stop is refused with 503, which the sink
// retries, instead of being sent on a closed subscriber channel
func TestBatchAfterStopIsRefused(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewHTTPChainSourcePlugin("in", map[string]any{"host": "127.0.0.1", "port": int64(1)},
		log.NewLogger(), session.NewProxy(manager, "in"))
	if err != nil {
		t.Fatal(err)
	}
	src := created.(*HTTPChainSource)
	entries := src.Subscribe()
	src.Stop()
	req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(`{"msg":"late"}`+"\n"))
	req.Header.Set(chain.HeaderProtocol, strconv.Itoa(chain.ProtocolVersion))
	rec := httptest.NewRecorder()
	src.handleIngest(rec, req)
	if _, open := <-entries; open || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d after Stop, want %d with nothing published", rec.Code, http.StatusServiceUnavailable)
	}
}
