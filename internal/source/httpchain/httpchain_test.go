package httpchain

import (
	"bytes"
	"net"
	"net/http"
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

// The session cache drops the keys of sessions the manager has expired, not
// keeping one per label a sender ever declared
func TestExpiredSessionsLeaveTheCache(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	proxy := session.NewProxy(manager, "in")
	src := &HTTPChainSource{proxy: proxy, sessions: map[string]string{}}
	for i := range 1000 {
		proxy.RemoveSession(src.sessionFor("192.0.2.1", "edge-"+strconv.Itoa(i), "", nil, authz.Identity{})) // as idle expiry does
	}
	if n := len(src.sessions); n > 64 {
		t.Fatalf("%d keys cached for no live session", n)
	}
}
