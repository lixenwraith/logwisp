package http

import (
	"context"
	"maps"
	"net"
	"net/http"
	"testing"
	"time"

	"logwisp/internal/session"

	"github.com/lixenwraith/log"
)

func newTestHTTPSink(t *testing.T, overrides map[string]any) (*HTTPSink, *session.Manager) {
	t.Helper()
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	opts := map[string]any{"host": "127.0.0.1", "port": int64(8081), "write_timeout_ms": int64(5000)}
	maps.Copy(opts, overrides)
	created, err := NewHTTPSinkPlugin("stream", opts, log.NewLogger(), session.NewProxy(manager, "stream"))
	if err != nil {
		t.Fatal(err)
	}
	h, ok := created.(*HTTPSink)
	if !ok {
		t.Fatalf("sink type = %T", created)
	}
	return h, manager
}

func serveTestHTTPSink(t *testing.T, h *HTTPSink) (*http.Client, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() { cancel(); h.Stop() })
	if err := h.serve(ctx, listener); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return client, "http://" + listener.Addr().String()
}
