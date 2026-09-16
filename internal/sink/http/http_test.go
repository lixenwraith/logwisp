package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"logwisp/internal/session"
	"logwisp/internal/sink"

	"github.com/lixenwraith/log"
)

func TestStatusReportsQueueAndConnectionBounds(t *testing.T) {
	manager := session.NewManager(time.Hour)
	defer manager.Stop()
	created, err := NewHTTPSinkPlugin(
		"stream",
		map[string]any{
			"host":               "127.0.0.1",
			"port":               int64(8081),
			"buffer_size":        int64(4096),
			"client_buffer_size": int64(512),
			"max_connections":    int64(32),
			"write_timeout_ms":   int64(5000),
		},
		log.NewLogger(),
		session.NewProxy(manager, "stream"),
	)
	if err != nil {
		t.Fatal(err)
	}
	httpSink, ok := created.(*HTTPSink)
	if !ok {
		t.Fatalf("sink type = %T", created)
	}

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
	manager := session.NewManager(time.Hour)
	defer manager.Stop()
	created, err := NewHTTPSinkPlugin(
		"stream",
		map[string]any{"host": "127.0.0.1", "port": int64(18191), "write_timeout_ms": int64(5000)},
		log.NewLogger(),
		session.NewProxy(manager, "stream"),
	)
	if err != nil {
		t.Fatal(err)
	}
	httpSink := created.(*HTTPSink)
	httpSink.keepalive = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := httpSink.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer httpSink.Stop()

	resp, err := http.Get("http://127.0.0.1:18191/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	activity := func() time.Time {
		for _, s := range manager.GetActiveSessions() {
			return s.LastActivity
		}
		t.Fatal("no session for the connected client")
		return time.Time{}
	}

	deadline := time.Now().Add(2 * time.Second)
	for activity().IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	before := activity()

	// No events are sent for several keepalive periods.
	time.Sleep(350 * time.Millisecond)
	if after := activity(); !after.After(before) {
		t.Fatalf("last activity %v did not advance on a silent stream", after)
	}
}
