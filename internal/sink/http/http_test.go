package http

import (
	"encoding/json"
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
