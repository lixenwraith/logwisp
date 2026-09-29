package http

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"logwisp/internal/sink"
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
