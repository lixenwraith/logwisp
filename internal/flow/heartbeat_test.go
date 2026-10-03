package flow

import (
	"bytes"
	"testing"
	"time"

	"logwisp/internal/config"
	"logwisp/internal/format"
)

// include_timestamp = false drops the timestamp the formatter shows by default
func TestHeartbeatTimestampFollowsIncludeTimestamp(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, include := range []bool{false, true} {
		f, err := format.NewFormatter(&config.FormatConfig{Type: "txt"})
		if err != nil {
			t.Fatal(err)
		}
		hg, err := NewHeartbeatGenerator(&config.HeartbeatConfig{Enabled: true, IncludeTimestamp: include}, f, nil)
		if err != nil {
			t.Fatal(err)
		}
		payload := hg.generateHeartbeat(at).Payload
		if got := bytes.Contains(payload, []byte("2026-01-02")); got != include {
			t.Errorf("include_timestamp=%v: payload %q", include, payload)
		}
	}
}
