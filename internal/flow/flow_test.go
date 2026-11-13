package flow

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/log"
)

var benchEntry = core.LogEntry{
	Time:    time.Date(2026, 11, 13, 1, 2, 3, 456789000, time.UTC),
	Source:  "app.log",
	Level:   "INFO",
	Message: "GET /api/v1/users/42 200 1.2ms user=alice request_id=7f3a9c2e",
	RawSize: 64,
}

// BenchmarkProcess is the flow's cost per entry, by its stages
func BenchmarkProcess(b *testing.B) {
	fielded := benchEntry
	fielded.Node = "edge-1"
	fielded.Fields = json.RawMessage(`{"user":"alice","status":200,"latency_ms":1.2,"path":"/api/v1/users/42","ok":true}`)
	filters := []config.FilterConfig{
		{Type: config.FilterTypeInclude, Patterns: []string{"ERROR", "WARN", "GET /api"}},
		{Type: config.FilterTypeExclude, Patterns: []string{"healthz", "metrics"}},
	}
	cases := []struct {
		name  string
		cfg   config.FlowConfig
		entry core.LogEntry
	}{
		{"raw", config.FlowConfig{Format: &config.FormatConfig{Type: "raw"}}, benchEntry},
		{"txt", config.FlowConfig{Format: &config.FormatConfig{Type: "txt"}}, benchEntry},
		{"json", config.FlowConfig{Format: &config.FormatConfig{Type: "json"}}, benchEntry},
		{"json-fields", config.FlowConfig{Format: &config.FormatConfig{Type: "json"}}, fielded},
		{"txt-filters", config.FlowConfig{Format: &config.FormatConfig{Type: "txt"}, Filters: filters}, benchEntry},
		{"txt-rate", config.FlowConfig{Format: &config.FormatConfig{Type: "txt"},
			RateLimit: &config.RateLimitConfig{EntriesPerSecond: 1e12, Policy: "drop", MaxEntrySizeBytes: 1 << 20}}, benchEntry},
	}
	for _, c := range cases {
		f, err := NewFlow(&c.cfg, log.NewLogger())
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, stage, _ := f.Process(c.entry); stage != "" {
					b.Fatal(stage)
				}
			}
		})
		// Sources share their pipeline's flow, one goroutine each
		b.Run(c.name+"-parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					f.Process(c.entry)
				}
			})
		})
	}
}
