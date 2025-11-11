// FILE: src/internal/flow/heartbeat.go
package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/lixenwraith/log"
)

// HeartbeatGenerator produces periodic heartbeat events
type HeartbeatGenerator struct {
	config    *config.HeartbeatConfig
	logger    *log.Logger
	beatCount atomic.Uint64
	lastBeat  atomic.Value // time.Time
}

// NewHeartbeatGenerator creates a new heartbeat generator
func NewHeartbeatGenerator(cfg *config.HeartbeatConfig, logger *log.Logger) *HeartbeatGenerator {
	hg := &HeartbeatGenerator{
		config: cfg,
		logger: logger,
	}
	hg.lastBeat.Store(time.Time{})
	return hg
}

// Start begins generating heartbeat events
func (hg *HeartbeatGenerator) Start(ctx context.Context) <-chan core.TransportEvent {
	ch := make(chan core.TransportEvent)

	go func() {
		defer close(ch)

		ticker := time.NewTicker(time.Duration(hg.config.IntervalMS) * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				event := hg.generateHeartbeat(t)
				select {
				case ch <- event:
					hg.beatCount.Add(1)
					hg.lastBeat.Store(t)
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return ch
}

// generateHeartbeat creates a heartbeat transport event
func (hg *HeartbeatGenerator) generateHeartbeat(t time.Time) core.TransportEvent {
	var payload []byte

	switch hg.config.Format {
	case "json":
		data := map[string]any{
			"type":      "heartbeat",
			"timestamp": t.Format(time.RFC3339Nano),
		}
		if hg.config.IncludeStats {
			data["beat_count"] = hg.beatCount.Load()
			if last, ok := hg.lastBeat.Load().(time.Time); ok && !last.IsZero() {
				data["interval_ms"] = t.Sub(last).Milliseconds()
			}
		}
		payload, _ = json.Marshal(data)
		payload = append(payload, '\n')

	case "comment":
		// SSE-style comment for web streaming
		msg := fmt.Sprintf(": heartbeat %s", t.Format(time.RFC3339))
		if hg.config.IncludeStats {
			msg = fmt.Sprintf("%s [#%d]", msg, hg.beatCount.Load())
		}
		payload = []byte(msg + "\n")

	default:
		// Plain text
		msg := fmt.Sprintf("heartbeat: %s", t.Format(time.RFC3339))
		if hg.config.IncludeStats {
			msg = fmt.Sprintf("%s (#%d)", msg, hg.beatCount.Load())
		}
		payload = []byte(msg + "\n")
	}

	return core.TransportEvent{
		Time:    t,
		Payload: payload,
	}
}

// IntervalMS returns the heartbeat interval in milliseconds
func (hg *HeartbeatGenerator) IntervalMS() int64 {
	return hg.config.IntervalMS
}