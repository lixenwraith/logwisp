package flow

import (
	"context"
	"encoding/json"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/format"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/log/formatter"
)

// HeartbeatGenerator produces periodic heartbeat events
type HeartbeatGenerator struct {
	config    *config.HeartbeatConfig
	formatter format.Formatter // Use flow's formatter
	logger    *log.Logger
	beatCount atomic.Uint64
	lastBeat  atomic.Value // time.Time
}

// NewHeartbeatGenerator creates a new heartbeat generator
func NewHeartbeatGenerator(cfg *config.HeartbeatConfig, formatter format.Formatter, logger *log.Logger) (*HeartbeatGenerator, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	if err := config.Settle(cfg); err != nil {
		return nil, err
	}

	hg := &HeartbeatGenerator{
		config:    cfg,
		formatter: formatter,
		logger:    logger,
	}
	hg.lastBeat.Store(time.Time{})
	return hg, nil
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
	// Create heartbeat as LogEntry for consistent formatting
	entry := core.LogEntry{
		Time:    t,
		Source:  "heartbeat",
		Level:   "INFO",
		Message: "heartbeat",
	}

	// Add stats if configured
	if hg.config.IncludeStats {
		fields := map[string]any{
			"type":       "heartbeat",
			"beat_count": hg.beatCount.Load(),
		}

		if last, ok := hg.lastBeat.Load().(time.Time); ok && !last.IsZero() {
			fields["interval_ms"] = t.Sub(last).Milliseconds()
		}

		fieldsJSON, _ := json.Marshal(fields)
		entry.Fields = fieldsJSON
	}

	// Use formatter to generate payload
	var payload []byte
	var err error

	// Check if we need special formatting for heartbeat
	if hg.config.Format == "comment" {
		// SSE comment format - bypass formatter for this special case
		if hg.config.IncludeStats {
			beatNum := hg.beatCount.Load()
			payload = []byte(": heartbeat " + t.Format(time.RFC3339) +
				" [#" + strconv.FormatUint(beatNum, 10) + "]\n")
		} else {
			payload = []byte(": heartbeat " + t.Format(time.RFC3339) + "\n")
		}
	} else {
		// Use flow's formatter for consistent formatting
		if adapter, ok := hg.formatter.(*format.FormatterAdapter); ok {
			// Customize flags for heartbeat if needed
			// The formatter shows a timestamp unless told otherwise
			customFlags := formatter.FlagDefault
			if !hg.config.IncludeTimestamp {
				customFlags = formatter.FlagShowLevel | formatter.FlagNoTimestamp
			}
			payload, err = adapter.FormatWithFlags(entry, customFlags)
		} else {
			// Fallback to standard format
			payload, err = hg.formatter.Format(entry)
		}

		if err != nil {
			hg.logger.Error("msg", "Failed to format heartbeat",
				"error", err)
			// Fallback to simple text
			payload = []byte("heartbeat: " + t.Format(time.RFC3339) + "\n")
		}
	}

	return core.TransportEvent{
		Time:    t,
		Payload: payload,
		Entry:   entry, // heartbeats traverse chain links as structured entries
	}
}

// IntervalMS returns the heartbeat interval in milliseconds
func (hg *HeartbeatGenerator) IntervalMS() int64 {
	return hg.config.IntervalMS
}
