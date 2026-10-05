package sink

import (
	"context"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
)

// Sink represents an output data stream.
type Sink interface {
	// Capabilities returns a slice of supported Source capabilities
	Capabilities() []core.Capability

	// Input returns the channel for sending transport events to this sink.
	Input() chan<- core.TransportEvent

	// Start begins processing transport events.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the sink.
	Stop()

	// GetStats returns sink statistics.
	GetStats() SinkStats
}

// SinkStats contains statistics about a sink.
type SinkStats struct {
	ID                string
	Type              string
	TotalProcessed    uint64
	ActiveConnections int64
	StartTime         time.Time
	LastProcessed     time.Time
	Details           map[string]any
}

// FlushBound is how long a network sink's Stop gives what is queued to reach
// its clients or its downstream: its write or request timeout, at most
// core.SinkFlushTimeout, which a reload also waits out for a stalled peer.
func FlushBound(writeTimeout time.Duration) time.Duration {
	if writeTimeout > 0 && writeTimeout < core.SinkFlushTimeout {
		return writeTimeout
	}
	return core.SinkFlushTimeout
}

// FlushContext is ctx ending FlushBound(timeout) after done closes: a sink
// that dials runs its loop under it, so Stop leaves its queue that long.
func FlushContext(ctx context.Context, done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
			select {
			case <-time.After(FlushBound(timeout)):
			case <-ctx.Done():
			}
		case <-ctx.Done():
		}
		cancel()
	}()
	return ctx, cancel
}

// Drain takes the payloads queued in input without waiting: a network sink's
// last events, which each client then writes on its own.
func Drain(input <-chan core.TransportEvent) [][]byte {
	var tail [][]byte
	for {
		select {
		case event := <-input:
			tail = append(tail, event.Payload)
		default:
			return tail
		}
	}
}
