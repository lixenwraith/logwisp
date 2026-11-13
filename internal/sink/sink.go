package sink

import (
	"context"
	"maps"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
)

// Sink represents an output data stream.
type Sink interface {
	// Capabilities returns a slice of supported Sink capabilities
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

// Batch is what a sink writes at once: first, then what queue holds behind it
// while the whole stays within core.SinkWriteBatchBytes, n items appended to
// dst by add. more reports next, the queued item that would have crossed the
// bound and starts the following batch; it is returned by value, as a pointer
// would put every item taken on the heap. Only queue's one reader calls it.
func Batch[T any](dst []byte, first T, queue <-chan T, add func([]byte, T) []byte) (batch []byte, n int, next T, more bool) {
	batch, n = add(dst[:0], first), 1
	for len(batch) < core.SinkWriteBatchBytes && len(queue) > 0 {
		item := <-queue
		mark := len(batch)
		if batch = add(batch, item); len(batch) > core.SinkWriteBatchBytes {
			return batch[:mark], n, item, true
		}
		n++
	}
	return batch, n, next, false
}

// Bytes appends a payload as it is: Batch's add for a queue of payloads
func Bytes(dst, payload []byte) []byte { return append(dst, payload...) }

// Queue holds payloads for Batch: the tail each client writes after its own
// queue at Stop
func Queue(payloads [][]byte) <-chan []byte {
	q := make(chan []byte, len(payloads))
	for _, p := range payloads {
		q <- p
	}
	close(q)
	return q
}

// Kept is a batch buffer to reuse, or nil past four batches' size: a long
// entry's buffer is not held for the next
func Kept(buf []byte) []byte {
	if cap(buf) > 4*core.SinkWriteBatchBytes {
		return nil
	}
	return buf[:0]
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

// Shrunk is m rebuilt once it holds under a quarter of peak, the most it held
// since it was built, with the peak that goes with it: a map keeps its
// largest table, which a broker's walk over its clients pays for every event
func Shrunk[K comparable, V any](m map[K]V, peak int) (map[K]V, int) {
	if len(m) < peak/4 {
		return maps.Collect(maps.All(m)), len(m)
	}
	return m, peak
}
