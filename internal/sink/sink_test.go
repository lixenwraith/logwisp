package sink

import (
	"bytes"
	"testing"

	"github.com/lixenwraith/logwisp/internal/core"
)

// Batches hold whole payloads, each once and in order, within the bound
// unless a batch is one payload, and a batch ends short of the bound only
// when nothing is queued behind it: the caller loops as the sinks do.
func FuzzBatchesHoldWholePayloadsInOrderWithinTheBound(f *testing.F) {
	f.Add([]byte{1, 200, 17, 255, 3, 0, 64}, uint8(16))
	f.Add([]byte{128, 128, 128}, uint8(16)) // two fill a batch exactly
	f.Add([]byte{255, 1, 255}, uint8(64))   // payloads past the bound alone
	f.Add([]byte{0, 0, 1}, uint8(1))
	f.Fuzz(func(t *testing.T, sizes []byte, unit uint8) {
		if len(sizes) == 0 {
			return
		}
		payloads := make([][]byte, len(sizes))
		q := make(chan []byte, len(sizes))
		for i, size := range sizes {
			payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, int(size)*int(unit))
			if i > 0 {
				q <- payloads[i]
			}
		}
		const bound = core.SinkWriteBatchBytes
		var buf []byte
		next, at := payloads[0], 0
		for more := true; more; {
			var n int
			buf, n, next, more = Batch(buf, next, q, Bytes)
			if at+n > len(payloads) {
				t.Fatalf("batch at payload %d counts %d of %d payloads", at, n, len(payloads))
			}
			if want := bytes.Join(payloads[at:at+n], nil); !bytes.Equal(buf, want) {
				t.Fatalf("batch at payload %d is not payloads %d to %d", at, at, at+n)
			}
			if n > 1 && len(buf) > bound {
				t.Fatalf("batch of %d payloads is %d bytes", n, len(buf))
			}
			if more && len(buf)+len(next) <= bound {
				t.Fatalf("payload %d fits the %d-byte batch it was left out of", at+n, len(buf))
			}
			if !more && len(q) > 0 && len(buf) < bound {
				t.Fatalf("%d-byte batch ended with %d payloads queued", len(buf), len(q))
			}
			if at += n; !more && len(q) > 0 {
				next, more = <-q, true
			}
		}
		if at != len(payloads) {
			t.Fatalf("batches carried %d of %d payloads", at, len(payloads))
		}
	})
}
