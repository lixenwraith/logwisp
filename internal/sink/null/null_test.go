package null

import (
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/session"

	"github.com/lixenwraith/log"
)

// Stop counts what is queued before it returns: what a measured source or
// flow sent appears in the counts
func TestStopCountsWhatIsQueued(t *testing.T) {
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewNullSinkPlugin("out", map[string]any{}, log.NewLogger(), session.NewProxy(manager, "out"))
	if err != nil {
		t.Fatal(err)
	}
	ns := created.(*NullSink)
	for range 1000 {
		ns.Input() <- core.TransportEvent{Payload: []byte("entry\n")}
	}
	if err := ns.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	ns.Stop()
	if s := ns.GetStats(); s.TotalProcessed != 1000 || s.Details["total_bytes"] != uint64(6000) {
		t.Fatalf("counted %d entries, %v bytes; want 1000 and 6000", s.TotalProcessed, s.Details["total_bytes"])
	}
}
