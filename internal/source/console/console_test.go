package console

import (
	"testing"
	"time"

	"github.com/lixenwraith/log"
	"github.com/lixenwraith/logwisp/internal/session"
)

// A console source stopped before it started closes its channels, which only
// its read loop does otherwise, so the run loop of a pipeline that another
// source failed to start ends
func TestASourceStoppedBeforeItStartedClosesItsChannels(t *testing.T) {
	m := session.NewManager(time.Minute)
	defer m.Stop()
	src, err := NewConsoleSourcePlugin("console", map[string]any{}, log.NewLogger(), session.NewProxy(m, "console"))
	if err != nil {
		t.Fatal(err)
	}
	ch := src.Subscribe()
	src.Stop()
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("an entry from a source that never started")
		}
	case <-time.After(time.Second):
		t.Fatal("the channel of a source stopped unstarted stayed open")
	}
}
