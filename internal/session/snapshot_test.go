package session

import (
	"sync"
	"testing"
	"time"
)

func TestSessionSnapshotsDoNotRaceActivityUpdates(t *testing.T) {
	m := NewManager(time.Minute)
	defer m.Stop()
	proxy := NewProxy(m, "source")
	stored := proxy.CreateSession("remote", map[string]any{"label": "original"})
	readers := []func() []*Session{
		m.GetActiveSessions,
		func() []*Session { return m.GetSessionsBySource("source") },
		func() []*Session { return m.GetActiveSessionsBySource("source") },
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			proxy.UpdateActivity(stored.ID)
		}
	})
	for _, read := range readers {
		for range 100 {
			snapshots := read()
			if len(snapshots) != 1 || snapshots[0] == stored || snapshots[0].InstanceID != "source" {
				t.Errorf("invalid snapshot: %+v", snapshots)
				break
			}
			snapshot := snapshots[0]
			before := snapshot.LastActivity
			proxy.UpdateActivity(stored.ID)
			if !snapshot.LastActivity.Equal(before) {
				t.Error("activity update changed an earlier snapshot")
			}
			snapshot.Metadata["label"] = "changed"
		}
	}
	wg.Wait()
	if stored.Metadata["label"] != "original" {
		t.Fatal("snapshot metadata aliases the stored map")
	}
}
