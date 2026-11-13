package session

import (
	"testing"
	"time"
)

// The sweep removes a session idle past the limit and keeps one whose
// activity was refreshed since
func TestSweepRemovesOnlySessionsIdlePastTheLimit(t *testing.T) {
	m := NewManager(time.Minute)
	defer m.Stop()
	proxy := NewProxy(m, "source")
	idle := proxy.CreateSession("idle", nil)
	used := proxy.CreateSession("used", nil)
	for _, s := range []*Session{idle, used} {
		s.seen.Store(int64(time.Since(epoch) - 2*time.Minute))
	}
	proxy.UpdateActivity(used.ID)
	m.cleanupIdleSessions()
	if _, ok := m.GetSession(idle.ID); ok {
		t.Error("a session idle past the limit was kept")
	}
	if _, ok := m.GetSession(used.ID); !ok {
		t.Error("a refreshed session was swept")
	}
}
