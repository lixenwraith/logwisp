// FILE: src/internal/session/session.go
package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session represents a connection session.
type Session struct {
	ID           string         // Unique session identifier
	RemoteAddr   string         // Client address
	CreatedAt    time.Time      // Session creation time
	LastActivity time.Time      // Last activity timestamp
	Metadata     map[string]any // Optional metadata (e.g., TLS info)

	// Connection context
	Source string // Source type: "tcp_source", "http_source", "tcp_sink", etc.
}

// Manager handles the lifecycle of sessions.
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex

	// Cleanup configuration
	maxIdleTime   time.Duration
	cleanupTicker *time.Ticker
	done          chan struct{}

	// Expiry callbacks by source type
	expiryCallbacks map[string]func(sessionID, remoteAddr string)
	callbacksMu     sync.RWMutex
}

// NewManager creates a new session manager with a specified idle timeout.
func NewManager(maxIdleTime time.Duration) *Manager {
	if maxIdleTime == 0 {
		maxIdleTime = 30 * time.Minute // Default idle timeout
	}

	m := &Manager{
		sessions:    make(map[string]*Session),
		maxIdleTime: maxIdleTime,
		done:        make(chan struct{}),
	}

	// Start cleanup routine
	m.startCleanup()

	return m
}

// CreateSession creates and stores a new session for a connection.
func (m *Manager) CreateSession(remoteAddr string, source string, metadata map[string]any) *Session {
	session := &Session{
		ID:           generateSessionID(),
		RemoteAddr:   remoteAddr,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Source:       source,
		Metadata:     metadata,
	}

	if metadata == nil {
		session.Metadata = make(map[string]any)
	}

	m.StoreSession(session)
	return session
}

// StoreSession adds a session to the manager.
func (m *Manager) StoreSession(session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
}

// GetSession retrieves a session by its unique ID.
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, exists := m.sessions[sessionID]
	return session, exists
}

// RemoveSession removes a session from the manager.
func (m *Manager) RemoveSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
}

// UpdateActivity updates the last activity timestamp for a session.
func (m *Manager) UpdateActivity(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[sessionID]; exists {
		session.LastActivity = time.Now()
	}
}

// IsSessionActive checks if a session exists and has not been idle for too long.
func (m *Manager) IsSessionActive(sessionID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if session, exists := m.sessions[sessionID]; exists {
		// Session exists and hasn't exceeded idle timeout
		return time.Since(session.LastActivity) < m.maxIdleTime
	}
	return false
}

// GetActiveSessions returns a snapshot of all currently active sessions.
func (m *Manager) GetActiveSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// GetSessionCount returns the number of active sessions.
func (m *Manager) GetSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// GetSessionsBySource returns all sessions matching a specific source type.
func (m *Manager) GetSessionsBySource(source string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []*Session
	for _, session := range m.sessions {
		if session.Source == source {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// GetActiveSessionsBySource returns all active sessions for a given source.
func (m *Manager) GetActiveSessionsBySource(source string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []*Session
	now := time.Now()

	for _, session := range m.sessions {
		if session.Source == source && now.Sub(session.LastActivity) < m.maxIdleTime {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// GetStats returns statistics about the session manager.
func (m *Manager) GetStats() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sourceCounts := make(map[string]int)
	var totalSessions int
	var oldestSession time.Time
	var newestSession time.Time

	for _, session := range m.sessions {
		totalSessions++
		sourceCounts[session.Source]++

		if oldestSession.IsZero() || session.CreatedAt.Before(oldestSession) {
			oldestSession = session.CreatedAt
		}
		if newestSession.IsZero() || session.CreatedAt.After(newestSession) {
			newestSession = session.CreatedAt
		}
	}

	stats := map[string]any{
		"total_sessions":   totalSessions,
		"sessions_by_type": sourceCounts,
		"max_idle_time":    m.maxIdleTime.String(),
	}

	if !oldestSession.IsZero() {
		stats["oldest_session_age"] = time.Since(oldestSession).String()
	}
	if !newestSession.IsZero() {
		stats["newest_session_age"] = time.Since(newestSession).String()
	}

	return stats
}

// Stop gracefully stops the session manager and its cleanup goroutine.
func (m *Manager) Stop() {
	close(m.done)
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
	}
}

// RegisterExpiryCallback registers a callback function to be executed when a session expires.
func (m *Manager) RegisterExpiryCallback(source string, callback func(sessionID, remoteAddr string)) {
	m.callbacksMu.Lock()
	defer m.callbacksMu.Unlock()

	if m.expiryCallbacks == nil {
		m.expiryCallbacks = make(map[string]func(sessionID, remoteAddr string))
	}
	m.expiryCallbacks[source] = callback
}

// UnregisterExpiryCallback removes an expiry callback for a given source type.
func (m *Manager) UnregisterExpiryCallback(source string) {
	m.callbacksMu.Lock()
	defer m.callbacksMu.Unlock()

	delete(m.expiryCallbacks, source)
}

// startCleanup initializes the periodic cleanup of idle sessions.
func (m *Manager) startCleanup() {
	m.cleanupTicker = time.NewTicker(5 * time.Minute)

	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupIdleSessions()
			case <-m.done:
				return
			}
		}
	}()
}

// cleanupIdleSessions removes sessions that have exceeded the maximum idle time.
func (m *Manager) cleanupIdleSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredSessions := make([]*Session, 0)

	for id, session := range m.sessions {
		idleTime := now.Sub(session.LastActivity)

		if idleTime > m.maxIdleTime {
			expiredSessions = append(expiredSessions, session)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()

	// Call callbacks outside of lock
	if len(expiredSessions) > 0 {
		m.callbacksMu.RLock()
		defer m.callbacksMu.RUnlock()

		for _, session := range expiredSessions {
			if callback, exists := m.expiryCallbacks[session.Source]; exists {
				// Call callback to notify owner
				go callback(session.ID, session.RemoteAddr)
			}
		}
	}
}

// generateSessionID creates a unique, random session identifier.
func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("session_%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}