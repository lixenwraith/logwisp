// FILE: src/internal/session/proxy.go
package session

import (
	"sync"
)

// Proxy provides filtered access to session management for a specific plugin instance
type Proxy struct {
	manager    *Manager
	instanceID string
	mu         sync.RWMutex
}

// NewProxy creates a session proxy for a specific plugin instance
func NewProxy(manager *Manager, instanceID string) *Proxy {
	return &Proxy{
		manager:    manager,
		instanceID: instanceID,
	}
}

// CreateSession creates a new session scoped to this instance
func (p *Proxy) CreateSession(remoteAddr string, metadata map[string]any) *Session {
	if metadata == nil {
		metadata = make(map[string]any)
	}

	// Add instance ID to metadata
	metadata["instance_id"] = p.instanceID

	// Create session with instance-scoped source
	session := p.manager.CreateSession(remoteAddr, p.instanceID, metadata)
	session.InstanceID = p.instanceID

	return session
}

// GetSession retrieves a session if it belongs to this instance
func (p *Proxy) GetSession(sessionID string) (*Session, bool) {
	session, exists := p.manager.GetSession(sessionID)
	if !exists || session.InstanceID != p.instanceID {
		return nil, false
	}
	return session, true
}

// RemoveSession removes a session if it belongs to this instance
func (p *Proxy) RemoveSession(sessionID string) bool {
	if session, exists := p.GetSession(sessionID); exists {
		p.manager.RemoveSession(session.ID)
		return true
	}
	return false
}

// GetActiveSessions returns all active sessions for this instance
func (p *Proxy) GetActiveSessions() []*Session {
	allSessions := p.manager.GetSessionsBySource(p.instanceID)

	// Filter by instance ID
	var filtered []*Session
	for _, session := range allSessions {
		if session.InstanceID == p.instanceID {
			filtered = append(filtered, session)
		}
	}
	return filtered
}

// UpdateActivity updates activity for a session if it belongs to this instance
func (p *Proxy) UpdateActivity(sessionID string) bool {
	if session, exists := p.GetSession(sessionID); exists {
		p.manager.UpdateActivity(session.ID)
		return true
	}
	return false
}

// GetInstanceID returns the instance ID this proxy is bound to
func (p *Proxy) GetInstanceID() string {
	return p.instanceID
}