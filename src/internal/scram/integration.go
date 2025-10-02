// FILE: src/internal/scram/integration.go
package scram

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ScramManager provides high-level SCRAM operations with rate limiting
type ScramManager struct {
	server   *Server
	sessions map[string]*SessionInfo
	limiter  map[string]*rate.Limiter
	mu       sync.RWMutex
}

// SessionInfo tracks authenticated sessions
type SessionInfo struct {
	Username     string
	RemoteAddr   string
	SessionID    string
	CreatedAt    time.Time
	LastActivity time.Time
	Method       string // "scram-sha-256"
}

// NewScramManager creates SCRAM manager
func NewScramManager() *ScramManager {
	m := &ScramManager{
		server:   NewServer(),
		sessions: make(map[string]*SessionInfo),
		limiter:  make(map[string]*rate.Limiter),
	}

	// Start cleanup goroutine
	go m.cleanupLoop()
	return m
}

// RegisterUser creates new user credential
func (sm *ScramManager) RegisterUser(username, password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt generation failed: %w", err)
	}

	cred, err := DeriveCredential(username, password, salt,
		sm.server.DefaultTime, sm.server.DefaultMemory, sm.server.DefaultThreads)
	if err != nil {
		return err
	}

	sm.server.AddCredential(cred)
	return nil
}

// GetRateLimiter returns per-IP rate limiter
func (sm *ScramManager) GetRateLimiter(remoteAddr string) *rate.Limiter {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if limiter, exists := sm.limiter[remoteAddr]; exists {
		return limiter
	}

	// 10 attempts per minute, burst of 3
	limiter := rate.NewLimiter(rate.Every(6*time.Second), 3)
	sm.limiter[remoteAddr] = limiter

	// Prevent unbounded growth
	if len(sm.limiter) > 10000 {
		// Remove oldest entries
		for addr := range sm.limiter {
			delete(sm.limiter, addr)
			if len(sm.limiter) < 8000 {
				break
			}
		}
	}

	return limiter
}

func (sm *ScramManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for sid, session := range sm.sessions {
			if session.LastActivity.Before(cutoff) {
				delete(sm.sessions, sid)
			}
		}
		sm.mu.Unlock()
	}
}

// HandleClientFirst wraps server's HandleClientFirst
func (sm *ScramManager) HandleClientFirst(msg *ClientFirst) (*ServerFirst, error) {
	return sm.server.HandleClientFirst(msg)
}

// HandleClientFinal wraps server's HandleClientFinal
func (sm *ScramManager) HandleClientFinal(msg *ClientFinal) (*ServerFinal, error) {
	return sm.server.HandleClientFinal(msg)
}

// AddCredential wraps server's AddCredential
func (sm *ScramManager) AddCredential(cred *Credential) {
	sm.server.AddCredential(cred)
}