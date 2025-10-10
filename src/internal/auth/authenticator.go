// FILE: logwisp/src/internal/auth/authenticator.go
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// Prevent unbounded map growth
const maxAuthTrackedIPs = 10000

// Handles all authentication methods for a pipeline
type Authenticator struct {
	config *config.ServerAuthConfig
	logger *log.Logger
	tokens map[string]bool // token -> valid
	mu     sync.RWMutex

	// Session tracking
	sessions  map[string]*Session
	sessionMu sync.RWMutex
}

// TODO: only one connection per user, token, mtls
// TODO: implement tracker logic
// Represents an authenticated connection
type Session struct {
	ID           string
	Username     string
	Method       string // basic, token, mtls
	RemoteAddr   string
	CreatedAt    time.Time
	LastActivity time.Time
}

// Creates a new authenticator from config
func NewAuthenticator(cfg *config.ServerAuthConfig, logger *log.Logger) (*Authenticator, error) {
	// SCRAM is handled by ScramManager in sources
	if cfg == nil || cfg.Type == "none" || cfg.Type == "scram" {
		return nil, nil
	}

	a := &Authenticator{
		config:   cfg,
		logger:   logger,
		tokens:   make(map[string]bool),
		sessions: make(map[string]*Session),
	}

	// Initialize tokens
	if cfg.Type == "token" && cfg.Token != nil {
		for _, token := range cfg.Token.Tokens {
			a.tokens[token] = true
		}
	}

	// Start session cleanup
	go a.sessionCleanup()

	logger.Info("msg", "Authenticator initialized",
		"component", "auth",
		"type", cfg.Type)

	return a, nil
}

// Handles HTTP authentication headers
func (a *Authenticator) AuthenticateHTTP(authHeader, remoteAddr string) (*Session, error) {
	if a == nil || a.config.Type == "none" {
		return &Session{
			ID:         generateSessionID(),
			Method:     "none",
			RemoteAddr: remoteAddr,
			CreatedAt:  time.Now(),
		}, nil
	}

	var session *Session
	var err error

	switch a.config.Type {
	case "token":
		session, err = a.authenticateToken(authHeader, remoteAddr)
	default:
		err = fmt.Errorf("unsupported auth type: %s", a.config.Type)
	}

	if err != nil {
		time.Sleep(500 * time.Millisecond)
		return nil, err
	}

	return session, nil
}

func (a *Authenticator) authenticateToken(authHeader, remoteAddr string) (*Session, error) {
	if !strings.HasPrefix(authHeader, "Token") {
		return nil, fmt.Errorf("invalid token auth header")
	}

	token := authHeader[7:]
	return a.validateToken(token, remoteAddr)
}

func (a *Authenticator) validateToken(token, remoteAddr string) (*Session, error) {
	// Check static tokens first
	a.mu.RLock()
	isValid := a.tokens[token]
	a.mu.RUnlock()

	if !isValid {
		return nil, fmt.Errorf("invalid token")
	}

	session := &Session{
		ID:           generateSessionID(),
		Method:       "token",
		RemoteAddr:   remoteAddr,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	a.storeSession(session)
	return session, nil
}

func (a *Authenticator) storeSession(session *Session) {
	a.sessionMu.Lock()
	a.sessions[session.ID] = session
	a.sessionMu.Unlock()

	a.logger.Info("msg", "Session created",
		"component", "auth",
		"session_id", session.ID,
		"username", session.Username,
		"method", session.Method,
		"remote_addr", session.RemoteAddr)
}

func (a *Authenticator) sessionCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.sessionMu.Lock()
		now := time.Now()
		for id, session := range a.sessions {
			if now.Sub(session.LastActivity) > 30*time.Minute {
				delete(a.sessions, id)
				a.logger.Debug("msg", "Session expired",
					"component", "auth",
					"session_id", id)
			}
		}
		a.sessionMu.Unlock()
	}
}

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a less secure method if crypto/rand fails
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Checks if a session is still valid
func (a *Authenticator) ValidateSession(sessionID string) bool {
	if a == nil {
		return true
	}

	a.sessionMu.RLock()
	session, exists := a.sessions[sessionID]
	a.sessionMu.RUnlock()

	if !exists {
		return false
	}

	// Update activity
	a.sessionMu.Lock()
	session.LastActivity = time.Now()
	a.sessionMu.Unlock()

	return true
}

// Returns authentication statistics
func (a *Authenticator) GetStats() map[string]any {
	if a == nil {
		return map[string]any{"enabled": false}
	}

	a.sessionMu.RLock()
	sessionCount := len(a.sessions)
	a.sessionMu.RUnlock()

	return map[string]any{
		"enabled":         true,
		"type":            a.config.Type,
		"active_sessions": sessionCount,
		"static_tokens":   len(a.tokens),
	}
}