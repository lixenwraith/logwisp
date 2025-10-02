// FILE: logwisp/src/internal/auth/authenticator.go
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
	"golang.org/x/time/rate"
)

// Prevent unbounded map growth
const maxAuthTrackedIPs = 10000

// Handles all authentication methods for a pipeline
type Authenticator struct {
	config       *config.AuthConfig
	logger       *log.Logger
	bearerTokens map[string]bool // token -> valid
	mu           sync.RWMutex

	// Session tracking
	sessions  map[string]*Session
	sessionMu sync.RWMutex

	// Brute-force protection
	ipAuthAttempts map[string]*ipAuthState
	authMu         sync.RWMutex
}

// Per-IP auth attempt tracking
type ipAuthState struct {
	limiter      *rate.Limiter
	failCount    int
	lastAttempt  time.Time
	blockedUntil time.Time
}

// Represents an authenticated connection
type Session struct {
	ID           string
	Username     string
	Method       string // basic, bearer, mtls
	RemoteAddr   string
	CreatedAt    time.Time
	LastActivity time.Time
}

// Creates a new authenticator from config
func NewAuthenticator(cfg *config.AuthConfig, logger *log.Logger) (*Authenticator, error) {
	// SCRAM is handled by ScramManager in sources
	if cfg == nil || cfg.Type == "none" || cfg.Type == "scram" {
		return nil, nil
	}

	a := &Authenticator{
		config:         cfg,
		logger:         logger,
		bearerTokens:   make(map[string]bool),
		sessions:       make(map[string]*Session),
		ipAuthAttempts: make(map[string]*ipAuthState),
	}

	// Initialize Bearer tokens
	if cfg.Type == "bearer" && cfg.BearerAuth != nil {
		for _, token := range cfg.BearerAuth.Tokens {
			a.bearerTokens[token] = true
		}
	}

	// Start session cleanup
	go a.sessionCleanup()

	// Start auth attempt cleanup
	go a.authAttemptCleanup()

	logger.Info("msg", "Authenticator initialized",
		"component", "auth",
		"type", cfg.Type)

	return a, nil
}

// Check and enforce rate limits
func (a *Authenticator) checkRateLimit(remoteAddr string) error {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr // Fallback for malformed addresses
	}

	a.authMu.Lock()
	defer a.authMu.Unlock()

	state, exists := a.ipAuthAttempts[ip]
	now := time.Now()

	if !exists {
		// Check map size limit before creating new entry
		if len(a.ipAuthAttempts) >= maxAuthTrackedIPs {
			// Evict an old entry using simplified LRU
			// Sample 20 random entries and evict the oldest
			const sampleSize = 20
			var oldestIP string
			oldestTime := now

			// Build sample
			sampled := 0
			for sampledIP, sampledState := range a.ipAuthAttempts {
				if sampledState.lastAttempt.Before(oldestTime) {
					oldestIP = sampledIP
					oldestTime = sampledState.lastAttempt
				}
				sampled++
				if sampled >= sampleSize {
					break
				}
			}

			// Evict the oldest from our sample
			if oldestIP != "" {
				delete(a.ipAuthAttempts, oldestIP)
				a.logger.Debug("msg", "Evicted old auth attempt state",
					"component", "auth",
					"evicted_ip", oldestIP,
					"last_seen", oldestTime)
			}
		}

		// Create new state for this IP
		// 5 attempts per minute, burst of 3
		state = &ipAuthState{
			limiter:     rate.NewLimiter(rate.Every(12*time.Second), 3),
			lastAttempt: now,
		}
		a.ipAuthAttempts[ip] = state
	}

	// Check if IP is temporarily blocked
	if now.Before(state.blockedUntil) {
		remaining := state.blockedUntil.Sub(now)
		a.logger.Warn("msg", "IP temporarily blocked",
			"component", "auth",
			"ip", ip,
			"remaining", remaining)
		// Sleep to slow down even blocked attempts
		time.Sleep(2 * time.Second)
		return fmt.Errorf("temporarily blocked, try again in %v", remaining.Round(time.Second))
	}

	// Check rate limit
	if !state.limiter.Allow() {
		state.failCount++

		// Only set new blockedUntil if not already blocked
		// This prevents indefinite block extension
		if state.blockedUntil.IsZero() || now.After(state.blockedUntil) {
			// Progressive blocking: 2^failCount minutes
			blockMinutes := 1 << min(state.failCount, 6) // Cap at 64 minutes
			state.blockedUntil = now.Add(time.Duration(blockMinutes) * time.Minute)

			a.logger.Warn("msg", "Rate limit exceeded, blocking IP",
				"component", "auth",
				"ip", ip,
				"fail_count", state.failCount,
				"block_duration", time.Duration(blockMinutes)*time.Minute)
		}

		return fmt.Errorf("rate limit exceeded")
	}

	state.lastAttempt = now
	return nil
}

// Record failed attempt
func (a *Authenticator) recordFailure(remoteAddr string) {
	ip, _, _ := net.SplitHostPort(remoteAddr)
	if ip == "" {
		ip = remoteAddr
	}

	a.authMu.Lock()
	defer a.authMu.Unlock()

	if state, exists := a.ipAuthAttempts[ip]; exists {
		state.failCount++
		state.lastAttempt = time.Now()
	}
}

// Reset failure count on success
func (a *Authenticator) recordSuccess(remoteAddr string) {
	ip, _, _ := net.SplitHostPort(remoteAddr)
	if ip == "" {
		ip = remoteAddr
	}

	a.authMu.Lock()
	defer a.authMu.Unlock()

	if state, exists := a.ipAuthAttempts[ip]; exists {
		state.failCount = 0
		state.blockedUntil = time.Time{}
	}
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

	// Check rate limit
	if err := a.checkRateLimit(remoteAddr); err != nil {
		return nil, err
	}

	var session *Session
	var err error

	switch a.config.Type {
	case "bearer":
		session, err = a.authenticateBearer(authHeader, remoteAddr)
	default:
		err = fmt.Errorf("unsupported auth type: %s", a.config.Type)
	}

	if err != nil {
		a.recordFailure(remoteAddr)
		time.Sleep(500 * time.Millisecond)
		return nil, err
	}

	a.recordSuccess(remoteAddr)
	return session, nil
}

// Handles TCP connection authentication
func (a *Authenticator) AuthenticateTCP(method, credentials, remoteAddr string) (*Session, error) {
	if a == nil || a.config.Type == "none" {
		return &Session{
			ID:         generateSessionID(),
			Method:     "none",
			RemoteAddr: remoteAddr,
			CreatedAt:  time.Now(),
		}, nil
	}

	// Check rate limit first
	if err := a.checkRateLimit(remoteAddr); err != nil {
		return nil, err
	}

	var session *Session
	var err error

	// TCP auth protocol: AUTH <method> <credentials>
	switch strings.ToLower(method) {
	case "token":
		if a.config.Type != "bearer" {
			err = fmt.Errorf("token auth not configured")
		} else {
			session, err = a.validateToken(credentials, remoteAddr)
		}

	default:
		err = fmt.Errorf("unsupported auth method: %s", method)
	}

	if err != nil {
		a.recordFailure(remoteAddr)
		// Add delay on failure
		time.Sleep(500 * time.Millisecond)
		return nil, err
	}

	a.recordSuccess(remoteAddr)
	return session, nil
}

func (a *Authenticator) authenticateBearer(authHeader, remoteAddr string) (*Session, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid bearer auth header")
	}

	token := authHeader[7:]
	return a.validateToken(token, remoteAddr)
}

func (a *Authenticator) validateToken(token, remoteAddr string) (*Session, error) {
	// Check static tokens first
	a.mu.RLock()
	isValid := a.bearerTokens[token]
	a.mu.RUnlock()

	if !isValid {
		return nil, fmt.Errorf("invalid token")
	}

	session := &Session{
		ID:           generateSessionID(),
		Method:       "bearer",
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

// Cleanup old auth attempts
func (a *Authenticator) authAttemptCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.authMu.Lock()
		now := time.Now()
		for ip, state := range a.ipAuthAttempts {
			// Remove entries older than 1 hour with no recent activity
			if now.Sub(state.lastAttempt) > time.Hour {
				delete(a.ipAuthAttempts, ip)
				a.logger.Debug("msg", "Cleaned up auth attempt state",
					"component", "auth",
					"ip", ip)
			}
		}
		a.authMu.Unlock()
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
		"static_tokens":   len(a.bearerTokens),
	}
}