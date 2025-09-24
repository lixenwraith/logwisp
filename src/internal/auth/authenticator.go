// FILE: logwisp/src/internal/auth/authenticator.go
package auth

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"logwisp/src/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lixenwraith/log"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// Prevent unbounded map growth
const maxAuthTrackedIPs = 10000

// Authenticator handles all authentication methods for a pipeline
type Authenticator struct {
	config       *config.AuthConfig
	logger       *log.Logger
	basicUsers   map[string]string // username -> password hash
	bearerTokens map[string]bool   // token -> valid
	jwtParser    *jwt.Parser
	jwtKeyFunc   jwt.Keyfunc
	mu           sync.RWMutex

	// Session tracking
	sessions  map[string]*Session
	sessionMu sync.RWMutex

	// Brute-force protection
	ipAuthAttempts map[string]*ipAuthState
	authMu         sync.RWMutex
}

// ADDED: Per-IP auth attempt tracking
type ipAuthState struct {
	limiter      *rate.Limiter
	failCount    int
	lastAttempt  time.Time
	blockedUntil time.Time
}

// Session represents an authenticated connection
type Session struct {
	ID           string
	Username     string
	Method       string // basic, bearer, jwt, mtls
	RemoteAddr   string
	CreatedAt    time.Time
	LastActivity time.Time
	Metadata     map[string]any
}

// New creates a new authenticator from config
func New(cfg *config.AuthConfig, logger *log.Logger) (*Authenticator, error) {
	if cfg == nil || cfg.Type == "none" {
		return nil, nil
	}

	a := &Authenticator{
		config:         cfg,
		logger:         logger,
		basicUsers:     make(map[string]string),
		bearerTokens:   make(map[string]bool),
		sessions:       make(map[string]*Session),
		ipAuthAttempts: make(map[string]*ipAuthState),
	}

	// Initialize Basic Auth users
	if cfg.Type == "basic" && cfg.BasicAuth != nil {
		for _, user := range cfg.BasicAuth.Users {
			a.basicUsers[user.Username] = user.PasswordHash
		}

		// Load users from file if specified
		if cfg.BasicAuth.UsersFile != "" {
			if err := a.loadUsersFile(cfg.BasicAuth.UsersFile); err != nil {
				return nil, fmt.Errorf("failed to load users file: %w", err)
			}
		}
	}

	// Initialize Bearer tokens
	if cfg.Type == "bearer" && cfg.BearerAuth != nil {
		for _, token := range cfg.BearerAuth.Tokens {
			a.bearerTokens[token] = true
		}

		// Setup JWT validation if configured
		if cfg.BearerAuth.JWT != nil {
			a.jwtParser = jwt.NewParser(
				jwt.WithValidMethods([]string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
				jwt.WithLeeway(5*time.Second),
				jwt.WithExpirationRequired(),
			)

			// Setup key function
			if cfg.BearerAuth.JWT.SigningKey != "" {
				// Static key
				key := []byte(cfg.BearerAuth.JWT.SigningKey)
				a.jwtKeyFunc = func(token *jwt.Token) (any, error) {
					return key, nil
				}
			} else if cfg.BearerAuth.JWT.JWKSURL != "" {
				// JWKS support would require additional implementation
				// ☢ SECURITY: JWKS rotation not implemented - tokens won't refresh keys
				return nil, fmt.Errorf("JWKS support not yet implemented")
			}
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

// AuthenticateHTTP handles HTTP authentication headers
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
	case "basic":
		session, err = a.authenticateBasic(authHeader, remoteAddr)
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

// AuthenticateTCP handles TCP connection authentication
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

	case "basic":
		if a.config.Type != "basic" {
			err = fmt.Errorf("basic auth not configured")
		} else {
			// Expect base64(username:password)
			decoded, decErr := base64.StdEncoding.DecodeString(credentials)
			if decErr != nil {
				err = fmt.Errorf("invalid credentials encoding")
			} else {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) != 2 {
					err = fmt.Errorf("invalid credentials format")
				} else {
					session, err = a.validateBasicAuth(parts[0], parts[1], remoteAddr)
				}
			}
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

func (a *Authenticator) authenticateBasic(authHeader, remoteAddr string) (*Session, error) {
	if !strings.HasPrefix(authHeader, "Basic ") {
		return nil, fmt.Errorf("invalid basic auth header")
	}

	payload, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding")
	}

	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid credentials format")
	}

	return a.validateBasicAuth(parts[0], parts[1], remoteAddr)
}

func (a *Authenticator) validateBasicAuth(username, password, remoteAddr string) (*Session, error) {
	a.mu.RLock()
	expectedHash, exists := a.basicUsers[username]
	a.mu.RUnlock()

	if !exists {
		// Perform bcrypt anyway to prevent timing attacks
		bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy.hash.to.prevent.timing.attacks"), []byte(password))
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(expectedHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	session := &Session{
		ID:           generateSessionID(),
		Username:     username,
		Method:       "basic",
		RemoteAddr:   remoteAddr,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	a.storeSession(session)
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
	isStatic := a.bearerTokens[token]
	a.mu.RUnlock()

	if isStatic {
		session := &Session{
			ID:           generateSessionID(),
			Method:       "bearer",
			RemoteAddr:   remoteAddr,
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
			Metadata:     map[string]any{"token_type": "static"},
		}
		a.storeSession(session)
		return session, nil
	}

	// Try JWT validation if configured
	if a.jwtParser != nil && a.jwtKeyFunc != nil {
		claims := jwt.MapClaims{}
		parsedToken, err := a.jwtParser.ParseWithClaims(token, claims, a.jwtKeyFunc)
		if err != nil {
			return nil, fmt.Errorf("JWT validation failed: %w", err)
		}

		if !parsedToken.Valid {
			return nil, fmt.Errorf("invalid JWT token")
		}

		// Explicit expiration check
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, fmt.Errorf("token expired")
			}
		} else {
			// Reject tokens without expiration
			return nil, fmt.Errorf("token missing expiration claim")
		}

		// Check not-before claim
		if nbf, ok := claims["nbf"].(float64); ok {
			if time.Now().Unix() < int64(nbf) {
				return nil, fmt.Errorf("token not yet valid")
			}
		}

		// Check issuer if configured
		if a.config.BearerAuth.JWT.Issuer != "" {
			if iss, ok := claims["iss"].(string); !ok || iss != a.config.BearerAuth.JWT.Issuer {
				return nil, fmt.Errorf("invalid token issuer")
			}
		}

		// Check audience if configured
		if a.config.BearerAuth.JWT.Audience != "" {
			// Handle both string and []string audience formats
			audValid := false
			switch aud := claims["aud"].(type) {
			case string:
				audValid = aud == a.config.BearerAuth.JWT.Audience
			case []any:
				for _, aa := range aud {
					if audStr, ok := aa.(string); ok && audStr == a.config.BearerAuth.JWT.Audience {
						audValid = true
						break
					}
				}
			}
			if !audValid {
				return nil, fmt.Errorf("invalid token audience")
			}
		}

		username := ""
		if sub, ok := claims["sub"].(string); ok {
			username = sub
		}

		session := &Session{
			ID:           generateSessionID(),
			Username:     username,
			Method:       "jwt",
			RemoteAddr:   remoteAddr,
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
			Metadata:     map[string]any{"claims": claims},
		}
		a.storeSession(session)
		return session, nil
	}

	return nil, fmt.Errorf("invalid token")
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

func (a *Authenticator) loadUsersFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open users file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			a.logger.Warn("msg", "Skipping malformed line in users file",
				"component", "auth",
				"path", path,
				"line_number", lineNumber)
			continue
		}
		username, hash := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if username != "" && hash != "" {
			// File-based users can overwrite inline users if names conflict
			a.basicUsers[username] = hash
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading users file: %w", err)
	}

	a.logger.Info("msg", "Loaded users from file",
		"component", "auth",
		"path", path,
		"user_count", len(a.basicUsers))

	return nil
}

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a less secure method if crypto/rand fails
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// ValidateSession checks if a session is still valid
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

// GetStats returns authentication statistics
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
		"basic_users":     len(a.basicUsers),
		"static_tokens":   len(a.bearerTokens),
	}
}