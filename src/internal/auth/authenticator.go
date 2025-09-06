// FILE: logwisp/src/internal/auth/authenticator.go
package auth

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"logwisp/src/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lixenwraith/log"
	"golang.org/x/crypto/bcrypt"
)

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
		config:       cfg,
		logger:       logger,
		basicUsers:   make(map[string]string),
		bearerTokens: make(map[string]bool),
		sessions:     make(map[string]*Session),
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
			)

			// Setup key function
			if cfg.BearerAuth.JWT.SigningKey != "" {
				// Static key
				key := []byte(cfg.BearerAuth.JWT.SigningKey)
				a.jwtKeyFunc = func(token *jwt.Token) (interface{}, error) {
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

	logger.Info("msg", "Authenticator initialized",
		"component", "auth",
		"type", cfg.Type)

	return a, nil
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

	switch a.config.Type {
	case "basic":
		return a.authenticateBasic(authHeader, remoteAddr)
	case "bearer":
		return a.authenticateBearer(authHeader, remoteAddr)
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", a.config.Type)
	}
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

	// TCP auth protocol: AUTH <method> <credentials>
	switch strings.ToLower(method) {
	case "token":
		if a.config.Type != "bearer" {
			return nil, fmt.Errorf("token auth not configured")
		}
		return a.validateToken(credentials, remoteAddr)

	case "basic":
		if a.config.Type != "basic" {
			return nil, fmt.Errorf("basic auth not configured")
		}
		// Expect base64(username:password)
		decoded, err := base64.StdEncoding.DecodeString(credentials)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials encoding")
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid credentials format")
		}
		return a.validateBasicAuth(parts[0], parts[1], remoteAddr)

	default:
		return nil, fmt.Errorf("unsupported auth method: %s", method)
	}
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
		// ☢ SECURITY: Perform bcrypt anyway to prevent timing attacks
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

		// Check issuer if configured
		if a.config.BearerAuth.JWT.Issuer != "" {
			if iss, ok := claims["iss"].(string); !ok || iss != a.config.BearerAuth.JWT.Issuer {
				return nil, fmt.Errorf("invalid token issuer")
			}
		}

		// Check audience if configured
		if a.config.BearerAuth.JWT.Audience != "" {
			if aud, ok := claims["aud"].(string); !ok || aud != a.config.BearerAuth.JWT.Audience {
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
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
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