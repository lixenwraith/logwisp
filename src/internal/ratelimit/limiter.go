// FILE: src/internal/ratelimit/limiter.go
package ratelimit

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// Manages rate limiting for a transport
type Limiter struct {
	config config.RateLimitConfig
	logger *log.Logger

	// Per-IP limiters
	ipLimiters map[string]*ipLimiter
	ipMu       sync.RWMutex

	// Global limiter for the transport
	globalLimiter *TokenBucket

	// Connection tracking
	ipConnections map[string]*atomic.Int32
	connMu        sync.RWMutex

	// Statistics
	totalRequests   atomic.Uint64
	blockedRequests atomic.Uint64
	uniqueIPs       atomic.Uint64

	// Cleanup
	lastCleanup time.Time
	cleanupMu   sync.Mutex
}

type ipLimiter struct {
	bucket      *TokenBucket
	lastSeen    time.Time
	connections atomic.Int32
}

// Creates a new rate limiter
func New(cfg config.RateLimitConfig) *Limiter {
	if !cfg.Enabled {
		return nil
	}

	l := &Limiter{
		config:        cfg,
		ipLimiters:    make(map[string]*ipLimiter),
		ipConnections: make(map[string]*atomic.Int32),
		lastCleanup:   time.Now(),
		logger:        log.NewLogger(),
	}

	// Initialize the logger with defaults
	if err := l.logger.InitWithDefaults(); err != nil {
		// Fall back to stderr logging if logger init fails
		fmt.Fprintf(os.Stderr, "ratelimit: failed to initialize logger: %v\n", err)
	}

	// Create global limiter if not using per-IP limiting
	if cfg.LimitBy == "global" {
		l.globalLimiter = NewTokenBucket(
			float64(cfg.BurstSize),
			cfg.RequestsPerSecond,
		)
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	l.logger.Info("msg", "Rate limiter initialized",
		"component", "ratelimit",
		"requests_per_second", cfg.RequestsPerSecond,
		"burst_size", cfg.BurstSize,
		"limit_by", cfg.LimitBy)

	return l
}

// Checks if an HTTP request should be allowed
func (l *Limiter) CheckHTTP(remoteAddr string) (allowed bool, statusCode int, message string) {
	if l == nil {
		return true, 0, ""
	}

	l.totalRequests.Add(1)

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If we can't parse the IP, allow the request but log
		l.logger.Warn("msg", "Failed to parse remote addr",
			"component", "ratelimit",
			"remote_addr", remoteAddr,
			"error", err)
		return true, 0, ""
	}

	// Check connection limit for streaming endpoint
	if l.config.MaxConnectionsPerIP > 0 {
		l.connMu.RLock()
		counter, exists := l.ipConnections[ip]
		l.connMu.RUnlock()

		if exists && counter.Load() >= int32(l.config.MaxConnectionsPerIP) {
			l.blockedRequests.Add(1)
			statusCode = l.config.ResponseCode
			if statusCode == 0 {
				statusCode = 429
			}
			message = "Connection limit exceeded"

			l.logger.Warn("msg", "Connection limit exceeded",
				"component", "ratelimit",
				"ip", ip,
				"connections", counter.Load(),
				"limit", l.config.MaxConnectionsPerIP)

			return false, statusCode, message
		}
	}

	// Check rate limit
	allowed = l.checkLimit(ip)
	if !allowed {
		l.blockedRequests.Add(1)
		statusCode = l.config.ResponseCode
		if statusCode == 0 {
			statusCode = 429
		}
		message = l.config.ResponseMessage
		if message == "" {
			message = "Rate limit exceeded"
		}
		l.logger.Debug("msg", "Request rate limited", "ip", ip)
	}

	return allowed, statusCode, message
}

// Checks if a TCP connection should be allowed
func (l *Limiter) CheckTCP(remoteAddr net.Addr) bool {
	if l == nil {
		return true
	}

	l.totalRequests.Add(1)

	// Extract IP from TCP addr
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return true
	}

	ip := tcpAddr.IP.String()
	allowed := l.checkLimit(ip)
	if !allowed {
		l.blockedRequests.Add(1)
		l.logger.Debug("msg", "TCP connection rate limited", "ip", ip)
	}

	return allowed
}

// Tracks a new connection for an IP
func (l *Limiter) AddConnection(remoteAddr string) {
	if l == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return
	}

	l.connMu.Lock()
	counter, exists := l.ipConnections[ip]
	if !exists {
		counter = &atomic.Int32{}
		l.ipConnections[ip] = counter
	}
	l.connMu.Unlock()

	newCount := counter.Add(1)
	l.logger.Debug("msg", "Connection added",
		"ip", ip,
		"connections", newCount)
}

// Removes a connection for an IP
func (l *Limiter) RemoveConnection(remoteAddr string) {
	if l == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return
	}

	l.connMu.RLock()
	counter, exists := l.ipConnections[ip]
	l.connMu.RUnlock()

	if exists {
		newCount := counter.Add(-1)
		l.logger.Debug("msg", "Connection removed",
			"ip", ip,
			"connections", newCount)

		if newCount <= 0 {
			// Clean up if no more connections
			l.connMu.Lock()
			if counter.Load() <= 0 {
				delete(l.ipConnections, ip)
			}
			l.connMu.Unlock()
		}
	}
}

// Returns rate limiter statistics
func (l *Limiter) GetStats() map[string]any {
	if l == nil {
		return map[string]any{
			"enabled": false,
		}
	}

	l.ipMu.RLock()
	activeIPs := len(l.ipLimiters)
	l.ipMu.RUnlock()

	l.connMu.RLock()
	totalConnections := 0
	for _, counter := range l.ipConnections {
		totalConnections += int(counter.Load())
	}
	l.connMu.RUnlock()

	return map[string]any{
		"enabled":           true,
		"total_requests":    l.totalRequests.Load(),
		"blocked_requests":  l.blockedRequests.Load(),
		"active_ips":        activeIPs,
		"total_connections": totalConnections,
		"config": map[string]any{
			"requests_per_second": l.config.RequestsPerSecond,
			"burst_size":          l.config.BurstSize,
			"limit_by":            l.config.LimitBy,
		},
	}
}

// Performs the actual rate limit check
func (l *Limiter) checkLimit(ip string) bool {
	// Maybe run cleanup
	l.maybeCleanup()

	switch l.config.LimitBy {
	case "global":
		return l.globalLimiter.Allow()

	case "ip", "":
		// Default to per-IP limiting
		l.ipMu.Lock()
		limiter, exists := l.ipLimiters[ip]
		if !exists {
			// Create new limiter for this IP
			limiter = &ipLimiter{
				bucket: NewTokenBucket(
					float64(l.config.BurstSize),
					l.config.RequestsPerSecond,
				),
				lastSeen: time.Now(),
			}
			l.ipLimiters[ip] = limiter
			l.uniqueIPs.Add(1)

			l.logger.Debug("msg", "Created new IP limiter",
				"ip", ip,
				"total_ips", l.uniqueIPs.Load())
		} else {
			limiter.lastSeen = time.Now()
		}
		l.ipMu.Unlock()

		// Check connection limit if configured
		if l.config.MaxConnectionsPerIP > 0 {
			l.connMu.RLock()
			counter, exists := l.ipConnections[ip]
			l.connMu.RUnlock()

			if exists && counter.Load() >= int32(l.config.MaxConnectionsPerIP) {
				return false
			}
		}

		return limiter.bucket.Allow()

	default:
		// Unknown limit_by value, allow by default
		l.logger.Warn("msg", "Unknown limit_by value",
			"limit_by", l.config.LimitBy)
		return true
	}
}

// Runs cleanup if enough time has passed
func (l *Limiter) maybeCleanup() {
	l.cleanupMu.Lock()
	defer l.cleanupMu.Unlock()

	if time.Since(l.lastCleanup) < 30*time.Second {
		return
	}

	l.lastCleanup = time.Now()
	go l.cleanup()
}

// Removes stale IP limiters
func (l *Limiter) cleanup() {
	staleTimeout := 5 * time.Minute
	now := time.Now()

	l.ipMu.Lock()
	defer l.ipMu.Unlock()

	cleaned := 0
	for ip, limiter := range l.ipLimiters {
		if now.Sub(limiter.lastSeen) > staleTimeout {
			delete(l.ipLimiters, ip)
			cleaned++
		}
	}

	if cleaned > 0 {
		l.logger.Debug("msg", "Cleaned up stale IP limiters",
			"cleaned", cleaned,
			"remaining", len(l.ipLimiters))
	}
}

// Runs periodic cleanup
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		l.cleanup()
	}
}