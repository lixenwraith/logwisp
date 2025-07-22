// FILE: logwisp/src/internal/netlimit/limiter.go
package netlimit

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/limiter"

	"github.com/lixenwraith/log"
)

// Limiter manages net limiting for a transport
type Limiter struct {
	config config.NetLimitConfig
	logger *log.Logger

	// Per-IP limiters
	ipLimiters map[string]*ipLimiter
	ipMu       sync.RWMutex

	// Global limiter for the transport
	globalLimiter *limiter.TokenBucket

	// Connection tracking
	ipConnections map[string]*atomic.Int64
	connMu        sync.RWMutex

	// Statistics
	totalRequests   atomic.Uint64
	blockedRequests atomic.Uint64
	uniqueIPs       atomic.Uint64

	// Cleanup
	lastCleanup time.Time
	cleanupMu   sync.Mutex

	// Lifecycle management
	ctx         context.Context
	cancel      context.CancelFunc
	cleanupDone chan struct{}
}

type ipLimiter struct {
	bucket      *limiter.TokenBucket
	lastSeen    time.Time
	connections atomic.Int64
}

// Creates a new net limiter
func New(cfg config.NetLimitConfig, logger *log.Logger) *Limiter {
	if !cfg.Enabled {
		return nil
	}

	if logger == nil {
		panic("netlimit.New: logger cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &Limiter{
		config:        cfg,
		ipLimiters:    make(map[string]*ipLimiter),
		ipConnections: make(map[string]*atomic.Int64),
		lastCleanup:   time.Now(),
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		cleanupDone:   make(chan struct{}),
	}

	// Create global limiter if not using per-IP limiting
	if cfg.LimitBy == "global" {
		l.globalLimiter = limiter.NewTokenBucket(
			float64(cfg.BurstSize),
			cfg.RequestsPerSecond,
		)
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	l.logger.Info("msg", "Net limiter initialized",
		"component", "netlimit",
		"requests_per_second", cfg.RequestsPerSecond,
		"burst_size", cfg.BurstSize,
		"limit_by", cfg.LimitBy)

	return l
}

func (l *Limiter) Shutdown() {
	if l == nil {
		return
	}

	l.logger.Info("msg", "Shutting down net limiter", "component", "netlimit")

	// Cancel context to stop cleanup goroutine
	l.cancel()

	// Wait for cleanup goroutine to finish
	select {
	case <-l.cleanupDone:
		l.logger.Debug("msg", "Cleanup goroutine stopped", "component", "netlimit")
	case <-time.After(2 * time.Second):
		l.logger.Warn("msg", "Cleanup goroutine shutdown timeout", "component", "netlimit")
	}
}

// Checks if an HTTP request should be allowed
func (l *Limiter) CheckHTTP(remoteAddr string) (allowed bool, statusCode int64, message string) {
	if l == nil {
		return true, 0, ""
	}

	l.totalRequests.Add(1)

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If we can't parse the IP, allow the request but log
		l.logger.Warn("msg", "Failed to parse remote addr",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return true, 0, ""
	}

	// Only supporting ipv4
	if !isIPv4(ip) {
		// Block non-IPv4 addresses to prevent complications
		l.blockedRequests.Add(1)
		l.logger.Warn("msg", "Non-IPv4 address blocked",
			"component", "netlimit",
			"ip", ip)
		return false, 403, "IPv4 only"
	}

	// Check connection limit for streaming endpoint
	if l.config.MaxConnectionsPerIP > 0 {
		l.connMu.RLock()
		counter, exists := l.ipConnections[ip]
		l.connMu.RUnlock()

		if exists && counter.Load() >= l.config.MaxConnectionsPerIP {
			l.blockedRequests.Add(1)
			statusCode = l.config.ResponseCode
			if statusCode == 0 {
				statusCode = 429
			}
			message = "Connection limit exceeded"

			l.logger.Warn("msg", "Connection limit exceeded",
				"component", "netlimit",
				"ip", ip,
				"connections", counter.Load(),
				"limit", l.config.MaxConnectionsPerIP)

			return false, statusCode, message
		}
	}

	// Check net limit
	allowed = l.checkLimit(ip)
	if !allowed {
		l.blockedRequests.Add(1)
		statusCode = l.config.ResponseCode
		if statusCode == 0 {
			statusCode = 429
		}
		message = l.config.ResponseMessage
		if message == "" {
			message = "Net limit exceeded"
		}
		l.logger.Debug("msg", "Request net limited", "ip", ip)
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

	// Only supporting ipv4
	if !isIPv4(ip) {
		l.blockedRequests.Add(1)
		l.logger.Warn("msg", "Non-IPv4 TCP connection blocked",
			"component", "netlimit",
			"ip", ip)
		return false
	}

	allowed := l.checkLimit(ip)
	if !allowed {
		l.blockedRequests.Add(1)
		l.logger.Debug("msg", "TCP connection net limited", "ip", ip)
	}

	return allowed
}

func isIPv4(ip string) bool {
	// Simple check: IPv4 addresses contain dots, IPv6 contain colons
	return strings.Contains(ip, ".") && !strings.Contains(ip, ":")
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

	// Only supporting ipv4
	if !isIPv4(ip) {
		return
	}

	l.connMu.Lock()
	counter, exists := l.ipConnections[ip]
	if !exists {
		counter = &atomic.Int64{}
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

	// Only supporting ipv4
	if !isIPv4(ip) {
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

// Returns net limiter statistics
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

// Performs the actual net limit check
func (l *Limiter) checkLimit(ip string) bool {
	// Maybe run cleanup
	l.maybeCleanup()

	switch l.config.LimitBy {
	case "global":
		return l.globalLimiter.Allow()

	case "ip", "":
		// Default to per-IP limiting
		l.ipMu.Lock()
		lim, exists := l.ipLimiters[ip]
		if !exists {
			// Create new limiter for this IP
			lim = &ipLimiter{
				bucket: limiter.NewTokenBucket(
					float64(l.config.BurstSize),
					l.config.RequestsPerSecond,
				),
				lastSeen: time.Now(),
			}
			l.ipLimiters[ip] = lim
			l.uniqueIPs.Add(1)

			l.logger.Debug("msg", "Created new IP limiter",
				"ip", ip,
				"total_ips", l.uniqueIPs.Load())
		} else {
			lim.lastSeen = time.Now()
		}
		l.ipMu.Unlock()

		// Check connection limit if configured
		if l.config.MaxConnectionsPerIP > 0 {
			l.connMu.RLock()
			counter, exists := l.ipConnections[ip]
			l.connMu.RUnlock()

			if exists && counter.Load() >= l.config.MaxConnectionsPerIP {
				return false
			}
		}

		return lim.bucket.Allow()

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
	for ip, lim := range l.ipLimiters {
		if now.Sub(lim.lastSeen) > staleTimeout {
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
	defer close(l.cleanupDone)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			// Exit when context is cancelled
			l.logger.Debug("msg", "Cleanup loop stopping", "component", "netlimit")
			return
		case <-ticker.C:
			l.cleanup()
		}
	}
}