// FILE: logwisp/src/internal/limit/net.go
package limit

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// DenialReason indicates why a network request was denied.
type DenialReason string

// ** THIS PROGRAM IS IPV4 ONLY !!**
const (
	// IPv4Only is the enforcement message for IPv6 rejection
	IPv4Only = "IPv4-only (IPv6 not supported)"
)

const (
	ReasonAllowed           DenialReason = ""
	ReasonBlacklisted       DenialReason = "IP denied by blacklist"
	ReasonNotWhitelisted    DenialReason = "IP not in whitelist"
	ReasonRateLimited       DenialReason = "Rate limit exceeded"
	ReasonConnectionLimited DenialReason = "Connection limit exceeded"
	ReasonInvalidIP         DenialReason = "Invalid IP address"
)

// NetLimiter manages network-level limiting including ACLs, rate limits, and connection counts.
type NetLimiter struct {
	config *config.NetLimitConfig
	logger *log.Logger

	// IP Access Control Lists
	ipWhitelist []*net.IPNet
	ipBlacklist []*net.IPNet

	// Per-IP limiters
	ipLimiters map[string]*ipLimiter
	ipMu       sync.RWMutex

	// Global limiter for the transport
	globalLimiter *TokenBucket

	// Connection tracking
	ipConnections    map[string]*connTracker
	userConnections  map[string]*connTracker
	tokenConnections map[string]*connTracker
	totalConnections atomic.Int64
	connMu           sync.RWMutex

	// Statistics
	totalRequests      atomic.Uint64
	blockedByBlacklist atomic.Uint64
	blockedByWhitelist atomic.Uint64
	blockedByRateLimit atomic.Uint64
	blockedByConnLimit atomic.Uint64
	blockedByInvalidIP atomic.Uint64
	uniqueIPs          atomic.Uint64

	// Cleanup
	lastCleanup   time.Time
	cleanupMu     sync.Mutex
	cleanupActive atomic.Bool

	// Lifecycle management
	ctx         context.Context
	cancel      context.CancelFunc
	cleanupDone chan struct{}
}

// ipLimiter holds the rate limiting and activity state for a single IP address.
type ipLimiter struct {
	bucket      *TokenBucket
	lastSeen    time.Time
	connections atomic.Int64
}

// connTracker tracks active connections and their last activity.
type connTracker struct {
	connections atomic.Int64
	lastSeen    time.Time
	mu          sync.Mutex
}

// NewNetLimiter creates a new network limiter from configuration.
func NewNetLimiter(cfg *config.NetLimitConfig, logger *log.Logger) *NetLimiter {
	if cfg == nil {
		return nil
	}

	// Return nil only if nothing is configured
	hasACL := len(cfg.IPWhitelist) > 0 || len(cfg.IPBlacklist) > 0
	hasRateLimit := cfg.Enabled

	if !hasACL && !hasRateLimit {
		return nil
	}

	if logger == nil {
		panic("netlimit.New: logger cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &NetLimiter{
		config:           cfg,
		logger:           logger,
		ipWhitelist:      make([]*net.IPNet, 0),
		ipBlacklist:      make([]*net.IPNet, 0),
		ipLimiters:       make(map[string]*ipLimiter),
		ipConnections:    make(map[string]*connTracker),
		userConnections:  make(map[string]*connTracker),
		tokenConnections: make(map[string]*connTracker),
		lastCleanup:      time.Now(),
		ctx:              ctx,
		cancel:           cancel,
		cleanupDone:      make(chan struct{}),
	}

	// Parse IP lists
	l.parseIPLists()

	// Start cleanup goroutine only if rate limiting is enabled
	if cfg.Enabled {
		go l.cleanupLoop()
	}

	logger.Info("msg", "Net limiter initialized",
		"component", "netlimit",
		"acl_enabled", hasACL,
		"rate_limiting", cfg.Enabled,
		"whitelist_rules", len(l.ipWhitelist),
		"blacklist_rules", len(l.ipBlacklist),
		"requests_per_second", cfg.RequestsPerSecond,
		"burst_size", cfg.BurstSize,
		"max_connections_per_ip", cfg.MaxConnectionsPerIP,
		"max_connections_total", cfg.MaxConnectionsTotal)

	return l
}

// Shutdown gracefully stops the net limiter's background cleanup processes.
func (l *NetLimiter) Shutdown() {
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

// CheckHTTP checks if an incoming HTTP request is allowed based on all configured limits.
func (l *NetLimiter) CheckHTTP(remoteAddr string) (allowed bool, statusCode int64, message string) {
	if l == nil {
		return true, 0, ""
	}

	l.totalRequests.Add(1)

	// Parse IP address
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		l.logger.Warn("msg", "Failed to parse remote addr",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return true, 0, ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		l.blockedByInvalidIP.Add(1)
		l.logger.Warn("msg", "Failed to parse IP",
			"component", "netlimit",
			"ip", ipStr)
		return false, 403, string(ReasonInvalidIP)
	}

	// Reject IPv6 connections
	if !isIPv4(ip) {
		l.blockedByInvalidIP.Add(1)
		l.logger.Warn("msg", "IPv6 connection rejected",
			"component", "netlimit",
			"ip", ipStr,
			"reason", IPv4Only)
		return false, 403, IPv4Only
	}

	// Normalize to IPv4 representation
	ip = ip.To4()

	// Check IP access control
	if reason := l.checkIPAccess(ip); reason != ReasonAllowed {
		return false, 403, string(reason)
	}

	// If rate limiting is not enabled, allow
	if !l.config.Enabled {
		return true, 0, ""
	}

	// Check connection limits
	if l.config.MaxConnectionsPerIP > 0 {
		l.connMu.RLock()
		tracker, exists := l.ipConnections[ipStr]
		l.connMu.RUnlock()

		if exists && tracker.connections.Load() >= l.config.MaxConnectionsPerIP {
			l.blockedByConnLimit.Add(1)
			statusCode = l.config.ResponseCode
			if statusCode == 0 {
				statusCode = 429
			}
			return false, statusCode, string(ReasonConnectionLimited)
		}
	}

	// Check rate limit
	if !l.checkIPLimit(ipStr) {
		l.blockedByRateLimit.Add(1)
		statusCode = l.config.ResponseCode
		if statusCode == 0 {
			statusCode = 429
		}
		message = l.config.ResponseMessage
		if message == "" {
			message = string(ReasonRateLimited)
		}
		return false, statusCode, message
	}

	return true, 0, ""
}

// CheckTCP checks if an incoming TCP connection is allowed based on ACLs and rate limits.
func (l *NetLimiter) CheckTCP(remoteAddr net.Addr) bool {
	if l == nil {
		return true
	}

	l.totalRequests.Add(1)

	// Extract IP from TCP addr
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		l.blockedByInvalidIP.Add(1)
		return false
	}

	// Reject IPv6 connections
	if !isIPv4(tcpAddr.IP) {
		l.blockedByInvalidIP.Add(1)
		l.logger.Warn("msg", "IPv6 TCP connection rejected",
			"component", "netlimit",
			"ip", tcpAddr.IP.String(),
			"reason", IPv4Only)
		return false
	}

	// Normalize to IPv4 representation
	ip := tcpAddr.IP.To4()

	// Check IP access control
	if reason := l.checkIPAccess(ip); reason != ReasonAllowed {
		return false
	}

	// If rate limiting is not enabled, allow
	if !l.config.Enabled {
		return true
	}

	// Check rate limit
	ipStr := tcpAddr.IP.String()
	if !l.checkIPLimit(ipStr) {
		l.blockedByRateLimit.Add(1)
		return false
	}

	return true
}

// AddConnection tracks a new connection from a specific remote address (for HTTP).
func (l *NetLimiter) AddConnection(remoteAddr string) {
	if l == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		l.logger.Warn("msg", "Failed to parse remote address in AddConnection",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return
	}

	// IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		l.logger.Warn("msg", "Failed to parse IP in AddConnection",
			"component", "netlimit",
			"ip", ip)
		return
	}

	// Only supporting ipv4
	if !isIPv4(parsedIP) {
		return
	}

	l.connMu.Lock()
	tracker, exists := l.ipConnections[ip]
	if !exists {
		// Create new tracker with timestamp
		tracker = &connTracker{
			lastSeen: time.Now(),
		}
		l.ipConnections[ip] = tracker
	}
	l.connMu.Unlock()

	newCount := tracker.connections.Add(1)
	// Update activity timestamp
	tracker.mu.Lock()
	tracker.lastSeen = time.Now()
	tracker.mu.Unlock()

	l.logger.Debug("msg", "Connection added",
		"ip", ip,
		"connections", newCount)
}

// RemoveConnection removes a tracked connection (for HTTP).
func (l *NetLimiter) RemoveConnection(remoteAddr string) {
	if l == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		l.logger.Warn("msg", "Failed to parse remote address in RemoveConnection",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return
	}

	// IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		l.logger.Warn("msg", "Failed to parse IP in RemoveConnection",
			"component", "netlimit",
			"ip", ip)
		return
	}

	// Only supporting ipv4
	if !isIPv4(parsedIP) {
		return
	}

	l.connMu.RLock()
	tracker, exists := l.ipConnections[ip]
	l.connMu.RUnlock()

	if exists {
		newCount := tracker.connections.Add(-1)
		l.logger.Debug("msg", "Connection removed",
			"ip", ip,
			"connections", newCount)

		if newCount <= 0 {
			// Clean up if no more connections
			l.connMu.Lock()
			if tracker.connections.Load() <= 0 {
				delete(l.ipConnections, ip)
			}
			l.connMu.Unlock()
		}
	}
}

// TrackConnection checks connection limits and tracks a new connection (for TCP).
func (l *NetLimiter) TrackConnection(ip string, user string, token string) bool {
	if l == nil {
		return true
	}

	l.connMu.Lock()
	defer l.connMu.Unlock()

	// Check total connections limit (0 = disabled)
	if l.config.MaxConnectionsTotal > 0 {
		currentTotal := l.totalConnections.Load()
		if currentTotal >= l.config.MaxConnectionsTotal {
			l.blockedByConnLimit.Add(1)
			l.logger.Debug("msg", "TCP connection blocked by total limit",
				"component", "netlimit",
				"current_total", currentTotal,
				"max_connections_total", l.config.MaxConnectionsTotal)
			return false
		}
	}

	// Check per-IP connection limit (0 = disabled)
	if l.config.MaxConnectionsPerIP > 0 && ip != "" {
		tracker, exists := l.ipConnections[ip]
		if !exists {
			tracker = &connTracker{lastSeen: time.Now()}
			l.ipConnections[ip] = tracker
		}
		if tracker.connections.Load() >= l.config.MaxConnectionsPerIP {
			l.blockedByConnLimit.Add(1)
			l.logger.Debug("msg", "TCP connection blocked by IP limit",
				"component", "netlimit",
				"ip", ip,
				"current", tracker.connections.Load(),
				"max", l.config.MaxConnectionsPerIP)
			return false
		}
	}

	// All checks passed, increment counters
	l.totalConnections.Add(1)

	if ip != "" && l.config.MaxConnectionsPerIP > 0 {
		if tracker, exists := l.ipConnections[ip]; exists {
			tracker.connections.Add(1)
			tracker.mu.Lock()
			tracker.lastSeen = time.Now()
			tracker.mu.Unlock()
		}
	}

	return true
}

// ReleaseConnection decrements connection counters when a connection is closed (for TCP).
func (l *NetLimiter) ReleaseConnection(ip string, user string, token string) {
	if l == nil {
		return
	}

	l.connMu.Lock()
	defer l.connMu.Unlock()

	// Decrement total
	if l.totalConnections.Load() > 0 {
		l.totalConnections.Add(-1)
	}

	// Decrement IP counter
	if ip != "" {
		if tracker, exists := l.ipConnections[ip]; exists {
			if tracker.connections.Load() > 0 {
				tracker.connections.Add(-1)
			}
			tracker.mu.Lock()
			tracker.lastSeen = time.Now()
			tracker.mu.Unlock()
		}
	}

	// Decrement user counter
	if user != "" {
		if tracker, exists := l.userConnections[user]; exists {
			if tracker.connections.Load() > 0 {
				tracker.connections.Add(-1)
			}
			tracker.mu.Lock()
			tracker.lastSeen = time.Now()
			tracker.mu.Unlock()
		}
	}

	// Decrement token counter
	if token != "" {
		if tracker, exists := l.tokenConnections[token]; exists {
			if tracker.connections.Load() > 0 {
				tracker.connections.Add(-1)
			}
			tracker.mu.Lock()
			tracker.lastSeen = time.Now()
			tracker.mu.Unlock()
		}
	}
}

// GetStats returns a map of the net limiter's current statistics.
func (l *NetLimiter) GetStats() map[string]any {
	if l == nil {
		return map[string]any{"enabled": false}
	}

	// Get active rate limiters count
	l.ipMu.RLock()
	activeIPs := len(l.ipLimiters)
	l.ipMu.RUnlock()

	// Get connection tracker counts and calculate total active connections
	l.connMu.RLock()
	ipConnTrackers := len(l.ipConnections)
	userConnTrackers := len(l.userConnections)
	tokenConnTrackers := len(l.tokenConnections)

	// Calculate actual connection count by summing all IP connections
	// Potentially more accurate than totalConnections counter which might drift
	// TODO: test and refactor if they match
	actualIPConnections := 0
	for _, tracker := range l.ipConnections {
		actualIPConnections += int(tracker.connections.Load())
	}

	actualUserConnections := 0
	for _, tracker := range l.userConnections {
		actualUserConnections += int(tracker.connections.Load())
	}

	actualTokenConnections := 0
	for _, tracker := range l.tokenConnections {
		actualTokenConnections += int(tracker.connections.Load())
	}

	// Use the counter for total (should match actualIPConnections in most cases)
	totalConns := l.totalConnections.Load()
	l.connMu.RUnlock()

	// Calculate total blocked
	totalBlocked := l.blockedByBlacklist.Load() +
		l.blockedByWhitelist.Load() +
		l.blockedByRateLimit.Load() +
		l.blockedByConnLimit.Load() +
		l.blockedByInvalidIP.Load()

	return map[string]any{
		"enabled":        true,
		"total_requests": l.totalRequests.Load(),
		"total_blocked":  totalBlocked,
		"blocked_breakdown": map[string]uint64{
			"blacklist":  l.blockedByBlacklist.Load(),
			"whitelist":  l.blockedByWhitelist.Load(),
			"rate_limit": l.blockedByRateLimit.Load(),
			"conn_limit": l.blockedByConnLimit.Load(),
			"invalid_ip": l.blockedByInvalidIP.Load(),
		},
		"rate_limiting": map[string]any{
			"enabled":             l.config.Enabled,
			"requests_per_second": l.config.RequestsPerSecond,
			"burst_size":          l.config.BurstSize,
			"active_ip_limiters":  activeIPs, // IPs being rate-limited
		},
		"access_control": map[string]any{
			"whitelist_rules": len(l.ipWhitelist),
			"blacklist_rules": len(l.ipBlacklist),
		},
		"connections": map[string]any{
			// Actual counts
			"total_active":             totalConns,             // Counter-based total
			"active_ip_connections":    actualIPConnections,    // Sum of all IP connections
			"active_user_connections":  actualUserConnections,  // Sum of all user connections
			"active_token_connections": actualTokenConnections, // Sum of all token connections

			// Tracker counts (number of unique IPs/users/tokens being tracked)
			"tracked_ips":    ipConnTrackers,
			"tracked_users":  userConnTrackers,
			"tracked_tokens": tokenConnTrackers,

			// Configuration limits (0 = disabled)
			"limit_per_ip": l.config.MaxConnectionsPerIP,
			"limit_total":  l.config.MaxConnectionsTotal,
		},
	}
}

// cleanupLoop runs a periodic cleanup of stale limiter and tracker entries.
func (l *NetLimiter) cleanupLoop() {
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

// maybeCleanup triggers an asynchronous cleanup if enough time has passed since the last one.
func (l *NetLimiter) maybeCleanup() {
	l.cleanupMu.Lock()

	// Check if enough time has passed
	if time.Since(l.lastCleanup) < 30*time.Second {
		l.cleanupMu.Unlock()
		return
	}

	// Check if cleanup already running
	if !l.cleanupActive.CompareAndSwap(false, true) {
		l.cleanupMu.Unlock()
		return
	}

	l.lastCleanup = time.Now()
	l.cleanupMu.Unlock()

	// Run cleanup async
	go func() {
		defer l.cleanupActive.Store(false)
		l.cleanup()
	}()
}

// cleanup removes stale IP limiters and connection trackers from memory.
func (l *NetLimiter) cleanup() {
	staleTimeout := 5 * time.Minute
	now := time.Now()

	l.ipMu.Lock()
	defer l.ipMu.Unlock()

	// Clean up rate limiters
	l.ipMu.Lock()
	cleaned := 0
	for ip, lim := range l.ipLimiters {
		if now.Sub(lim.lastSeen) > staleTimeout {
			delete(l.ipLimiters, ip)
			cleaned++
		}
	}
	l.ipMu.Unlock()

	if cleaned > 0 {
		l.logger.Debug("msg", "Cleaned up stale IP limiters",
			"component", "netlimit",
			"cleaned", cleaned,
			"remaining", len(l.ipLimiters))
	}

	// Clean up stale connection trackers
	l.connMu.Lock()

	// Clean IP connections
	ipCleaned := 0
	for ip, tracker := range l.ipConnections {
		tracker.mu.Lock()
		lastSeen := tracker.lastSeen
		tracker.mu.Unlock()

		if now.Sub(lastSeen) > staleTimeout && tracker.connections.Load() <= 0 {
			delete(l.ipConnections, ip)
			ipCleaned++
		}
	}

	// Clean user connections
	userCleaned := 0
	for user, tracker := range l.userConnections {
		tracker.mu.Lock()
		lastSeen := tracker.lastSeen
		tracker.mu.Unlock()

		if now.Sub(lastSeen) > staleTimeout && tracker.connections.Load() <= 0 {
			delete(l.userConnections, user)
			userCleaned++
		}
	}

	// Clean token connections
	tokenCleaned := 0
	for token, tracker := range l.tokenConnections {
		tracker.mu.Lock()
		lastSeen := tracker.lastSeen
		tracker.mu.Unlock()

		if now.Sub(lastSeen) > staleTimeout && tracker.connections.Load() <= 0 {
			delete(l.tokenConnections, token)
			tokenCleaned++
		}
	}

	l.connMu.Unlock()

	if ipCleaned > 0 || userCleaned > 0 || tokenCleaned > 0 {
		l.logger.Debug("msg", "Cleaned up stale connection trackers",
			"component", "netlimit",
			"ip_cleaned", ipCleaned,
			"user_cleaned", userCleaned,
			"token_cleaned", tokenCleaned,
			"ip_remaining", len(l.ipConnections),
			"user_remaining", len(l.userConnections),
			"token_remaining", len(l.tokenConnections))
	}
}

// checkIPAccess verifies if an IP address is permitted by the configured ACLs.
func (l *NetLimiter) checkIPAccess(ip net.IP) DenialReason {
	// 1. Check blacklist first (deny takes precedence)
	for _, ipNet := range l.ipBlacklist {
		if ipNet.Contains(ip) {
			l.blockedByBlacklist.Add(1)
			l.logger.Debug("msg", "IP denied by blacklist",
				"component", "netlimit",
				"ip", ip.String(),
				"rule", ipNet.String())
			return ReasonBlacklisted
		}
	}

	// 2. If whitelist is configured, IP must be in it
	if len(l.ipWhitelist) > 0 {
		for _, ipNet := range l.ipWhitelist {
			if ipNet.Contains(ip) {
				l.logger.Debug("msg", "IP allowed by whitelist",
					"component", "netlimit",
					"ip", ip.String(),
					"rule", ipNet.String())
				return ReasonAllowed
			}
		}
		l.blockedByWhitelist.Add(1)
		l.logger.Debug("msg", "IP not in whitelist",
			"component", "netlimit",
			"ip", ip.String())
		return ReasonNotWhitelisted
	}

	return ReasonAllowed
}

// checkIPLimit enforces the requests-per-second limit for a given IP address.
func (l *NetLimiter) checkIPLimit(ip string) bool {
	// Validate IP format
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !isIPv4(parsedIP) {
		l.logger.Warn("msg", "Invalid or non-IPv4 address in rate limiter",
			"component", "netlimit",
			"ip", ip)
		return false
	}

	// Maybe run cleanup
	l.maybeCleanup()

	// IP limit
	l.ipMu.Lock()
	lim, exists := l.ipLimiters[ip]
	if !exists {
		// Create new limiter for this IP
		lim = &ipLimiter{
			bucket: NewTokenBucket(
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

	// Rate limit check
	allowed := lim.bucket.Allow()
	if !allowed {
		l.blockedByRateLimit.Add(1)
	}

	return allowed
}

// parseIPLists converts the string-based IP rules from the config into parsed net.IPNet objects.
func (l *NetLimiter) parseIPLists() {
	// Parse whitelist
	for _, entry := range l.config.IPWhitelist {
		if ipNet := l.parseIPEntry(entry, "whitelist"); ipNet != nil {
			l.ipWhitelist = append(l.ipWhitelist, ipNet)
		}
	}

	// Parse blacklist
	for _, entry := range l.config.IPBlacklist {
		if ipNet := l.parseIPEntry(entry, "blacklist"); ipNet != nil {
			l.ipBlacklist = append(l.ipBlacklist, ipNet)
		}
	}
}

// parseIPEntry parses a single IP address or CIDR notation string into a net.IPNet object.
func (l *NetLimiter) parseIPEntry(entry, listType string) *net.IPNet {
	// Handle single IP
	if !strings.Contains(entry, "/") {
		ip := net.ParseIP(entry)
		if ip == nil {
			l.logger.Warn("msg", "Invalid IP entry",
				"component", "netlimit",
				"list", listType,
				"entry", entry)
			return nil
		}

		// Reject IPv6
		if ip.To4() == nil {
			l.logger.Warn("msg", "IPv6 address rejected",
				"component", "netlimit",
				"list", listType,
				"entry", entry,
				"reason", IPv4Only)
			return nil
		}

		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
	}

	// Parse CIDR
	ipAddr, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		l.logger.Warn("msg", "Invalid CIDR entry",
			"component", "netlimit",
			"list", listType,
			"entry", entry,
			"error", err)
		return nil
	}

	// Reject IPv6 CIDR
	if ipAddr.To4() == nil {
		l.logger.Warn("msg", "IPv6 CIDR rejected",
			"component", "netlimit",
			"list", listType,
			"entry", entry,
			"reason", IPv4Only)
		return nil
	}

	// Ensure mask is IPv4
	_, bits := ipNet.Mask.Size()
	if bits != 32 {
		l.logger.Warn("msg", "Non-IPv4 CIDR mask rejected",
			"component", "netlimit",
			"list", listType,
			"entry", entry,
			"mask_bits", bits,
			"reason", IPv4Only)
		return nil
	}

	return &net.IPNet{IP: ipAddr.To4(), Mask: ipNet.Mask}
}

// updateConnectionActivity updates the last seen timestamp for a connection tracker.
func (l *NetLimiter) updateConnectionActivity(ip string) {
	l.connMu.RLock()
	tracker, exists := l.ipConnections[ip]
	l.connMu.RUnlock()

	if exists {
		tracker.mu.Lock()
		tracker.lastSeen = time.Now()
		tracker.mu.Unlock()
	}
}

// isIPv4 is a helper function to check if a net.IP is an IPv4 address.
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}