// FILE: logwisp/src/internal/network/netlimit.go
package network

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/tokenbucket"

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

// NetLimiter manages network-level access control, connection limits, and per-IP rate limiting.
type NetLimiter struct {
	// Configuration
	config *config.ACLConfig
	logger *log.Logger

	// IP Access Control Lists
	ipWhitelist []*net.IPNet
	ipBlacklist []*net.IPNet

	// Unified IP tracking (rate limiting + connections)
	ipTrackers map[string]*ipTracker
	trackerMu  sync.RWMutex

	// Global connection counter
	totalConnections atomic.Int64

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

// ipTracker unifies rate limiting and connection tracking for a single IP.
type ipTracker struct {
	rateBucket  *tokenbucket.TokenBucket // nil if rate limiting disabled
	connections atomic.Int64
	lastSeen    atomic.Value // time.Time
}

// NewNetLimiter creates a new network limiter from configuration.
func NewNetLimiter(cfg *config.ACLConfig, logger *log.Logger) *NetLimiter {
	if cfg == nil {
		return nil
	}

	// Return nil only if nothing is configured
	hasACL := len(cfg.IPWhitelist) > 0 || len(cfg.IPBlacklist) > 0
	hasRateLimit := cfg.Enabled

	if !hasACL && !hasRateLimit {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &NetLimiter{
		config:      cfg,
		logger:      logger,
		ipWhitelist: make([]*net.IPNet, 0),
		ipBlacklist: make([]*net.IPNet, 0),
		ipTrackers:  make(map[string]*ipTracker),
		lastCleanup: time.Now(),
		ctx:         ctx,
		cancel:      cancel,
		cleanupDone: make(chan struct{}),
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
	case <-time.After(core.NetLimitCleanupTimeout):
		l.logger.Warn("msg", "Cleanup goroutine shutdown timeout", "component", "netlimit")
	}
}

// CheckHTTP checks if an HTTP request is allowed based on ACLs and rate limits.
// Does NOT track connections - caller must use ReserveConnection or RegisterConnection.
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

	// Check rate limit
	if !l.checkRateLimit(ipStr) {
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

// CheckTCP checks if a TCP connection is allowed based on ACLs and rate limits.
// Does NOT track connections - caller must use ReserveConnection or RegisterConnection.
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
	if !l.checkRateLimit(ipStr) {
		l.blockedByRateLimit.Add(1)
		return false
	}

	return true
}

// ReserveConnection atomically checks limits and reserves a connection slot.
// Used by sources when accepting new connections (pre-establishment).
// Returns true if connection is allowed and has been counted.
func (l *NetLimiter) ReserveConnection(remoteAddr string) bool {
	if l == nil {
		return true
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		l.logger.Warn("msg", "Failed to parse remote address in ReserveConnection",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return false
	}

	// IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !isIPv4(parsedIP) {
		l.logger.Warn("msg", "Invalid or non-IPv4 address in ReserveConnection",
			"component", "netlimit",
			"ip", ip)
		return false
	}

	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	// Check total connections limit first
	if l.config.MaxConnectionsTotal > 0 {
		currentTotal := l.totalConnections.Load()
		if currentTotal >= l.config.MaxConnectionsTotal {
			l.blockedByConnLimit.Add(1)
			l.logger.Debug("msg", "Connection blocked by total limit",
				"component", "netlimit",
				"current_total", currentTotal,
				"max_connections_total", l.config.MaxConnectionsTotal)
			return false
		}
	}

	// Check per-IP connection limit
	tracker := l.getOrCreateTrackerLocked(ip)
	if l.config.MaxConnectionsPerIP > 0 {
		currentConns := tracker.connections.Load()
		if currentConns >= l.config.MaxConnectionsPerIP {
			l.blockedByConnLimit.Add(1)
			l.logger.Debug("msg", "Connection blocked by IP limit",
				"component", "netlimit",
				"ip", ip,
				"current", currentConns,
				"max", l.config.MaxConnectionsPerIP)
			return false
		}
	}

	// All checks passed, increment counters
	tracker.connections.Add(1)
	tracker.lastSeen.Store(time.Now())
	newTotal := l.totalConnections.Add(1)

	l.logger.Debug("msg", "Connection reserved",
		"component", "netlimit",
		"ip", ip,
		"ip_connections", tracker.connections.Load(),
		"total_connections", newTotal)

	return true
}

// RegisterConnection tracks an already-established connection.
// Used by sinks after successfully establishing outbound connections.
func (l *NetLimiter) RegisterConnection(remoteAddr string) {
	if l == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		l.logger.Warn("msg", "Failed to parse remote address in RegisterConnection",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return
	}

	// IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !isIPv4(parsedIP) {
		return
	}

	l.trackerMu.Lock()
	tracker := l.getOrCreateTrackerLocked(ip)
	l.trackerMu.Unlock()

	newIPCount := tracker.connections.Add(1)
	tracker.lastSeen.Store(time.Now())
	newTotal := l.totalConnections.Add(1)

	l.logger.Debug("msg", "Connection registered",
		"component", "netlimit",
		"ip", ip,
		"ip_connections", newIPCount,
		"total_connections", newTotal)
}

// ReleaseConnection releases a connection slot when a connection closes.
// Used by all components when connections are closed.
func (l *NetLimiter) ReleaseConnection(remoteAddr string) {
	if l == nil {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		l.logger.Warn("msg", "Failed to parse remote address in ReleaseConnection",
			"component", "netlimit",
			"remote_addr", remoteAddr,
			"error", err)
		return
	}

	// IP validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !isIPv4(parsedIP) {
		return
	}

	l.trackerMu.RLock()
	tracker, exists := l.ipTrackers[ip]
	l.trackerMu.RUnlock()

	if !exists {
		return
	}

	newIPCount := tracker.connections.Add(-1)
	tracker.lastSeen.Store(time.Now())
	newTotal := l.totalConnections.Add(-1)

	l.logger.Debug("msg", "Connection released",
		"component", "netlimit",
		"ip", ip,
		"ip_connections", newIPCount,
		"total_connections", newTotal)

	// Clean up tracker if no more connections
	if newIPCount <= 0 {
		l.trackerMu.Lock()
		// Re-check after acquiring write lock
		if tracker.connections.Load() <= 0 {
			delete(l.ipTrackers, ip)
		}
		l.trackerMu.Unlock()
	}
}

// GetStats returns a map of the net limiter's current statistics.
func (l *NetLimiter) GetStats() map[string]any {
	if l == nil {
		return map[string]any{"enabled": false}
	}

	l.trackerMu.RLock()
	activeTrackers := len(l.ipTrackers)

	// Calculate actual connection count
	actualConnections := int64(0)
	for _, tracker := range l.ipTrackers {
		actualConnections += tracker.connections.Load()
	}
	l.trackerMu.RUnlock()

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
		},
		"access_control": map[string]any{
			"whitelist_rules": len(l.ipWhitelist),
			"blacklist_rules": len(l.ipBlacklist),
		},
		"connections": map[string]any{
			"total_active":  l.totalConnections.Load(),
			"actual_ip_sum": actualConnections,
			"tracked_ips":   activeTrackers,
			"limit_per_ip":  l.config.MaxConnectionsPerIP,
			"limit_total":   l.config.MaxConnectionsTotal,
		},
	}
}

// cleanupLoop runs a periodic cleanup of stale tracker entries.
func (l *NetLimiter) cleanupLoop() {
	defer close(l.cleanupDone)

	ticker := time.NewTicker(core.NetLimitPeriodicCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			l.logger.Debug("msg", "Cleanup loop stopping", "component", "netlimit")
			return
		case <-ticker.C:
			l.cleanup()
		}
	}
}

// cleanup removes stale IP trackers from memory.
func (l *NetLimiter) cleanup() {
	staleTimeout := core.NetLimitStaleTimeout
	now := time.Now()

	l.trackerMu.Lock()
	defer l.trackerMu.Unlock()

	cleaned := 0
	for ip, tracker := range l.ipTrackers {
		if lastSeen, ok := tracker.lastSeen.Load().(time.Time); ok {
			if now.Sub(lastSeen) > staleTimeout && tracker.connections.Load() <= 0 {
				delete(l.ipTrackers, ip)
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		l.logger.Debug("msg", "Cleaned up stale IP trackers",
			"component", "netlimit",
			"cleaned", cleaned,
			"remaining", len(l.ipTrackers))
	}
}

// getOrCreateTrackerLocked gets or creates a tracker for an IP.
// MUST be called with trackerMu write lock held.
func (l *NetLimiter) getOrCreateTrackerLocked(ip string) *ipTracker {
	tracker, exists := l.ipTrackers[ip]
	if !exists {
		tracker = &ipTracker{}
		tracker.lastSeen.Store(time.Now())

		// Create rate limiter if configured
		if l.config.Enabled && l.config.RequestsPerSecond > 0 {
			tracker.rateBucket = tokenbucket.New(
				float64(l.config.BurstSize),
				l.config.RequestsPerSecond,
			)
		}

		l.ipTrackers[ip] = tracker
		l.uniqueIPs.Add(1)

		l.logger.Debug("msg", "Created new IP tracker",
			"component", "netlimit",
			"ip", ip,
			"total_ips", l.uniqueIPs.Load())
	}
	return tracker
}

// checkRateLimit enforces the requests-per-second limit for a given IP.
func (l *NetLimiter) checkRateLimit(ip string) bool {
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

	l.trackerMu.Lock()
	tracker := l.getOrCreateTrackerLocked(ip)
	l.trackerMu.Unlock()

	// Update last seen
	tracker.lastSeen.Store(time.Now())

	// Check rate limit if bucket exists
	if tracker.rateBucket != nil {
		return tracker.rateBucket.Allow()
	}

	// No rate limiting configured for this tracker
	return true
}

// maybeCleanup triggers an asynchronous cleanup if enough time has passed.
func (l *NetLimiter) maybeCleanup() {
	l.cleanupMu.Lock()

	// Check if enough time has passed
	if time.Since(l.lastCleanup) < core.NetLimitCleanupInterval {
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

// parseIPLists converts the string-based IP rules from config into parsed net.IPNet objects.
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

// isIPv4 is a helper function to check if a net.IP is an IPv4 address.
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}