// FILE: src/internal/ratelimit/limiter.go
package ratelimit

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/log"
	"logwisp/src/internal/config"
	"logwisp/src/internal/source"
)

// Limiter enforces rate limits on log entries flowing through a pipeline.
type Limiter struct {
	mu        sync.Mutex
	rate      float64
	burst     float64
	tokens    float64
	lastToken time.Time
	policy    config.RateLimitPolicy
	logger    *log.Logger

	// Statistics
	droppedCount atomic.Uint64
}

// New creates a new rate limiter. If cfg.Rate is 0, it returns nil.
func New(cfg config.RateLimitConfig, logger *log.Logger) (*Limiter, error) {
	if cfg.Rate <= 0 {
		return nil, nil // No rate limit
	}

	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.Rate // Default burst to rate
	}

	var policy config.RateLimitPolicy
	switch strings.ToLower(cfg.Policy) {
	case "drop":
		policy = config.PolicyDrop
	default:
		policy = config.PolicyPass
	}

	l := &Limiter{
		rate:      cfg.Rate,
		burst:     burst,
		tokens:    burst,
		lastToken: time.Now(),
		policy:    policy,
		logger:    logger,
	}

	return l, nil
}

// Allow checks if a log entry is allowed to pass based on the rate limit.
// It returns true if the entry should pass, false if it should be dropped.
func (l *Limiter) Allow(entry source.LogEntry) bool {
	if l.policy == config.PolicyPass {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastToken).Seconds()

	if elapsed < 0 {
		// Clock went backwards, don't add tokens
		l.lastToken = now
		elapsed = 0
	}

	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.lastToken = now

	if l.tokens >= 1 {
		l.tokens--
		return true
	}

	// Not enough tokens, drop the entry
	l.droppedCount.Add(1)
	return false
}

// GetStats returns the statistics for the limiter.
func (l *Limiter) GetStats() map[string]any {
	return map[string]any{
		"dropped_total": l.droppedCount.Load(),
		"policy":        policyString(l.policy),
		"rate":          l.rate,
		"burst":         l.burst,
	}
}

// policyString returns the string representation of the policy.
func policyString(p config.RateLimitPolicy) string {
	switch p {
	case config.PolicyDrop:
		return "drop"
	case config.PolicyPass:
		return "pass"
	default:
		return "unknown"
	}
}