// FILE: logwisp/src/internal/ratelimit/limiter.go
package ratelimit

import (
	"strings"
	"sync/atomic"

	"logwisp/src/internal/config"
	"logwisp/src/internal/limiter"
	"logwisp/src/internal/source"

	"github.com/lixenwraith/log"
)

// Limiter enforces rate limits on log entries flowing through a pipeline.
type Limiter struct {
	bucket *limiter.TokenBucket
	policy config.RateLimitPolicy
	logger *log.Logger

	// Statistics
	maxEntrySizeBytes  int64
	droppedBySizeCount atomic.Uint64
	droppedCount       atomic.Uint64
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
		bucket:            limiter.NewTokenBucket(burst, cfg.Rate),
		policy:            policy,
		logger:            logger,
		maxEntrySizeBytes: cfg.MaxEntrySizeBytes,
	}

	if cfg.Rate > 0 {
		l.bucket = limiter.NewTokenBucket(burst, cfg.Rate)
	}

	return l, nil
}

// Allow checks if a log entry is allowed to pass based on the rate limit.
// It returns true if the entry should pass, false if it should be dropped.
func (l *Limiter) Allow(entry source.LogEntry) bool {
	if l == nil || l.policy == config.PolicyPass {
		return true
	}

	// Check size limit first
	if l.maxEntrySizeBytes > 0 && entry.RawSize > l.maxEntrySizeBytes {
		l.droppedBySizeCount.Add(1)
		return false
	}

	// Check rate limit if configured
	if l.bucket != nil {
		if l.bucket.Allow() {
			return true
		}
		// Not enough tokens, drop the entry
		l.droppedCount.Add(1)
		return false
	}

	// No rate limit configured, size check passed
	return true
}

// GetStats returns the statistics for the limiter.
func (l *Limiter) GetStats() map[string]any {
	if l == nil {
		return map[string]any{
			"enabled": false,
		}
	}

	stats := map[string]any{
		"enabled":               true,
		"dropped_total":         l.droppedCount.Load(),
		"dropped_by_size_total": l.droppedBySizeCount.Load(),
		"policy":                policyString(l.policy),
		"max_entry_size_bytes":  l.maxEntrySizeBytes,
	}

	if l.bucket != nil {
		stats["tokens"] = l.bucket.Tokens()
	}

	return stats
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