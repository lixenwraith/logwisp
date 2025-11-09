// FILE: src/internal/flow/rate.go
package flow

import (
	"strings"
	"sync/atomic"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"logwisp/src/internal/tokenbucket"

	"github.com/lixenwraith/log"
)

// RateLimiter enforces rate limits on log entries flowing through a pipeline.
type RateLimiter struct {
	bucket *tokenbucket.TokenBucket
	policy config.RateLimitPolicy
	logger *log.Logger

	// Statistics
	maxEntrySizeBytes  int64
	droppedBySizeCount atomic.Uint64
	droppedCount       atomic.Uint64
}

// NewRateLimiter creates a new pipeline-level rate limiter from configuration.
func NewRateLimiter(cfg config.RateLimitConfig, logger *log.Logger) (*RateLimiter, error) {
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

	l := &RateLimiter{
		bucket:            tokenbucket.New(burst, cfg.Rate),
		policy:            policy,
		logger:            logger,
		maxEntrySizeBytes: cfg.MaxEntrySizeBytes,
	}

	return l, nil
}

// Allow checks if a log entry is permitted to pass based on the rate limit.
func (l *RateLimiter) Allow(entry core.LogEntry) bool {
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

// GetStats returns statistics for the rate limiter.
func (l *RateLimiter) GetStats() map[string]any {
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

// policyString returns the string representation of a rate limit policy.
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