package flow

import (
	"fmt"
	"strings"
	"sync/atomic"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/tokenbucket"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

// RateLimiter enforces rate limits on log entries flowing through a pipeline
type RateLimiter struct {
	bucket *tokenbucket.TokenBucket
	policy config.RateLimitPolicy
	logger *log.Logger

	// Statistics
	maxEntrySizeBytes  int64
	droppedBySizeCount atomic.Uint64
	droppedCount       atomic.Uint64
}

// NewRateLimiter creates a new pipeline-level rate limiter from configuration
func NewRateLimiter(cfg config.RateLimitConfig, logger *log.Logger) (*RateLimiter, error) {
	// Rate <= 0 means disabled
	if cfg.Rate <= 0 {
		return nil, nil // No rate limit
	}

	// Validate
	if err := lconfig.NonNegative(cfg.Rate); err != nil {
		return nil, fmt.Errorf("rate: %w", err)
	}
	if err := lconfig.NonNegative(cfg.Burst); err != nil {
		return nil, fmt.Errorf("burst: %w", err)
	}
	if err := lconfig.NonNegative(cfg.MaxEntrySizeBytes); err != nil {
		return nil, fmt.Errorf("max_entry_size_bytes: %w", err)
	}

	// Defaults
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.Rate
	}

	var policy config.RateLimitPolicy
	switch strings.ToLower(cfg.Policy) {
	case "drop":
		policy = config.PolicyDrop
	case "pass", "":
		policy = config.PolicyPass
	default:
		return nil, fmt.Errorf("policy: must be one of [drop, pass], got %s", cfg.Policy)
	}

	l := &RateLimiter{
		bucket:            tokenbucket.New(burst, cfg.Rate),
		policy:            policy,
		logger:            logger,
		maxEntrySizeBytes: cfg.MaxEntrySizeBytes,
	}

	return l, nil
}

// Allow checks if a log entry is permitted to pass based on the rate limit
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

// GetStats returns statistics for the rate limiter
func (l *RateLimiter) GetStats() map[string]any {
	if l == nil {
		return map[string]any{
			"enabled": false,
		}
	}

	stats := map[string]any{
		"enabled":               true,
		"rate":                  l.bucket.Rate(),
		"burst":                 l.bucket.Capacity(),
		"dropped_total":         l.droppedCount.Load(),
		"dropped_by_size_total": l.droppedBySizeCount.Load(),
		"policy":                policyString(l.policy),
		"max_entry_size_bytes":  l.maxEntrySizeBytes,
	}

	if l.bucket != nil {
		stats["available_tokens"] = l.bucket.Tokens()
	}

	return stats
}

// policyString returns the string representation of a rate limit policy
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