// FILE: logwisp/src/internal/config/ratelimit.go
package config

import (
	"fmt"
	"net"
	"strings"
)

// RateLimitPolicy defines the action to take when a rate limit is exceeded.
type RateLimitPolicy int

const (
	// PolicyPass allows all logs through, effectively disabling the limiter.
	PolicyPass RateLimitPolicy = iota
	// PolicyDrop drops logs that exceed the rate limit.
	PolicyDrop
)

// RateLimitConfig defines the configuration for pipeline-level rate limiting.
type RateLimitConfig struct {
	// Rate is the number of log entries allowed per second. Default: 0 (disabled).
	Rate float64 `toml:"rate"`
	// Burst is the maximum number of log entries that can be sent in a short burst. Defaults to the Rate.
	Burst float64 `toml:"burst"`
	// Policy defines the action to take when the limit is exceeded. "pass" or "drop".
	Policy string `toml:"policy"`
	// MaxEntrySizeBytes is the maximum allowed size for a single log entry. 0 = no limit.
	MaxEntrySizeBytes int64 `toml:"max_entry_size_bytes"`
}

func validateNetAccess(pipelineName string, cfg *NetAccessConfig) error {
	if cfg == nil {
		return nil
	}

	// Validate CIDR notation
	for _, cidr := range cfg.IPWhitelist {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if net.ParseIP(cidr) == nil {
				return fmt.Errorf("pipeline '%s': invalid IP whitelist entry: %s", pipelineName, cidr)
			}
		}
	}

	for _, cidr := range cfg.IPBlacklist {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if net.ParseIP(cidr) == nil {
				return fmt.Errorf("pipeline '%s': invalid IP blacklist entry: %s", pipelineName, cidr)
			}
		}
	}

	return nil
}

func validateRateLimit(pipelineName string, cfg *RateLimitConfig) error {
	if cfg == nil {
		return nil
	}

	if cfg.Rate < 0 {
		return fmt.Errorf("pipeline '%s': rate limit rate cannot be negative", pipelineName)
	}

	if cfg.Burst < 0 {
		return fmt.Errorf("pipeline '%s': rate limit burst cannot be negative", pipelineName)
	}

	if cfg.MaxEntrySizeBytes < 0 {
		return fmt.Errorf("pipeline '%s': max entry size bytes cannot be negative", pipelineName)
	}

	// Validate policy
	switch strings.ToLower(cfg.Policy) {
	case "", "pass", "drop":
		// Valid policies
	default:
		return fmt.Errorf("pipeline '%s': invalid rate limit policy '%s' (must be 'pass' or 'drop')",
			pipelineName, cfg.Policy)
	}

	return nil
}