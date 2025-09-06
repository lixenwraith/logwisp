// FILE: src/internal/limit/ip.go
package limit

import (
	"net"
	"strings"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// IPChecker handles IP-based access control lists
type IPChecker struct {
	ipWhitelist []*net.IPNet
	ipBlacklist []*net.IPNet
	logger      *log.Logger
}

// NewIPChecker creates a new IPChecker. Returns nil if no rules are defined.
func NewIPChecker(cfg *config.NetAccessConfig, logger *log.Logger) *IPChecker {
	if cfg == nil || (len(cfg.IPWhitelist) == 0 && len(cfg.IPBlacklist) == 0) {
		return nil
	}

	c := &IPChecker{
		ipWhitelist: make([]*net.IPNet, 0),
		ipBlacklist: make([]*net.IPNet, 0),
		logger:      logger,
	}

	// Parse whitelist entries
	for _, cidr := range cfg.IPWhitelist {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as plain IP
			if ip := net.ParseIP(cidr); ip != nil {
				if ip.To4() != nil {
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			} else {
				logger.Warn("msg", "Skipping invalid IP whitelist entry",
					"component", "ip_checker",
					"entry", cidr,
					"error", err)
				continue
			}
		}
		c.ipWhitelist = append(c.ipWhitelist, ipNet)
	}

	// Parse blacklist entries
	for _, cidr := range cfg.IPBlacklist {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as plain IP
			if ip := net.ParseIP(cidr); ip != nil {
				if ip.To4() != nil {
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			} else {
				logger.Warn("msg", "Skipping invalid IP blacklist entry",
					"component", "ip_checker",
					"entry", cidr,
					"error", err)
				continue
			}
		}
		c.ipBlacklist = append(c.ipBlacklist, ipNet)
	}

	logger.Info("msg", "IP checker initialized",
		"component", "ip_checker",
		"whitelist_rules", len(c.ipWhitelist),
		"blacklist_rules", len(c.ipBlacklist))

	return c
}

// IsAllowed validates if a remote address is permitted
func (c *IPChecker) IsAllowed(remoteAddr net.Addr) bool {
	if c == nil {
		return true // No checker = allow all
	}

	// No rules = allow all
	if len(c.ipWhitelist) == 0 && len(c.ipBlacklist) == 0 {
		return true
	}

	// Extract IP from address
	var ipStr string
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		ipStr = addr.IP.String()
	case *net.UDPAddr:
		ipStr = addr.IP.String()
	default:
		// Try string parsing
		addrStr := remoteAddr.String()
		host, _, err := net.SplitHostPort(addrStr)
		if err != nil {
			ipStr = addrStr
		} else {
			ipStr = host
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		c.logger.Warn("msg", "Could not parse remote address to IP",
			"component", "ip_checker",
			"remote_addr", remoteAddr.String())
		return false // Deny unparseable addresses
	}

	// Check blacklist first (deny takes precedence)
	for _, ipNet := range c.ipBlacklist {
		if ipNet.Contains(ip) {
			c.logger.Warn("msg", "Blacklisted IP denied",
				"component", "ip_checker",
				"ip", ipStr,
				"rule", ipNet.String())
			return false
		}
	}

	// If whitelist is configured, IP must be in it
	if len(c.ipWhitelist) > 0 {
		for _, ipNet := range c.ipWhitelist {
			if ipNet.Contains(ip) {
				c.logger.Debug("msg", "IP allowed by whitelist",
					"component", "ip_checker",
					"ip", ipStr,
					"rule", ipNet.String())
				return true
			}
		}
		// No whitelist match = deny
		c.logger.Warn("msg", "IP not in whitelist",
			"component", "ip_checker",
			"ip", ipStr)
		return false
	}

	// No blacklist match + no whitelist configured = allow
	return true
}

// GetStats returns IP checker statistics
func (c *IPChecker) GetStats() map[string]any {
	if c == nil {
		return map[string]any{"enabled": false}
	}

	return map[string]any{
		"enabled":         true,
		"whitelist_rules": len(c.ipWhitelist),
		"blacklist_rules": len(c.ipBlacklist),
	}
}