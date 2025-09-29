// FILE: logwisp/src/internal/config/server.go
package config

import (
	"fmt"
	"net"
	"strings"
)

type TCPConfig struct {
	Enabled    bool  `toml:"enabled"`
	Port       int64 `toml:"port"`
	BufferSize int64 `toml:"buffer_size"`

	// Net limiting
	NetLimit *NetLimitConfig `toml:"net_limit"`

	// Heartbeat
	Heartbeat *HeartbeatConfig `toml:"heartbeat"`
}

type HTTPConfig struct {
	Enabled    bool  `toml:"enabled"`
	Port       int64 `toml:"port"`
	BufferSize int64 `toml:"buffer_size"`

	// Endpoint paths
	StreamPath string `toml:"stream_path"`
	StatusPath string `toml:"status_path"`

	// TLS Configuration
	TLS *TLSConfig `toml:"tls"`

	// Nate limiting
	NetLimit *NetLimitConfig `toml:"net_limit"`

	// Heartbeat
	Heartbeat *HeartbeatConfig `toml:"heartbeat"`
}

type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled"`
	IntervalSeconds  int64  `toml:"interval_seconds"`
	IncludeTimestamp bool   `toml:"include_timestamp"`
	IncludeStats     bool   `toml:"include_stats"`
	Format           string `toml:"format"`
}

type NetLimitConfig struct {
	// Enable net limiting
	Enabled bool `toml:"enabled"`

	// IP Access Control Lists
	IPWhitelist []string `toml:"ip_whitelist"`
	IPBlacklist []string `toml:"ip_blacklist"`

	// Requests per second per client
	RequestsPerSecond float64 `toml:"requests_per_second"`

	// Burst size (token bucket)
	BurstSize int64 `toml:"burst_size"`

	// Response when net limited
	ResponseCode    int64  `toml:"response_code"`    // Default: 429
	ResponseMessage string `toml:"response_message"` // Default: "Net limit exceeded"

	// Connection limits
	MaxConnectionsPerIP    int64 `toml:"max_connections_per_ip"`
	MaxConnectionsPerUser  int64 `toml:"max_connections_per_user"`
	MaxConnectionsPerToken int64 `toml:"max_connections_per_token"`
	MaxConnectionsTotal    int64 `toml:"max_connections_total"`
}

func validateHeartbeatOptions(serverType, pipelineName string, sinkIndex int, hb map[string]any) error {
	if enabled, ok := hb["enabled"].(bool); ok && enabled {
		interval, ok := hb["interval_seconds"].(int64)
		if !ok || interval < 1 {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: heartbeat interval must be positive",
				pipelineName, sinkIndex, serverType)
		}

		if format, ok := hb["format"].(string); ok {
			if format != "json" && format != "comment" {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: heartbeat format must be 'json' or 'comment': %s",
					pipelineName, sinkIndex, serverType, format)
			}
		}
	}
	return nil
}

func validateNetLimitOptions(serverType, pipelineName string, sinkIndex int, nl map[string]any) error {
	if enabled, ok := nl["enabled"].(bool); !ok || !enabled {
		return nil
	}

	// Validate IP lists if present
	if ipWhitelist, ok := nl["ip_whitelist"].([]any); ok {
		for i, entry := range ipWhitelist {
			entryStr, ok := entry.(string)
			if !ok {
				continue
			}
			if err := validateIPv4Entry(entryStr); err != nil {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: whitelist[%d] %v",
					pipelineName, sinkIndex, serverType, i, err)
			}
		}
	}

	if ipBlacklist, ok := nl["ip_blacklist"].([]any); ok {
		for i, entry := range ipBlacklist {
			entryStr, ok := entry.(string)
			if !ok {
				continue
			}
			if err := validateIPv4Entry(entryStr); err != nil {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: blacklist[%d] %v",
					pipelineName, sinkIndex, serverType, i, err)
			}
		}
	}

	// Validate requests per second
	rps, ok := nl["requests_per_second"].(float64)
	if !ok || rps <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d] %s: requests_per_second must be positive",
			pipelineName, sinkIndex, serverType)
	}

	// Validate burst size
	burst, ok := nl["burst_size"].(int64)
	if !ok || burst < 1 {
		return fmt.Errorf("pipeline '%s' sink[%d] %s: burst_size must be at least 1",
			pipelineName, sinkIndex, serverType)
	}

	// Validate response code
	if respCode, ok := nl["response_code"].(int64); ok {
		if respCode > 0 && (respCode < 400 || respCode >= 600) {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: response_code must be 4xx or 5xx: %d",
				pipelineName, sinkIndex, serverType, respCode)
		}
	}

	// Validate connection limits
	maxPerIP, perIPOk := nl["max_connections_per_ip"].(int64)
	maxPerUser, perUserOk := nl["max_connections_per_user"].(int64)
	maxPerToken, perTokenOk := nl["max_connections_per_token"].(int64)
	maxTotal, totalOk := nl["max_connections_total"].(int64)

	if perIPOk && perUserOk && perTokenOk && totalOk &&
		maxPerIP > 0 && maxPerUser > 0 && maxPerToken > 0 && maxTotal > 0 {
		if maxPerIP > maxTotal {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: max_connections_per_ip (%d) cannot exceed max_connections_total (%d)",
				pipelineName, sinkIndex, serverType, maxPerIP, maxTotal)
		}
		if maxPerUser > maxTotal {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: max_connections_per_user (%d) cannot exceed max_connections_total (%d)",
				pipelineName, sinkIndex, serverType, maxPerUser, maxTotal)
		}
		if maxPerToken > maxTotal {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: max_connections_per_token (%d) cannot exceed max_connections_total (%d)",
				pipelineName, sinkIndex, serverType, maxPerToken, maxTotal)
		}
	}

	return nil
}

// Ensures an IP or CIDR is IPv4
func validateIPv4Entry(entry string) error {
	// Handle single IP
	if !strings.Contains(entry, "/") {
		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", entry)
		}
		if ip.To4() == nil {
			return fmt.Errorf("IPv6 not supported (IPv4-only): %s", entry)
		}
		return nil
	}

	// Handle CIDR
	ipAddr, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", entry)
	}

	// Check if the IP is IPv4
	if ipAddr.To4() == nil {
		return fmt.Errorf("IPv6 CIDR not supported (IPv4-only): %s", entry)
	}

	// Verify the network mask is appropriate for IPv4
	_, bits := ipNet.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("invalid IPv4 CIDR mask (got %d bits, expected 32): %s", bits, entry)
	}

	return nil
}