// FILE: src/internal/config/validation.go
package config

import (
	"fmt"
	"regexp"
	"strings"

	"logwisp/src/internal/filter"
)

func (c *Config) validate() error {
	if len(c.Streams) == 0 {
		return fmt.Errorf("no streams configured")
	}

	// Validate each transport
	streamNames := make(map[string]bool)
	streamPorts := make(map[int]string)

	for i, stream := range c.Streams {
		if stream.Name == "" {
			return fmt.Errorf("transport %d: missing name", i)
		}

		if streamNames[stream.Name] {
			return fmt.Errorf("transport %d: duplicate name '%s'", i, stream.Name)
		}
		streamNames[stream.Name] = true

		// Stream must have monitor config with targets
		if stream.Monitor == nil || len(stream.Monitor.Targets) == 0 {
			return fmt.Errorf("transport '%s': no monitor targets specified", stream.Name)
		}

		// Validate check interval
		if stream.Monitor.CheckIntervalMs < 10 {
			return fmt.Errorf("transport '%s': check interval too small: %d ms (min: 10ms)",
				stream.Name, stream.Monitor.CheckIntervalMs)
		}

		// Validate targets
		for j, target := range stream.Monitor.Targets {
			if target.Path == "" {
				return fmt.Errorf("transport '%s' target %d: empty path", stream.Name, j)
			}
			if strings.Contains(target.Path, "..") {
				return fmt.Errorf("transport '%s' target %d: path contains directory traversal", stream.Name, j)
			}
		}

		// Validate filters
		for j, filterCfg := range stream.Filters {
			if err := validateFilter(stream.Name, j, &filterCfg); err != nil {
				return err
			}
		}

		// Validate TCP server
		if stream.TCPServer != nil && stream.TCPServer.Enabled {
			if stream.TCPServer.Port < 1 || stream.TCPServer.Port > 65535 {
				return fmt.Errorf("transport '%s': invalid TCP port: %d", stream.Name, stream.TCPServer.Port)
			}
			if existing, exists := streamPorts[stream.TCPServer.Port]; exists {
				return fmt.Errorf("transport '%s': TCP port %d already used by transport '%s'",
					stream.Name, stream.TCPServer.Port, existing)
			}
			streamPorts[stream.TCPServer.Port] = stream.Name + "-tcp"

			if stream.TCPServer.BufferSize < 1 {
				return fmt.Errorf("transport '%s': TCP buffer size must be positive: %d",
					stream.Name, stream.TCPServer.BufferSize)
			}

			if err := validateHeartbeat("TCP", stream.Name, &stream.TCPServer.Heartbeat); err != nil {
				return err
			}

			if err := validateSSL("TCP", stream.Name, stream.TCPServer.SSL); err != nil {
				return err
			}

			if err := validateRateLimit("TCP", stream.Name, stream.TCPServer.RateLimit); err != nil {
				return err
			}
		}

		// Validate HTTP server
		if stream.HTTPServer != nil && stream.HTTPServer.Enabled {
			if stream.HTTPServer.Port < 1 || stream.HTTPServer.Port > 65535 {
				return fmt.Errorf("transport '%s': invalid HTTP port: %d", stream.Name, stream.HTTPServer.Port)
			}
			if existing, exists := streamPorts[stream.HTTPServer.Port]; exists {
				return fmt.Errorf("transport '%s': HTTP port %d already used by transport '%s'",
					stream.Name, stream.HTTPServer.Port, existing)
			}
			streamPorts[stream.HTTPServer.Port] = stream.Name + "-http"

			if stream.HTTPServer.BufferSize < 1 {
				return fmt.Errorf("transport '%s': HTTP buffer size must be positive: %d",
					stream.Name, stream.HTTPServer.BufferSize)
			}

			// Validate paths
			if stream.HTTPServer.StreamPath == "" {
				stream.HTTPServer.StreamPath = "/transport"
			}
			if stream.HTTPServer.StatusPath == "" {
				stream.HTTPServer.StatusPath = "/status"
			}
			if !strings.HasPrefix(stream.HTTPServer.StreamPath, "/") {
				return fmt.Errorf("transport '%s': transport path must start with /: %s",
					stream.Name, stream.HTTPServer.StreamPath)
			}
			if !strings.HasPrefix(stream.HTTPServer.StatusPath, "/") {
				return fmt.Errorf("transport '%s': status path must start with /: %s",
					stream.Name, stream.HTTPServer.StatusPath)
			}

			if err := validateHeartbeat("HTTP", stream.Name, &stream.HTTPServer.Heartbeat); err != nil {
				return err
			}

			if err := validateSSL("HTTP", stream.Name, stream.HTTPServer.SSL); err != nil {
				return err
			}

			if err := validateRateLimit("HTTP", stream.Name, stream.HTTPServer.RateLimit); err != nil {
				return err
			}
		}

		// At least one server must be enabled
		tcpEnabled := stream.TCPServer != nil && stream.TCPServer.Enabled
		httpEnabled := stream.HTTPServer != nil && stream.HTTPServer.Enabled
		if !tcpEnabled && !httpEnabled {
			return fmt.Errorf("transport '%s': no servers enabled", stream.Name)
		}

		// Validate auth if present
		if err := validateAuth(stream.Name, stream.Auth); err != nil {
			return err
		}
	}

	return nil
}

func validateHeartbeat(serverType, streamName string, hb *HeartbeatConfig) error {
	if hb.Enabled {
		if hb.IntervalSeconds < 1 {
			return fmt.Errorf("transport '%s' %s: heartbeat interval must be positive: %d",
				streamName, serverType, hb.IntervalSeconds)
		}
		if hb.Format != "json" && hb.Format != "comment" {
			return fmt.Errorf("transport '%s' %s: heartbeat format must be 'json' or 'comment': %s",
				streamName, serverType, hb.Format)
		}
	}
	return nil
}

func validateSSL(serverType, streamName string, ssl *SSLConfig) error {
	if ssl != nil && ssl.Enabled {
		if ssl.CertFile == "" || ssl.KeyFile == "" {
			return fmt.Errorf("transport '%s' %s: SSL enabled but cert/key files not specified",
				streamName, serverType)
		}

		if ssl.ClientAuth && ssl.ClientCAFile == "" {
			return fmt.Errorf("transport '%s' %s: client auth enabled but CA file not specified",
				streamName, serverType)
		}

		// Validate TLS versions
		validVersions := map[string]bool{"TLS1.0": true, "TLS1.1": true, "TLS1.2": true, "TLS1.3": true}
		if ssl.MinVersion != "" && !validVersions[ssl.MinVersion] {
			return fmt.Errorf("transport '%s' %s: invalid min TLS version: %s",
				streamName, serverType, ssl.MinVersion)
		}
		if ssl.MaxVersion != "" && !validVersions[ssl.MaxVersion] {
			return fmt.Errorf("transport '%s' %s: invalid max TLS version: %s",
				streamName, serverType, ssl.MaxVersion)
		}
	}
	return nil
}

func validateAuth(streamName string, auth *AuthConfig) error {
	if auth == nil {
		return nil
	}

	validTypes := map[string]bool{"none": true, "basic": true, "bearer": true, "mtls": true}
	if !validTypes[auth.Type] {
		return fmt.Errorf("transport '%s': invalid auth type: %s", streamName, auth.Type)
	}

	if auth.Type == "basic" && auth.BasicAuth == nil {
		return fmt.Errorf("transport '%s': basic auth type specified but config missing", streamName)
	}

	if auth.Type == "bearer" && auth.BearerAuth == nil {
		return fmt.Errorf("transport '%s': bearer auth type specified but config missing", streamName)
	}

	return nil
}

func validateRateLimit(serverType, streamName string, rl *RateLimitConfig) error {
	if rl == nil || !rl.Enabled {
		return nil
	}

	if rl.RequestsPerSecond <= 0 {
		return fmt.Errorf("transport '%s' %s: requests_per_second must be positive: %f",
			streamName, serverType, rl.RequestsPerSecond)
	}

	if rl.BurstSize < 1 {
		return fmt.Errorf("transport '%s' %s: burst_size must be at least 1: %d",
			streamName, serverType, rl.BurstSize)
	}

	validLimitBy := map[string]bool{"ip": true, "global": true, "": true}
	if !validLimitBy[rl.LimitBy] {
		return fmt.Errorf("transport '%s' %s: invalid limit_by value: %s (must be 'ip' or 'global')",
			streamName, serverType, rl.LimitBy)
	}

	if rl.ResponseCode > 0 && (rl.ResponseCode < 400 || rl.ResponseCode >= 600) {
		return fmt.Errorf("transport '%s' %s: response_code must be 4xx or 5xx: %d",
			streamName, serverType, rl.ResponseCode)
	}

	if rl.MaxConnectionsPerIP > 0 && rl.MaxTotalConnections > 0 {
		if rl.MaxConnectionsPerIP > rl.MaxTotalConnections {
			return fmt.Errorf("stream '%s' %s: max_connections_per_ip (%d) cannot exceed max_total_connections (%d)",
				streamName, serverType, rl.MaxConnectionsPerIP, rl.MaxTotalConnections)
		}
	}

	return nil
}

func validateFilter(streamName string, filterIndex int, cfg *filter.Config) error {
	// Validate filter type
	switch cfg.Type {
	case filter.TypeInclude, filter.TypeExclude, "":
		// Valid types
	default:
		return fmt.Errorf("transport '%s' filter[%d]: invalid type '%s' (must be 'include' or 'exclude')",
			streamName, filterIndex, cfg.Type)
	}

	// Validate filter logic
	switch cfg.Logic {
	case filter.LogicOr, filter.LogicAnd, "":
		// Valid logic
	default:
		return fmt.Errorf("transport '%s' filter[%d]: invalid logic '%s' (must be 'or' or 'and')",
			streamName, filterIndex, cfg.Logic)
	}

	// Empty patterns is valid - passes everything
	if len(cfg.Patterns) == 0 {
		return nil
	}

	// Validate regex patterns
	for i, pattern := range cfg.Patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("transport '%s' filter[%d] pattern[%d] '%s': invalid regex: %w",
				streamName, filterIndex, i, pattern, err)
		}
	}

	return nil
}