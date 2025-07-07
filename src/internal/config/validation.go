// FILE: src/internal/config/validation.go
package config

import (
	"fmt"
	"strings"
)

func (c *Config) validate() error {
	if c.Monitor.CheckIntervalMs < 10 {
		return fmt.Errorf("check interval too small: %d ms", c.Monitor.CheckIntervalMs)
	}

	if len(c.Streams) == 0 {
		return fmt.Errorf("no streams configured")
	}

	// Validate each stream
	streamNames := make(map[string]bool)
	streamPorts := make(map[int]string)

	for i, stream := range c.Streams {
		if stream.Name == "" {
			return fmt.Errorf("stream %d: missing name", i)
		}

		if streamNames[stream.Name] {
			return fmt.Errorf("stream %d: duplicate name '%s'", i, stream.Name)
		}
		streamNames[stream.Name] = true

		// Stream must have targets
		if stream.Monitor == nil || len(stream.Monitor.Targets) == 0 {
			return fmt.Errorf("stream '%s': no monitor targets specified", stream.Name)
		}

		for j, target := range stream.Monitor.Targets {
			if target.Path == "" {
				return fmt.Errorf("stream '%s' target %d: empty path", stream.Name, j)
			}
			if strings.Contains(target.Path, "..") {
				return fmt.Errorf("stream '%s' target %d: path contains directory traversal", stream.Name, j)
			}
		}

		// Validate TCP server
		if stream.TCPServer != nil && stream.TCPServer.Enabled {
			if stream.TCPServer.Port < 1 || stream.TCPServer.Port > 65535 {
				return fmt.Errorf("stream '%s': invalid TCP port: %d", stream.Name, stream.TCPServer.Port)
			}
			if existing, exists := streamPorts[stream.TCPServer.Port]; exists {
				return fmt.Errorf("stream '%s': TCP port %d already used by stream '%s'",
					stream.Name, stream.TCPServer.Port, existing)
			}
			streamPorts[stream.TCPServer.Port] = stream.Name + "-tcp"

			if stream.TCPServer.BufferSize < 1 {
				return fmt.Errorf("stream '%s': TCP buffer size must be positive: %d",
					stream.Name, stream.TCPServer.BufferSize)
			}

			if err := validateHeartbeat("TCP", stream.Name, &stream.TCPServer.Heartbeat); err != nil {
				return err
			}

			if err := validateSSL("TCP", stream.Name, stream.TCPServer.SSL); err != nil {
				return err
			}
		}

		// Validate HTTP server
		if stream.HTTPServer != nil && stream.HTTPServer.Enabled {
			if stream.HTTPServer.Port < 1 || stream.HTTPServer.Port > 65535 {
				return fmt.Errorf("stream '%s': invalid HTTP port: %d", stream.Name, stream.HTTPServer.Port)
			}
			if existing, exists := streamPorts[stream.HTTPServer.Port]; exists {
				return fmt.Errorf("stream '%s': HTTP port %d already used by stream '%s'",
					stream.Name, stream.HTTPServer.Port, existing)
			}
			streamPorts[stream.HTTPServer.Port] = stream.Name + "-http"

			if stream.HTTPServer.BufferSize < 1 {
				return fmt.Errorf("stream '%s': HTTP buffer size must be positive: %d",
					stream.Name, stream.HTTPServer.BufferSize)
			}

			// Validate paths
			if stream.HTTPServer.StreamPath == "" {
				stream.HTTPServer.StreamPath = "/stream"
			}
			if stream.HTTPServer.StatusPath == "" {
				stream.HTTPServer.StatusPath = "/status"
			}
			if !strings.HasPrefix(stream.HTTPServer.StreamPath, "/") {
				return fmt.Errorf("stream '%s': stream path must start with /: %s",
					stream.Name, stream.HTTPServer.StreamPath)
			}
			if !strings.HasPrefix(stream.HTTPServer.StatusPath, "/") {
				return fmt.Errorf("stream '%s': status path must start with /: %s",
					stream.Name, stream.HTTPServer.StatusPath)
			}

			if err := validateHeartbeat("HTTP", stream.Name, &stream.HTTPServer.Heartbeat); err != nil {
				return err
			}

			if err := validateSSL("HTTP", stream.Name, stream.HTTPServer.SSL); err != nil {
				return err
			}
		}

		// At least one server must be enabled
		tcpEnabled := stream.TCPServer != nil && stream.TCPServer.Enabled
		httpEnabled := stream.HTTPServer != nil && stream.HTTPServer.Enabled
		if !tcpEnabled && !httpEnabled {
			return fmt.Errorf("stream '%s': no servers enabled", stream.Name)
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
			return fmt.Errorf("stream '%s' %s: heartbeat interval must be positive: %d",
				streamName, serverType, hb.IntervalSeconds)
		}
		if hb.Format != "json" && hb.Format != "comment" {
			return fmt.Errorf("stream '%s' %s: heartbeat format must be 'json' or 'comment': %s",
				streamName, serverType, hb.Format)
		}
	}
	return nil
}

func validateSSL(serverType, streamName string, ssl *SSLConfig) error {
	if ssl != nil && ssl.Enabled {
		if ssl.CertFile == "" || ssl.KeyFile == "" {
			return fmt.Errorf("stream '%s' %s: SSL enabled but cert/key files not specified",
				streamName, serverType)
		}

		if ssl.ClientAuth && ssl.ClientCAFile == "" {
			return fmt.Errorf("stream '%s' %s: client auth enabled but CA file not specified",
				streamName, serverType)
		}

		// Validate TLS versions
		validVersions := map[string]bool{"TLS1.0": true, "TLS1.1": true, "TLS1.2": true, "TLS1.3": true}
		if ssl.MinVersion != "" && !validVersions[ssl.MinVersion] {
			return fmt.Errorf("stream '%s' %s: invalid min TLS version: %s",
				streamName, serverType, ssl.MinVersion)
		}
		if ssl.MaxVersion != "" && !validVersions[ssl.MaxVersion] {
			return fmt.Errorf("stream '%s' %s: invalid max TLS version: %s",
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
		return fmt.Errorf("stream '%s': invalid auth type: %s", streamName, auth.Type)
	}

	if auth.Type == "basic" && auth.BasicAuth == nil {
		return fmt.Errorf("stream '%s': basic auth type specified but config missing", streamName)
	}

	if auth.Type == "bearer" && auth.BearerAuth == nil {
		return fmt.Errorf("stream '%s': bearer auth type specified but config missing", streamName)
	}

	return nil
}