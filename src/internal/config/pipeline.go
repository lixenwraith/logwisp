// FILE: src/internal/config/pipeline.go
package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// PipelineConfig represents a data processing pipeline
type PipelineConfig struct {
	// Pipeline identifier (used in logs and metrics)
	Name string `toml:"name"`

	// Data sources for this pipeline
	Sources []SourceConfig `toml:"sources"`

	// Filter configuration
	Filters []FilterConfig `toml:"filters"`

	// Output sinks for this pipeline
	Sinks []SinkConfig `toml:"sinks"`

	// Authentication/Authorization (applies to network sinks)
	Auth *AuthConfig `toml:"auth"`
}

// SourceConfig represents an input data source
type SourceConfig struct {
	// Source type: "directory", "file", "stdin", etc.
	Type string `toml:"type"`

	// Type-specific configuration options
	Options map[string]any `toml:"options"`

	// Placeholder for future source-side rate limiting
	// This will be used for features like aggregation and summarization
	RateLimit *RateLimitConfig `toml:"rate_limit"`
}

// SinkConfig represents an output destination
type SinkConfig struct {
	// Sink type: "http", "tcp", "file", "stdout", "stderr"
	Type string `toml:"type"`

	// Type-specific configuration options
	Options map[string]any `toml:"options"`
}

func validateSource(pipelineName string, sourceIndex int, cfg *SourceConfig) error {
	if cfg.Type == "" {
		return fmt.Errorf("pipeline '%s' source[%d]: missing type", pipelineName, sourceIndex)
	}

	switch cfg.Type {
	case "directory":
		// Validate directory source options
		path, ok := cfg.Options["path"].(string)
		if !ok || path == "" {
			return fmt.Errorf("pipeline '%s' source[%d]: directory source requires 'path' option",
				pipelineName, sourceIndex)
		}

		// Check for directory traversal
		if strings.Contains(path, "..") {
			return fmt.Errorf("pipeline '%s' source[%d]: path contains directory traversal",
				pipelineName, sourceIndex)
		}

		// Validate pattern if provided
		if pattern, ok := cfg.Options["pattern"].(string); ok && pattern != "" {
			// Try to compile as glob pattern (will be converted to regex internally)
			if strings.Count(pattern, "*") == 0 && strings.Count(pattern, "?") == 0 {
				// If no wildcards, ensure it's a valid filename
				if filepath.Base(pattern) != pattern {
					return fmt.Errorf("pipeline '%s' source[%d]: pattern contains path separators",
						pipelineName, sourceIndex)
				}
			}
		}

		// Validate check interval if provided
		if interval, ok := cfg.Options["check_interval_ms"]; ok {
			if intVal, ok := toInt(interval); ok {
				if intVal < 10 {
					return fmt.Errorf("pipeline '%s' source[%d]: check interval too small: %d ms (min: 10ms)",
						pipelineName, sourceIndex, intVal)
				}
			} else {
				return fmt.Errorf("pipeline '%s' source[%d]: invalid check_interval_ms type",
					pipelineName, sourceIndex)
			}
		}

	case "stdin":
		// No specific validation needed for stdin

	case "http":
		// Validate HTTP source options
		port, ok := toInt(cfg.Options["port"])
		if !ok || port < 1 || port > 65535 {
			return fmt.Errorf("pipeline '%s' source[%d]: invalid or missing HTTP port",
				pipelineName, sourceIndex)
		}

		// Validate path if provided
		if ingestPath, ok := cfg.Options["ingest_path"].(string); ok {
			if !strings.HasPrefix(ingestPath, "/") {
				return fmt.Errorf("pipeline '%s' source[%d]: ingest path must start with /: %s",
					pipelineName, sourceIndex, ingestPath)
			}
		}

	case "tcp":
		// Validate TCP source options
		port, ok := toInt(cfg.Options["port"])
		if !ok || port < 1 || port > 65535 {
			return fmt.Errorf("pipeline '%s' source[%d]: invalid or missing TCP port",
				pipelineName, sourceIndex)
		}

	default:
		return fmt.Errorf("pipeline '%s' source[%d]: unknown source type '%s'",
			pipelineName, sourceIndex, cfg.Type)
	}

	return nil
}

func validateSink(pipelineName string, sinkIndex int, cfg *SinkConfig, allPorts map[int]string) error {
	if cfg.Type == "" {
		return fmt.Errorf("pipeline '%s' sink[%d]: missing type", pipelineName, sinkIndex)
	}

	switch cfg.Type {
	case "http":
		// Extract and validate HTTP configuration
		port, ok := toInt(cfg.Options["port"])
		if !ok || port < 1 || port > 65535 {
			return fmt.Errorf("pipeline '%s' sink[%d]: invalid or missing HTTP port",
				pipelineName, sinkIndex)
		}

		// Check port conflicts
		if existing, exists := allPorts[port]; exists {
			return fmt.Errorf("pipeline '%s' sink[%d]: HTTP port %d already used by %s",
				pipelineName, sinkIndex, port, existing)
		}
		allPorts[port] = fmt.Sprintf("%s-http[%d]", pipelineName, sinkIndex)

		// Validate buffer size
		if bufSize, ok := toInt(cfg.Options["buffer_size"]); ok {
			if bufSize < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: HTTP buffer size must be positive: %d",
					pipelineName, sinkIndex, bufSize)
			}
		}

		// Validate paths if provided
		if streamPath, ok := cfg.Options["stream_path"].(string); ok {
			if !strings.HasPrefix(streamPath, "/") {
				return fmt.Errorf("pipeline '%s' sink[%d]: stream path must start with /: %s",
					pipelineName, sinkIndex, streamPath)
			}
		}

		if statusPath, ok := cfg.Options["status_path"].(string); ok {
			if !strings.HasPrefix(statusPath, "/") {
				return fmt.Errorf("pipeline '%s' sink[%d]: status path must start with /: %s",
					pipelineName, sinkIndex, statusPath)
			}
		}

		// Validate heartbeat if present
		if hb, ok := cfg.Options["heartbeat"].(map[string]any); ok {
			if err := validateHeartbeatOptions("HTTP", pipelineName, sinkIndex, hb); err != nil {
				return err
			}
		}

		// Validate SSL if present
		if ssl, ok := cfg.Options["ssl"].(map[string]any); ok {
			if err := validateSSLOptions("HTTP", pipelineName, sinkIndex, ssl); err != nil {
				return err
			}
		}

		// Validate rate limit if present
		if rl, ok := cfg.Options["rate_limit"].(map[string]any); ok {
			if err := validateRateLimitOptions("HTTP", pipelineName, sinkIndex, rl); err != nil {
				return err
			}
		}

	case "tcp":
		// Extract and validate TCP configuration
		port, ok := toInt(cfg.Options["port"])
		if !ok || port < 1 || port > 65535 {
			return fmt.Errorf("pipeline '%s' sink[%d]: invalid or missing TCP port",
				pipelineName, sinkIndex)
		}

		// Check port conflicts
		if existing, exists := allPorts[port]; exists {
			return fmt.Errorf("pipeline '%s' sink[%d]: TCP port %d already used by %s",
				pipelineName, sinkIndex, port, existing)
		}
		allPorts[port] = fmt.Sprintf("%s-tcp[%d]", pipelineName, sinkIndex)

		// Validate buffer size
		if bufSize, ok := toInt(cfg.Options["buffer_size"]); ok {
			if bufSize < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: TCP buffer size must be positive: %d",
					pipelineName, sinkIndex, bufSize)
			}
		}

		// Validate heartbeat if present
		if hb, ok := cfg.Options["heartbeat"].(map[string]any); ok {
			if err := validateHeartbeatOptions("TCP", pipelineName, sinkIndex, hb); err != nil {
				return err
			}
		}

		// Validate SSL if present
		if ssl, ok := cfg.Options["ssl"].(map[string]any); ok {
			if err := validateSSLOptions("TCP", pipelineName, sinkIndex, ssl); err != nil {
				return err
			}
		}

		// Validate rate limit if present
		if rl, ok := cfg.Options["rate_limit"].(map[string]any); ok {
			if err := validateRateLimitOptions("TCP", pipelineName, sinkIndex, rl); err != nil {
				return err
			}
		}

	case "http_client":
		// Validate URL
		urlStr, ok := cfg.Options["url"].(string)
		if !ok || urlStr == "" {
			return fmt.Errorf("pipeline '%s' sink[%d]: http_client sink requires 'url' option",
				pipelineName, sinkIndex)
		}

		// Validate URL format
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return fmt.Errorf("pipeline '%s' sink[%d]: invalid URL: %w",
				pipelineName, sinkIndex, err)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("pipeline '%s' sink[%d]: URL must use http or https scheme",
				pipelineName, sinkIndex)
		}

		// Validate batch size
		if batchSize, ok := toInt(cfg.Options["batch_size"]); ok {
			if batchSize < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: batch_size must be positive: %d",
					pipelineName, sinkIndex, batchSize)
			}
		}

		// Validate timeout
		if timeout, ok := toInt(cfg.Options["timeout_seconds"]); ok {
			if timeout < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: timeout_seconds must be positive: %d",
					pipelineName, sinkIndex, timeout)
			}
		}

	case "tcp_client":
		// FIXED: Added validation for TCP client sink
		// Validate address
		address, ok := cfg.Options["address"].(string)
		if !ok || address == "" {
			return fmt.Errorf("pipeline '%s' sink[%d]: tcp_client sink requires 'address' option",
				pipelineName, sinkIndex)
		}

		// Validate address format
		_, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("pipeline '%s' sink[%d]: invalid address format (expected host:port): %w",
				pipelineName, sinkIndex, err)
		}

		// Validate timeouts
		if dialTimeout, ok := toInt(cfg.Options["dial_timeout_seconds"]); ok {
			if dialTimeout < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: dial_timeout_seconds must be positive: %d",
					pipelineName, sinkIndex, dialTimeout)
			}
		}

		if writeTimeout, ok := toInt(cfg.Options["write_timeout_seconds"]); ok {
			if writeTimeout < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: write_timeout_seconds must be positive: %d",
					pipelineName, sinkIndex, writeTimeout)
			}
		}

	case "file":
		// Validate file sink options
		directory, ok := cfg.Options["directory"].(string)
		if !ok || directory == "" {
			return fmt.Errorf("pipeline '%s' sink[%d]: file sink requires 'directory' option",
				pipelineName, sinkIndex)
		}

		name, ok := cfg.Options["name"].(string)
		if !ok || name == "" {
			return fmt.Errorf("pipeline '%s' sink[%d]: file sink requires 'name' option",
				pipelineName, sinkIndex)
		}

		// Validate numeric options
		if maxSize, ok := toInt(cfg.Options["max_size_mb"]); ok {
			if maxSize < 1 {
				return fmt.Errorf("pipeline '%s' sink[%d]: max_size_mb must be positive: %d",
					pipelineName, sinkIndex, maxSize)
			}
		}

		if maxTotalSize, ok := toInt(cfg.Options["max_total_size_mb"]); ok {
			if maxTotalSize < 0 {
				return fmt.Errorf("pipeline '%s' sink[%d]: max_total_size_mb cannot be negative: %d",
					pipelineName, sinkIndex, maxTotalSize)
			}
		}

		if retention, ok := toFloat(cfg.Options["retention_hours"]); ok {
			if retention < 0 {
				return fmt.Errorf("pipeline '%s' sink[%d]: retention_hours cannot be negative: %f",
					pipelineName, sinkIndex, retention)
			}
		}

	case "stdout", "stderr":
		// No specific validation needed for console sinks

	default:
		return fmt.Errorf("pipeline '%s' sink[%d]: unknown sink type '%s'",
			pipelineName, sinkIndex, cfg.Type)
	}

	return nil
}