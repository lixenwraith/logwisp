package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	lconfig "github.com/lixenwraith/config"
)

// validateConfig is the centralized validator for the entire configuration
// This replaces the old (c *Config) validate() method
func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	if len(cfg.Pipelines) == 0 {
		return fmt.Errorf("no pipelines configured")
	}

	if err := validateLogConfig(cfg.Logging); err != nil {
		return fmt.Errorf("logging config: %w", err)
	}

	// Track used ports across all pipelines
	allPorts := make(map[int64]string)
	pipelineNames := make(map[string]bool)

	for i, pipeline := range cfg.Pipelines {
		if err := validatePipeline(i, &pipeline, pipelineNames, allPorts); err != nil {
			return err
		}
	}

	return nil
}

func validateLogConfig(cfg *LogConfig) error {
	validOutputs := map[string]bool{
		"file": true, "stdout": true, "stderr": true,
		"split": true, "all": true, "none": true,
	}
	if !validOutputs[cfg.Output] {
		return fmt.Errorf("invalid log output mode: %s", cfg.Output)
	}

	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLevels[cfg.Level] {
		return fmt.Errorf("invalid log level: %s", cfg.Level)
	}

	if cfg.Console != nil {
		validTargets := map[string]bool{
			"stdout": true, "stderr": true, "split": true,
		}
		if !validTargets[cfg.Console.Target] {
			return fmt.Errorf("invalid console target: %s", cfg.Console.Target)
		}

		validFormats := map[string]bool{
			"txt": true, "json": true, "": true,
		}
		if !validFormats[cfg.Console.Format] {
			return fmt.Errorf("invalid console format: %s", cfg.Console.Format)
		}
	}

	return nil
}

func validatePipeline(index int, p *PipelineConfig, pipelineNames map[string]bool, allPorts map[int64]string) error {
	// Validate pipeline name
	if err := lconfig.NonEmpty(p.Name); err != nil {
		return fmt.Errorf("pipeline %d: missing name", index)
	}

	if pipelineNames[p.Name] {
		return fmt.Errorf("pipeline %d: duplicate name '%s'", index, p.Name)
	}
	pipelineNames[p.Name] = true

	// Must have at least one source
	if len(p.Sources) == 0 {
		return fmt.Errorf("pipeline '%s': no sources specified", p.Name)
	}

	// Validate each source
	for j, source := range p.Sources {
		if err := validateSourceConfig(p.Name, j, &source); err != nil {
			return err
		}
	}

	// Validate rate limit if present
	if p.RateLimit != nil {
		if err := validateRateLimit(p.Name, p.RateLimit); err != nil {
			return err
		}
	}

	// Validate filters
	for j, filter := range p.Filters {
		if err := validateFilter(p.Name, j, &filter); err != nil {
			return err
		}
	}

	// Validate formatter configuration
	if err := validateFormatterConfig(p); err != nil {
		return fmt.Errorf("pipeline '%s': %w", p.Name, err)
	}

	// Must have at least one sink
	if len(p.Sinks) == 0 {
		return fmt.Errorf("pipeline '%s': no sinks specified", p.Name)
	}

	// Validate each sink
	for j, sink := range p.Sinks {
		if err := validateSinkConfig(p.Name, j, &sink, allPorts); err != nil {
			return err
		}
	}

	return nil
}

// validateSourceConfig validates typed source configuration
func validateSourceConfig(pipelineName string, index int, s *SourceConfig) error {
	if err := lconfig.NonEmpty(s.Type); err != nil {
		return fmt.Errorf("pipeline '%s' source[%d]: missing type", pipelineName, index)
	}

	// Count how many source configs are populated
	populated := 0
	var populatedType string

	if s.Directory != nil {
		populated++
		populatedType = "directory"
	}
	if s.Stdin != nil {
		populated++
		populatedType = "stdin"
	}
	if s.HTTP != nil {
		populated++
		populatedType = "http"
	}
	if s.TCP != nil {
		populated++
		populatedType = "tcp"
	}

	if populated == 0 {
		return fmt.Errorf("pipeline '%s' source[%d]: no configuration provided for type '%s'",
			pipelineName, index, s.Type)
	}
	if populated > 1 {
		return fmt.Errorf("pipeline '%s' source[%d]: multiple configurations provided, only one allowed",
			pipelineName, index)
	}
	if populatedType != s.Type {
		return fmt.Errorf("pipeline '%s' source[%d]: type mismatch - type is '%s' but config is for '%s'",
			pipelineName, index, s.Type, populatedType)
	}

	// Validate specific source type
	switch s.Type {
	case "directory":
		return validateDirectorySource(pipelineName, index, s.Directory)
	case "stdin":
		return validateStdinSource(pipelineName, index, s.Stdin)
	case "http":
		return validateHTTPSource(pipelineName, index, s.HTTP)
	case "tcp":
		return validateTCPSource(pipelineName, index, s.TCP)
	default:
		return fmt.Errorf("pipeline '%s' source[%d]: unknown type '%s'", pipelineName, index, s.Type)
	}
}

func validateDirectorySource(pipelineName string, index int, opts *DirectorySourceOptions) error {
	if err := lconfig.NonEmpty(opts.Path); err != nil {
		return fmt.Errorf("pipeline '%s' source[%d]: directory requires 'path'", pipelineName, index)
	} else {
		absPath, err := filepath.Abs(opts.Path)
		if err != nil {
			return fmt.Errorf("invalid path %s: %w", opts.Path, err)
		}
		opts.Path = absPath
	}

	// Check for directory traversal
	// TODO: traversal check only if optional security settings from cli/env set
	if strings.Contains(opts.Path, "..") {
		return fmt.Errorf("pipeline '%s' source[%d]: path contains directory traversal", pipelineName, index)
	}

	// Validate pattern if provided
	if opts.Pattern != "" {
		if strings.Count(opts.Pattern, "*") == 0 && strings.Count(opts.Pattern, "?") == 0 {
			// If no wildcards, ensure valid filename
			if filepath.Base(opts.Pattern) != opts.Pattern {
				return fmt.Errorf("pipeline '%s' source[%d]: pattern contains path separators", pipelineName, index)
			}
		}
	} else {
		opts.Pattern = "*"
	}

	// Validate check interval
	if opts.CheckIntervalMS < 10 {
		return fmt.Errorf("pipeline '%s' source[%d]: check_interval_ms must be at least 10ms", pipelineName, index)
	}

	return nil
}

func validateStdinSource(pipelineName string, index int, opts *StdinSourceOptions) error {
	if opts.BufferSize < 0 {
		return fmt.Errorf("pipeline '%s' source[%d]: buffer_size must be positive", pipelineName, index)
	} else if opts.BufferSize == 0 {
		opts.BufferSize = 1000
	}
	return nil
}

func validateHTTPSource(pipelineName string, index int, opts *HTTPSourceOptions) error {
	// Validate port
	if err := lconfig.Port(opts.Port); err != nil {
		return fmt.Errorf("pipeline '%s' source[%d]: %w", pipelineName, index, err)
	}

	// Set defaults
	if opts.Host == "" {
		opts.Host = "0.0.0.0"
	}
	if opts.IngestPath == "" {
		opts.IngestPath = "/ingest"
	}
	if opts.MaxRequestBodySize <= 0 {
		opts.MaxRequestBodySize = 10 * 1024 * 1024 // 10MB default
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 5000 // 5 seconds
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 5000 // 5 seconds
	}

	// Validate host if specified
	if opts.Host != "" && opts.Host != "0.0.0.0" {
		if err := lconfig.IPAddress(opts.Host); err != nil {
			return fmt.Errorf("pipeline '%s' source[%d]: %w", pipelineName, index, err)
		}
	}

	// Validate paths
	if !strings.HasPrefix(opts.IngestPath, "/") {
		return fmt.Errorf("pipeline '%s' source[%d]: ingest_path must start with /", pipelineName, index)
	}

	// Validate auth configuration
	validHTTPSourceAuthTypes := map[string]bool{"basic": true, "token": true, "mtls": true}
	if opts.Auth != nil && opts.Auth.Type != "none" && opts.Auth.Type != "" {
		if !validHTTPSourceAuthTypes[opts.Auth.Type] {
			return fmt.Errorf("pipeline '%s' source[%d]: %s is not a valid auth type",
				pipelineName, index, opts.Auth.Type)
		}
		// All non-none auth types require TLS for HTTP
		if opts.TLS == nil || !opts.TLS.Enabled {
			return fmt.Errorf("pipeline '%s' source[%d]: %s auth requires TLS to be enabled",
				pipelineName, index, opts.Auth.Type)
		}

		// Validate specific auth types
		if err := validateServerAuth(pipelineName, opts.Auth); err != nil {
			return fmt.Errorf("source[%d]: %w", index, err)
		}
	}

	// Validate nested configs
	if opts.NetLimit != nil {
		if err := validateNetLimit(pipelineName, fmt.Sprintf("source[%d]", index), opts.NetLimit); err != nil {
			return err
		}
	}

	if opts.TLS != nil {
		if err := validateTLS(pipelineName, fmt.Sprintf("source[%d]", index), opts.TLS); err != nil {
			return err
		}
	}

	return nil
}

func validateTCPSource(pipelineName string, index int, opts *TCPSourceOptions) error {
	// Validate port
	if err := lconfig.Port(opts.Port); err != nil {
		return fmt.Errorf("pipeline '%s' source[%d]: %w", pipelineName, index, err)
	}

	// Set defaults
	if opts.Host == "" {
		opts.Host = "0.0.0.0"
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 5000 // 5 seconds
	}
	if !opts.KeepAlive {
		opts.KeepAlive = true // Default enabled
	}
	if opts.KeepAlivePeriod <= 0 {
		opts.KeepAlivePeriod = 30000 // 30 seconds
	}

	// Validate host if specified
	if opts.Host != "" && opts.Host != "0.0.0.0" {
		if err := lconfig.IPAddress(opts.Host); err != nil {
			return fmt.Errorf("pipeline '%s' source[%d]: %w", pipelineName, index, err)
		}
	}

	// TCP source does NOT support TLS
	// Validate auth configuration - only none and scram are allowed
	if opts.Auth != nil {
		switch opts.Auth.Type {
		case "", "none":
			// OK
		case "scram":
			// SCRAM doesn't require TLS
			if err := validateServerAuth(pipelineName, opts.Auth); err != nil {
				return fmt.Errorf("source[%d]: %w", index, err)
			}
		default:
			return fmt.Errorf("pipeline '%s' source[%d]: TCP source only supports 'none' or 'scram' auth (got '%s')",
				pipelineName, index, opts.Auth.Type)
		}
	}

	// Validate NetLimit if present
	if opts.NetLimit != nil {
		if err := validateNetLimit(pipelineName, fmt.Sprintf("source[%d]", index), opts.NetLimit); err != nil {
			return err
		}
	}

	return nil
}

// validateSinkConfig validates typed sink configuration
func validateSinkConfig(pipelineName string, index int, s *SinkConfig, allPorts map[int64]string) error {
	if err := lconfig.NonEmpty(s.Type); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: missing type", pipelineName, index)
	}

	// Count populated sink configs
	populated := 0
	var populatedType string

	if s.Console != nil {
		populated++
		populatedType = "console"
	}
	if s.File != nil {
		populated++
		populatedType = "file"
	}
	if s.HTTP != nil {
		populated++
		populatedType = "http"
	}
	if s.TCP != nil {
		populated++
		populatedType = "tcp"
	}
	if s.HTTPClient != nil {
		populated++
		populatedType = "http_client"
	}
	if s.TCPClient != nil {
		populated++
		populatedType = "tcp_client"
	}

	if populated == 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: no configuration provided for type '%s'",
			pipelineName, index, s.Type)
	}
	if populated > 1 {
		return fmt.Errorf("pipeline '%s' sink[%d]: multiple configurations provided, only one allowed",
			pipelineName, index)
	}
	if populatedType != s.Type {
		return fmt.Errorf("pipeline '%s' sink[%d]: type mismatch - type is '%s' but config is for '%s'",
			pipelineName, index, s.Type, populatedType)
	}

	// Validate specific sink type
	switch s.Type {
	case "console":
		return validateConsoleSink(pipelineName, index, s.Console)
	case "file":
		return validateFileSink(pipelineName, index, s.File)
	case "http":
		return validateHTTPSink(pipelineName, index, s.HTTP, allPorts)
	case "tcp":
		return validateTCPSink(pipelineName, index, s.TCP, allPorts)
	case "http_client":
		return validateHTTPClientSink(pipelineName, index, s.HTTPClient)
	case "tcp_client":
		return validateTCPClientSink(pipelineName, index, s.TCPClient)
	default:
		return fmt.Errorf("pipeline '%s' sink[%d]: unknown type '%s'", pipelineName, index, s.Type)
	}
}

func validateConsoleSink(pipelineName string, index int, opts *ConsoleSinkOptions) error {
	if opts.BufferSize < 1 {
		return fmt.Errorf("pipeline '%s' sink[%d]: buffer_size must be positive", pipelineName, index)
	}
	return nil
}

func validateFileSink(pipelineName string, index int, opts *FileSinkOptions) error {
	if err := lconfig.NonEmpty(opts.Directory); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: file requires 'directory'", pipelineName, index)
	}

	if err := lconfig.NonEmpty(opts.Name); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: file requires 'name'", pipelineName, index)
	}

	if opts.BufferSize <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: max_size_mb must be positive", pipelineName, index)
	}

	// Validate sizes
	if opts.MaxSizeMB < 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: max_size_mb must be positive", pipelineName, index)
	}

	if opts.MaxTotalSizeMB <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: max_total_size_mb cannot be negative", pipelineName, index)
	}

	if opts.MinDiskFreeMB < 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: min_disk_free_mb must be positive", pipelineName, index)
	}

	if opts.RetentionHours <= 0 {
		return fmt.Errorf("pipeline '%s' sink[%d]: retention_hours cannot be negative", pipelineName, index)
	}

	return nil
}

func validateHTTPSink(pipelineName string, index int, opts *HTTPSinkOptions, allPorts map[int64]string) error {
	// Validate port
	if err := lconfig.Port(opts.Port); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: %w", pipelineName, index, err)
	}

	// Check port conflicts
	if existing, exists := allPorts[opts.Port]; exists {
		return fmt.Errorf("pipeline '%s' sink[%d]: port %d already used by %s",
			pipelineName, index, opts.Port, existing)
	}
	allPorts[opts.Port] = fmt.Sprintf("%s-http[%d]", pipelineName, index)

	// Validate host if specified
	if opts.Host != "" {
		if err := lconfig.IPAddress(opts.Host); err != nil {
			return fmt.Errorf("pipeline '%s' sink[%d]: %w", pipelineName, index, err)
		}
	}

	// Validate paths
	if !strings.HasPrefix(opts.StreamPath, "/") {
		return fmt.Errorf("pipeline '%s' sink[%d]: stream_path must start with /", pipelineName, index)
	}

	if !strings.HasPrefix(opts.StatusPath, "/") {
		return fmt.Errorf("pipeline '%s' sink[%d]: status_path must start with /", pipelineName, index)
	}

	// Validate buffer
	if opts.BufferSize < 1 {
		return fmt.Errorf("pipeline '%s' sink[%d]: buffer_size must be positive", pipelineName, index)
	}

	// Validate nested configs
	if opts.Heartbeat != nil {
		if err := validateHeartbeat(pipelineName, fmt.Sprintf("sink[%d]", index), opts.Heartbeat); err != nil {
			return err
		}
	}

	if opts.NetLimit != nil {
		if err := validateNetLimit(pipelineName, fmt.Sprintf("sink[%d]", index), opts.NetLimit); err != nil {
			return err
		}
	}

	if opts.TLS != nil {
		if err := validateTLS(pipelineName, fmt.Sprintf("sink[%d]", index), opts.TLS); err != nil {
			return err
		}
	}

	return nil
}

func validateTCPSink(pipelineName string, index int, opts *TCPSinkOptions, allPorts map[int64]string) error {
	// Validate port
	if err := lconfig.Port(opts.Port); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: %w", pipelineName, index, err)
	}

	// Check port conflicts
	if existing, exists := allPorts[opts.Port]; exists {
		return fmt.Errorf("pipeline '%s' sink[%d]: port %d already used by %s",
			pipelineName, index, opts.Port, existing)
	}
	allPorts[opts.Port] = fmt.Sprintf("%s-tcp[%d]", pipelineName, index)

	// Validate host if specified
	if opts.Host != "" {
		if err := lconfig.IPAddress(opts.Host); err != nil {
			return fmt.Errorf("pipeline '%s' sink[%d]: %w", pipelineName, index, err)
		}
	}

	// Validate buffer
	if opts.BufferSize < 1 {
		return fmt.Errorf("pipeline '%s' sink[%d]: buffer_size must be positive", pipelineName, index)
	}

	// Validate nested configs
	if opts.Heartbeat != nil {
		if err := validateHeartbeat(pipelineName, fmt.Sprintf("sink[%d]", index), opts.Heartbeat); err != nil {
			return err
		}
	}

	if opts.NetLimit != nil {
		if err := validateNetLimit(pipelineName, fmt.Sprintf("sink[%d]", index), opts.NetLimit); err != nil {
			return err
		}
	}

	return nil
}

func validateHTTPClientSink(pipelineName string, index int, opts *HTTPClientSinkOptions) error {
	// Validate URL
	if err := lconfig.NonEmpty(opts.URL); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: http_client requires 'url'", pipelineName, index)
	}

	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: invalid URL: %w", pipelineName, index, err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("pipeline '%s' sink[%d]: URL must use http or https scheme", pipelineName, index)
	}

	isHTTPS := parsedURL.Scheme == "https"

	// Set defaults for unspecified fields
	if opts.BufferSize <= 0 {
		opts.BufferSize = 1000
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}
	if opts.BatchDelayMS <= 0 {
		opts.BatchDelayMS = 1000 // 1 second in ms
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 // 30 seconds
	}
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 3
	}
	if opts.RetryDelayMS <= 0 {
		opts.RetryDelayMS = 1000 // 1 second in ms
	}
	if opts.RetryBackoff < 1.0 {
		opts.RetryBackoff = 2.0
	}
	if opts.Headers == nil {
		opts.Headers = make(map[string]string)
	}

	// Set default Content-Type if not specified
	if _, exists := opts.Headers["Content-Type"]; !exists {
		opts.Headers["Content-Type"] = "application/json"
	}

	// Validate auth configuration
	if opts.Auth != nil {
		switch opts.Auth.Type {
		case "basic":
			if opts.Auth.Username == "" || opts.Auth.Password == "" {
				return fmt.Errorf("pipeline '%s' sink[%d]: username and password required for basic auth",
					pipelineName, index)
			}
			if !isHTTPS && !opts.InsecureSkipVerify {
				return fmt.Errorf("pipeline '%s' sink[%d]: basic auth requires HTTPS (security: credentials would be sent in plaintext)",
					pipelineName, index)
			}

		case "token":
			if opts.Auth.Token == "" {
				return fmt.Errorf("pipeline '%s' sink[%d]: token required for %s auth",
					pipelineName, index, opts.Auth.Type)
			}
			if !isHTTPS && !opts.InsecureSkipVerify {
				return fmt.Errorf("pipeline '%s' sink[%d]: %s auth requires HTTPS (security: token would be sent in plaintext)",
					pipelineName, index, opts.Auth.Type)
			}

		case "mtls":
			if !isHTTPS {
				return fmt.Errorf("pipeline '%s' sink[%d]: mTLS requires HTTPS",
					pipelineName, index)
			}
			// mTLS certs should be in TLS config, not auth config
			if opts.TLS == nil || opts.TLS.CertFile == "" || opts.TLS.KeyFile == "" {
				return fmt.Errorf("pipeline '%s' sink[%d]: cert_file and key_file required in TLS config for mTLS auth",
					pipelineName, index)
			}

		case "none", "":
			// Clear any credentials if auth is "none" or empty
			if opts.Auth != nil {
				opts.Auth.Username = ""
				opts.Auth.Password = ""
				opts.Auth.Token = ""
			}

		default:
			return fmt.Errorf("pipeline '%s' sink[%d]: invalid auth type '%s' (valid: none, basic, token, mtls)",
				pipelineName, index, opts.Auth.Type)
		}
	}

	// Validate TLS config if present
	if opts.TLS != nil {
		if err := validateTLS(pipelineName, fmt.Sprintf("sink[%d]", index), opts.TLS); err != nil {
			return err
		}
	}

	return nil
}

func validateTCPClientSink(pipelineName string, index int, opts *TCPClientSinkOptions) error {
	// Validate host and port
	if err := lconfig.NonEmpty(opts.Host); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: tcp_client requires 'host'", pipelineName, index)
	}

	if err := lconfig.Port(opts.Port); err != nil {
		return fmt.Errorf("pipeline '%s' sink[%d]: %w", pipelineName, index, err)
	}

	// Set defaults
	if opts.BufferSize <= 0 {
		opts.BufferSize = 1000
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 // 10 seconds
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 30 // 30 seconds
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 10 // 10 seconds
	}
	if opts.KeepAlive <= 0 {
		opts.KeepAlive = 30 // 30 seconds
	}
	if opts.ReconnectDelayMS <= 0 {
		opts.ReconnectDelayMS = 1000 // 1 second in ms
	}
	if opts.MaxReconnectDelayMS <= 0 {
		opts.MaxReconnectDelayMS = 30000 // 30 seconds in ms
	}
	if opts.ReconnectBackoff < 1.0 {
		opts.ReconnectBackoff = 1.5
	}

	// Validate auth configuration
	if opts.Auth != nil {
		switch opts.Auth.Type {

		case "scram":
			if opts.Auth.Username == "" || opts.Auth.Password == "" {
				return fmt.Errorf("pipeline '%s' sink[%d]: username and password required for SCRAM auth",
					pipelineName, index)
			}
			// SCRAM doesn't require TLS as it uses challenge-response

		case "none", "":
			// Clear credentials
			if opts.Auth != nil {
				opts.Auth.Username = ""
				opts.Auth.Password = ""
				opts.Auth.Token = ""
			}

		default:
			return fmt.Errorf("pipeline '%s' sink[%d]: invalid auth type '%s' (valid: none, basic, token, scram, mtls)",
				pipelineName, index, opts.Auth.Type)
		}
	}

	return nil
}

// validateFormatterConfig validates formatter configuration
func validateFormatterConfig(p *PipelineConfig) error {
	if p.Format == nil {
		p.Format = &FormatConfig{
			Type: "raw",
		}
	} else if p.Format.Type == "" {
		p.Format.Type = "raw" // Default
	}

	switch p.Format.Type {

	case "raw":
		if p.Format.RawFormatOptions == nil {
			p.Format.RawFormatOptions = &RawFormatterOptions{}
		}

	case "txt":
		if p.Format.TextFormatOptions == nil {
			p.Format.TextFormatOptions = &TextFormatterOptions{}
		}

		// Default template format
		templateStr := "[{{.Timestamp | FmtTime}}] [{{.Level | ToUpper}}] {{.Source}} - {{.Message}}{{ if .Fields }} {{.Fields}}{{ end }}"
		if p.Format.TextFormatOptions.Template != "" {
			p.Format.TextFormatOptions.Template = templateStr
		}

		// Default timestamp format
		timestampFormat := time.RFC3339
		if p.Format.TextFormatOptions.TimestampFormat != "" {
			p.Format.TextFormatOptions.TimestampFormat = timestampFormat
		}

	case "json":
		if p.Format.JSONFormatOptions == nil {
			p.Format.JSONFormatOptions = &JSONFormatterOptions{}
		}
	}

	return nil
}

// Helper validation functions for nested configs
func validateNetLimit(pipelineName, location string, nl *NetLimitConfig) error {
	if !nl.Enabled {
		return nil // Skip validation if disabled
	}

	if nl.MaxConnections < 0 {
		return fmt.Errorf("pipeline '%s' %s: max_connections cannot be negative", pipelineName, location)
	}

	if nl.BurstSize < 0 {
		return fmt.Errorf("pipeline '%s' %s: burst_size cannot be negative", pipelineName, location)
	}

	return nil
}

func validateTLS(pipelineName, location string, tls *TLSConfig) error {
	if !tls.Enabled {
		return nil // Skip validation if disabled
	}

	// If TLS enabled, cert and key files required (unless skip verify)
	if !tls.SkipVerify {
		if tls.CertFile == "" || tls.KeyFile == "" {
			return fmt.Errorf("pipeline '%s' %s: TLS enabled requires cert_file and key_file", pipelineName, location)
		}
	}

	return nil
}

func validateHeartbeat(pipelineName, location string, hb *HeartbeatConfig) error {
	if !hb.Enabled {
		return nil // Skip validation if disabled
	}

	if hb.Interval < 1000 { // At least 1 second
		return fmt.Errorf("pipeline '%s' %s: heartbeat interval must be at least 1000ms", pipelineName, location)
	}

	return nil
}

func validateServerAuth(pipelineName string, auth *ServerAuthConfig) error {
	if auth.Type == "" || auth.Type == "none" {
		return nil
	}

	// Count populated auth configs
	populated := 0
	var populatedType string

	if auth.Basic != nil {
		populated++
		populatedType = "basic"
	}
	if auth.Token != nil {
		populated++
		populatedType = "token"
	}
	if auth.Scram != nil {
		populated++
		populatedType = "scram"
	}

	if populated == 0 {
		return fmt.Errorf("pipeline '%s': auth type '%s' specified but config missing", pipelineName, auth.Type)
	}
	if populated > 1 {
		return fmt.Errorf("pipeline '%s': multiple auth configurations provided", pipelineName)
	}
	if populatedType != auth.Type {
		return fmt.Errorf("pipeline '%s': auth type mismatch - type is '%s' but config is for '%s'",
			pipelineName, auth.Type, populatedType)
	}

	// Validate specific auth type
	switch auth.Type {
	case "basic":
		if len(auth.Basic.Users) == 0 {
			return fmt.Errorf("pipeline '%s': basic auth requires at least one user", pipelineName)
		}
		for i, user := range auth.Basic.Users {
			if err := lconfig.NonEmpty(user.Username); err != nil {
				return fmt.Errorf("pipeline '%s': basic auth user[%d] missing username", pipelineName, i)
			}
			if err := lconfig.NonEmpty(user.PasswordHash); err != nil {
				return fmt.Errorf("pipeline '%s': basic auth user[%d] missing password_hash", pipelineName, i)
			}
		}
	case "token":
		if len(auth.Token.Tokens) == 0 {
			return fmt.Errorf("pipeline '%s': token auth requires at least one token", pipelineName)
		}
	case "scram":
		if len(auth.Scram.Users) == 0 {
			return fmt.Errorf("pipeline '%s': scram auth requires at least one user", pipelineName)
		}
		for i, user := range auth.Scram.Users {
			if err := lconfig.NonEmpty(user.Username); err != nil {
				return fmt.Errorf("pipeline '%s': scram auth user[%d] missing username", pipelineName, i)
			}
			// Validate required SCRAM fields
			if user.StoredKey == "" || user.ServerKey == "" || user.Salt == "" {
				return fmt.Errorf("pipeline '%s': scram auth user[%d] missing required fields", pipelineName, i)
			}
		}
	default:
		return fmt.Errorf("pipeline '%s': unknown auth type '%s'", pipelineName, auth.Type)
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

func validateFilter(pipelineName string, filterIndex int, cfg *FilterConfig) error {
	// Validate filter type
	switch cfg.Type {
	case FilterTypeInclude, FilterTypeExclude, "":
		// Valid types
	default:
		return fmt.Errorf("pipeline '%s' filter[%d]: invalid type '%s' (must be 'include' or 'exclude')",
			pipelineName, filterIndex, cfg.Type)
	}

	// Validate filter logic
	switch cfg.Logic {
	case FilterLogicOr, FilterLogicAnd, "":
		// Valid logic
	default:
		return fmt.Errorf("pipeline '%s' filter[%d]: invalid logic '%s' (must be 'or' or 'and')",
			pipelineName, filterIndex, cfg.Logic)
	}

	// Empty patterns is valid - passes everything
	if len(cfg.Patterns) == 0 {
		return nil
	}

	// Validate regex patterns
	for i, pattern := range cfg.Patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("pipeline '%s' filter[%d] pattern[%d] '%s': invalid regex: %w",
				pipelineName, filterIndex, i, pattern, err)
		}
	}

	return nil
}