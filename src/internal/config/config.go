// FILE: logwisp/src/internal/config/config.go
package config

// --- LogWisp Configuration Options ---

// Config is the top-level configuration structure for the LogWisp application.
type Config struct {
	// Top-level flags for application control
	Background  bool `toml:"background"`
	ShowVersion bool `toml:"version"`
	Quiet       bool `toml:"quiet"`

	// Runtime behavior flags
	DisableStatusReporter bool `toml:"disable_status_reporter"`
	ConfigAutoReload      bool `toml:"config_auto_reload"`

	// Internal flag indicating demonized child process (DO NOT SET IN CONFIG FILE)
	BackgroundDaemon bool

	// Configuration file path
	ConfigFile string `toml:"config_file"`

	// Existing fields
	Logging   *LogConfig       `toml:"logging"`
	Pipelines []PipelineConfig `toml:"pipelines"`
}

// --- Logging Options ---

// LogConfig represents the logging configuration for the LogWisp application itself.
type LogConfig struct {
	// Output mode: "file", "stdout", "stderr", "split", "all", "none"
	Output string `toml:"output"`

	// Log level: "debug", "info", "warn", "error"
	Level string `toml:"level"`

	// File output settings (when Output includes "file" or "all")
	File *LogFileConfig `toml:"file"`

	// Console output settings
	Console *LogConsoleConfig `toml:"console"`
}

// LogFileConfig defines settings for file-based application logging.
type LogFileConfig struct {
	// Directory for log files
	Directory string `toml:"directory"`

	// Base name for log files
	Name string `toml:"name"`

	// Maximum size per log file in MB
	MaxSizeMB int64 `toml:"max_size_mb"`

	// Maximum total size of all logs in MB
	MaxTotalSizeMB int64 `toml:"max_total_size_mb"`

	// Log retention in hours (0 = disabled)
	RetentionHours float64 `toml:"retention_hours"`
}

// LogConsoleConfig defines settings for console-based application logging.
type LogConsoleConfig struct {
	// Target for console output: "stdout", "stderr", "split"
	// "split": info/debug to stdout, warn/error to stderr
	Target string `toml:"target"`

	// Format: "txt" or "json"
	Format string `toml:"format"`
}

// --- Pipeline Options ---

// PipelineConfig defines a complete data flow from sources to sinks.
type PipelineConfig struct {
	Name      string           `toml:"name"`
	Sources   []SourceConfig   `toml:"sources"`
	RateLimit *RateLimitConfig `toml:"rate_limit"`
	Filters   []FilterConfig   `toml:"filters"`
	Format    *FormatConfig    `toml:"format"`
	Sinks     []SinkConfig     `toml:"sinks"`
}

// Common configuration structs used across components

// ACLConfig defines network-level access control and rate limiting rules.
type ACLConfig struct {
	Enabled             bool     `toml:"enabled"`
	RequestsPerSecond   float64  `toml:"requests_per_second"`
	BurstSize           int64    `toml:"burst_size"`
	ResponseMessage     string   `toml:"response_message"`
	ResponseCode        int64    `toml:"response_code"` // Default: 429
	MaxConnectionsPerIP int64    `toml:"max_connections_per_ip"`
	MaxConnectionsTotal int64    `toml:"max_connections_total"`
	IPWhitelist         []string `toml:"ip_whitelist"`
	IPBlacklist         []string `toml:"ip_blacklist"`
}

// TLSServerConfig defines TLS settings for a server (HTTP Source, HTTP Sink).
type TLSServerConfig struct {
	Enabled          bool   `toml:"enabled"`
	CertFile         string `toml:"cert_file"`          // Server's certificate file.
	KeyFile          string `toml:"key_file"`           // Server's private key file.
	ClientAuth       bool   `toml:"client_auth"`        // Enable/disable mTLS.
	ClientCAFile     string `toml:"client_ca_file"`     // CA for verifying client certificates.
	VerifyClientCert bool   `toml:"verify_client_cert"` // Require and verify client certs.

	// Common TLS settings
	MinVersion   string `toml:"min_version"` // "TLS1.2", "TLS1.3"
	MaxVersion   string `toml:"max_version"`
	CipherSuites string `toml:"cipher_suites"`
}

// TLSClientConfig defines TLS settings for a client (HTTP Client Sink).
type TLSClientConfig struct {
	Enabled            bool   `toml:"enabled"`
	ServerCAFile       string `toml:"server_ca_file"`       // CA for verifying the remote server's certificate.
	ClientCertFile     string `toml:"client_cert_file"`     // Client's certificate for mTLS.
	ClientKeyFile      string `toml:"client_key_file"`      // Client's private key for mTLS.
	ServerName         string `toml:"server_name"`          // For server certificate validation (SNI).
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"` // Skip server verification, Use with caution.

	// Common TLS settings
	MinVersion   string `toml:"min_version"`
	MaxVersion   string `toml:"max_version"`
	CipherSuites string `toml:"cipher_suites"`
}

// HeartbeatConfig defines settings for periodic keep-alive or status messages.
type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled"`
	IntervalMS       int64  `toml:"interval_ms"`
	IncludeTimestamp bool   `toml:"include_timestamp"`
	IncludeStats     bool   `toml:"include_stats"`
	Format           string `toml:"format"`
}

// TODO: Future implementation
// ClientAuthConfig defines settings for client-side authentication.
type ClientAuthConfig struct {
	Type string `toml:"type"` // "none"
}

// --- Source Options ---

// SourceConfig is a polymorphic struct representing a single data source.
type SourceConfig struct {
	Type string `toml:"type"`

	// Polymorphic - only one populated based on type
	File    *FileSourceOptions    `toml:"file,omitempty"`
	Console *ConsoleSourceOptions `toml:"console,omitempty"`
	HTTP    *HTTPSourceOptions    `toml:"http,omitempty"`
	TCP     *TCPSourceOptions     `toml:"tcp,omitempty"`
}

// FileSourceOptions defines settings for a file-based source.
type FileSourceOptions struct {
	Directory       string `toml:"directory"`
	Pattern         string `toml:"pattern"` // glob pattern
	CheckIntervalMS int64  `toml:"check_interval_ms"`
	Recursive       bool   `toml:"recursive"` // TODO: implement logic
}

// ConsoleSourceOptions defines settings for a stdin-based source.
type ConsoleSourceOptions struct {
	BufferSize int64 `toml:"buffer_size"`
}

// HTTPSourceOptions defines settings for an HTTP server source.
type HTTPSourceOptions struct {
	Host               string            `toml:"host"`
	Port               int64             `toml:"port"`
	IngestPath         string            `toml:"ingest_path"`
	BufferSize         int64             `toml:"buffer_size"`
	MaxRequestBodySize int64             `toml:"max_body_size"`
	ReadTimeout        int64             `toml:"read_timeout_ms"`
	WriteTimeout       int64             `toml:"write_timeout_ms"`
	ACL                *ACLConfig        `toml:"acl"`
	TLS                *TLSServerConfig  `toml:"tls"`
	Auth               *ServerAuthConfig `toml:"auth"`
}

// TCPSourceOptions defines settings for a TCP server source.
type TCPSourceOptions struct {
	Host            string            `toml:"host"`
	Port            int64             `toml:"port"`
	BufferSize      int64             `toml:"buffer_size"`
	ReadTimeout     int64             `toml:"read_timeout_ms"`
	KeepAlive       bool              `toml:"keep_alive"`
	KeepAlivePeriod int64             `toml:"keep_alive_period_ms"`
	ACL             *ACLConfig        `toml:"acl"`
	Auth            *ServerAuthConfig `toml:"auth"`
}

// --- Sink Options ---

// SinkConfig is a polymorphic struct representing a single data sink.
type SinkConfig struct {
	Type string `toml:"type"`

	// Polymorphic - only one populated based on type
	Console    *ConsoleSinkOptions    `toml:"console,omitempty"`
	File       *FileSinkOptions       `toml:"file,omitempty"`
	HTTP       *HTTPSinkOptions       `toml:"http,omitempty"`
	TCP        *TCPSinkOptions        `toml:"tcp,omitempty"`
	HTTPClient *HTTPClientSinkOptions `toml:"http_client,omitempty"`
	TCPClient  *TCPClientSinkOptions  `toml:"tcp_client,omitempty"`
}

// ConsoleSinkOptions defines settings for a console-based sink.
type ConsoleSinkOptions struct {
	Target     string `toml:"target"` // "stdout", "stderr", "split"
	Colorize   bool   `toml:"colorize"`
	BufferSize int64  `toml:"buffer_size"`
}

// FileSinkOptions defines settings for a file-based sink.
type FileSinkOptions struct {
	Directory      string  `toml:"directory"`
	Name           string  `toml:"name"`
	MaxSizeMB      int64   `toml:"max_size_mb"`
	MaxTotalSizeMB int64   `toml:"max_total_size_mb"`
	MinDiskFreeMB  int64   `toml:"min_disk_free_mb"`
	RetentionHours float64 `toml:"retention_hours"`
	BufferSize     int64   `toml:"buffer_size"`
	FlushInterval  int64   `toml:"flush_interval_ms"`
}

// HTTPSinkOptions defines settings for an HTTP server sink.
type HTTPSinkOptions struct {
	Host         string            `toml:"host"`
	Port         int64             `toml:"port"`
	StreamPath   string            `toml:"stream_path"`
	StatusPath   string            `toml:"status_path"`
	BufferSize   int64             `toml:"buffer_size"`
	WriteTimeout int64             `toml:"write_timeout_ms"`
	Heartbeat    *HeartbeatConfig  `toml:"heartbeat"`
	ACL          *ACLConfig        `toml:"acl"`
	TLS          *TLSServerConfig  `toml:"tls"`
	Auth         *ServerAuthConfig `toml:"auth"`
}

// TCPSinkOptions defines settings for a TCP server sink.
type TCPSinkOptions struct {
	Host            string            `toml:"host"`
	Port            int64             `toml:"port"`
	BufferSize      int64             `toml:"buffer_size"`
	WriteTimeout    int64             `toml:"write_timeout_ms"`
	KeepAlive       bool              `toml:"keep_alive"`
	KeepAlivePeriod int64             `toml:"keep_alive_period_ms"`
	Heartbeat       *HeartbeatConfig  `toml:"heartbeat"`
	ACL             *ACLConfig        `toml:"acl"`
	Auth            *ServerAuthConfig `toml:"auth"`
}

// HTTPClientSinkOptions defines settings for an HTTP client sink.
type HTTPClientSinkOptions struct {
	URL                string            `toml:"url"`
	BufferSize         int64             `toml:"buffer_size"`
	BatchSize          int64             `toml:"batch_size"`
	BatchDelayMS       int64             `toml:"batch_delay_ms"`
	Timeout            int64             `toml:"timeout_seconds"`
	MaxRetries         int64             `toml:"max_retries"`
	RetryDelayMS       int64             `toml:"retry_delay_ms"`
	RetryBackoff       float64           `toml:"retry_backoff"`
	InsecureSkipVerify bool              `toml:"insecure_skip_verify"`
	TLS                *TLSClientConfig  `toml:"tls"`
	Auth               *ClientAuthConfig `toml:"auth"`
}

// TCPClientSinkOptions defines settings for a TCP client sink.
type TCPClientSinkOptions struct {
	Host                string            `toml:"host"`
	Port                int64             `toml:"port"`
	BufferSize          int64             `toml:"buffer_size"`
	DialTimeout         int64             `toml:"dial_timeout_seconds"`
	WriteTimeout        int64             `toml:"write_timeout_seconds"`
	ReadTimeout         int64             `toml:"read_timeout_seconds"`
	KeepAlive           int64             `toml:"keep_alive_seconds"`
	ReconnectDelayMS    int64             `toml:"reconnect_delay_ms"`
	MaxReconnectDelayMS int64             `toml:"max_reconnect_delay_ms"`
	ReconnectBackoff    float64           `toml:"reconnect_backoff"`
	Auth                *ClientAuthConfig `toml:"auth"`
}

// --- Rate Limit Options ---

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

// --- Filter Options ---

// FilterType represents the filter's behavior (include or exclude).
type FilterType string

const (
	// FilterTypeInclude specifies that only matching logs will pass.
	FilterTypeInclude FilterType = "include" // Whitelist - only matching logs pass
	// FilterTypeExclude specifies that matching logs will be dropped.
	FilterTypeExclude FilterType = "exclude" // Blacklist - matching logs are dropped
)

// FilterLogic represents how multiple filter patterns are combined.
type FilterLogic string

const (
	// FilterLogicOr specifies that a match on any pattern is sufficient.
	FilterLogicOr FilterLogic = "or" // Match any pattern
	// FilterLogicAnd specifies that all patterns must match.
	FilterLogicAnd FilterLogic = "and" // Match all patterns
)

// FilterConfig represents the configuration for a single filter.
type FilterConfig struct {
	Type     FilterType  `toml:"type"`
	Logic    FilterLogic `toml:"logic"`
	Patterns []string    `toml:"patterns"`
}

// --- Formatter Options ---

// FormatConfig is a polymorphic struct representing log entry formatting options.
type FormatConfig struct {
	// Format configuration - polymorphic like sources/sinks
	Type string `toml:"type"` // "json", "txt", "raw"

	// Only one will be populated based on format type
	JSONFormatOptions *JSONFormatterOptions `toml:"json,omitempty"`
	TxtFormatOptions  *TxtFormatterOptions  `toml:"txt,omitempty"`
	RawFormatOptions  *RawFormatterOptions  `toml:"raw,omitempty"`
}

// JSONFormatterOptions defines settings for the JSON formatter.
type JSONFormatterOptions struct {
	Pretty         bool   `toml:"pretty"`
	TimestampField string `toml:"timestamp_field"`
	LevelField     string `toml:"level_field"`
	MessageField   string `toml:"message_field"`
	SourceField    string `toml:"source_field"`
}

// TxtFormatterOptions defines settings for the text template formatter.
type TxtFormatterOptions struct {
	Template        string `toml:"template"`
	TimestampFormat string `toml:"timestamp_format"`
}

// RawFormatterOptions defines settings for the raw pass-through formatter.
type RawFormatterOptions struct {
	AddNewLine bool `toml:"add_new_line"`
}

// --- Server-side Auth (for sources) ---

// TODO: future implementation
// ServerAuthConfig defines settings for server-side authentication.
type ServerAuthConfig struct {
	Type string `toml:"type"` // "none"
}