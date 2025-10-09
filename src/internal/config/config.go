// FILE: logwisp/src/internal/config/config.go
package config

// --- LogWisp Configuration Options ---

type Config struct {
	// Top-level flags for application control
	Background  bool `toml:"background"`
	ShowVersion bool `toml:"version"`
	Quiet       bool `toml:"quiet"`

	// Runtime behavior flags
	DisableStatusReporter bool `toml:"disable_status_reporter"`
	ConfigAutoReload      bool `toml:"config_auto_reload"`

	// Internal flag indicating demonized child process
	BackgroundDaemon bool `toml:"background-daemon"`

	// Configuration file path
	ConfigFile string `toml:"config"`

	// Existing fields
	Logging   *LogConfig       `toml:"logging"`
	Pipelines []PipelineConfig `toml:"pipelines"`
}

// --- Logging Options ---

// Represents logging configuration for LogWisp
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

type LogConsoleConfig struct {
	// Target for console output: "stdout", "stderr", "split"
	// "split": info/debug to stdout, warn/error to stderr
	Target string `toml:"target"`

	// Format: "txt" or "json"
	Format string `toml:"format"`
}

// --- Pipeline Options ---

type PipelineConfig struct {
	Name      string           `toml:"name"`
	Sources   []SourceConfig   `toml:"sources"`
	RateLimit *RateLimitConfig `toml:"rate_limit"`
	Filters   []FilterConfig   `toml:"filters"`
	Format    *FormatConfig    `toml:"format"`

	Sinks []SinkConfig `toml:"sinks"`
	// Auth  *ServerAuthConfig `toml:"auth"` // Global auth for pipeline
}

// Common configuration structs used across components

type NetLimitConfig struct {
	Enabled                bool     `toml:"enabled"`
	MaxConnections         int64    `toml:"max_connections"`
	RequestsPerSecond      float64  `toml:"requests_per_second"`
	BurstSize              int64    `toml:"burst_size"`
	ResponseMessage        string   `toml:"response_message"`
	ResponseCode           int64    `toml:"response_code"` // Default: 429
	MaxConnectionsPerIP    int64    `toml:"max_connections_per_ip"`
	MaxConnectionsPerUser  int64    `toml:"max_connections_per_user"`
	MaxConnectionsPerToken int64    `toml:"max_connections_per_token"`
	MaxConnectionsTotal    int64    `toml:"max_connections_total"`
	IPWhitelist            []string `toml:"ip_whitelist"`
	IPBlacklist            []string `toml:"ip_blacklist"`
}

type TLSConfig struct {
	Enabled    bool   `toml:"enabled"`
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	CAFile     string `toml:"ca_file"`
	ServerName string `toml:"server_name"` // for client verification
	SkipVerify bool   `toml:"skip_verify"`

	// Client certificate authentication
	ClientAuth       bool   `toml:"client_auth"`
	ClientCAFile     string `toml:"client_ca_file"`
	VerifyClientCert bool   `toml:"verify_client_cert"`

	// TLS version constraints
	MinVersion string `toml:"min_version"` // "TLS1.2", "TLS1.3"
	MaxVersion string `toml:"max_version"`

	// Cipher suites (comma-separated list)
	CipherSuites string `toml:"cipher_suites"`
}

type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled"`
	Interval         int64  `toml:"interval_ms"`
	IncludeTimestamp bool   `toml:"include_timestamp"`
	IncludeStats     bool   `toml:"include_stats"`
	Format           string `toml:"format"`
}

type ClientAuthConfig struct {
	Type     string `toml:"type"` // "none", "basic", "token", "scram"
	Username string `toml:"username"`
	Password string `toml:"password"`
	Token    string `toml:"token"`
}

// --- Source Options ---

type SourceConfig struct {
	Type string `toml:"type"`

	// Polymorphic - only one populated based on type
	Directory *DirectorySourceOptions `toml:"directory,omitempty"`
	Stdin     *StdinSourceOptions     `toml:"stdin,omitempty"`
	HTTP      *HTTPSourceOptions      `toml:"http,omitempty"`
	TCP       *TCPSourceOptions       `toml:"tcp,omitempty"`
}

type DirectorySourceOptions struct {
	Path            string `toml:"path"`
	Pattern         string `toml:"pattern"` // glob pattern
	CheckIntervalMS int64  `toml:"check_interval_ms"`
	Recursive       bool   `toml:"recursive"`
	FollowSymlinks  bool   `toml:"follow_symlinks"`
	DeleteAfterRead bool   `toml:"delete_after_read"`
	MoveToDirectory string `toml:"move_to_directory"` // move after processing
}

type StdinSourceOptions struct {
	BufferSize int64 `toml:"buffer_size"`
}

type HTTPSourceOptions struct {
	Host               string            `toml:"host"`
	Port               int64             `toml:"port"`
	IngestPath         string            `toml:"ingest_path"`
	BufferSize         int64             `toml:"buffer_size"`
	MaxRequestBodySize int64             `toml:"max_body_size"`
	ReadTimeout        int64             `toml:"read_timeout_ms"`
	WriteTimeout       int64             `toml:"write_timeout_ms"`
	NetLimit           *NetLimitConfig   `toml:"net_limit"`
	TLS                *TLSConfig        `toml:"tls"`
	Auth               *ServerAuthConfig `toml:"auth"`
}

type TCPSourceOptions struct {
	Host            string            `toml:"host"`
	Port            int64             `toml:"port"`
	BufferSize      int64             `toml:"buffer_size"`
	ReadTimeout     int64             `toml:"read_timeout_ms"`
	KeepAlive       bool              `toml:"keep_alive"`
	KeepAlivePeriod int64             `toml:"keep_alive_period_ms"`
	NetLimit        *NetLimitConfig   `toml:"net_limit"`
	Auth            *ServerAuthConfig `toml:"auth"`
}

// --- Sink Options ---

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

type ConsoleSinkOptions struct {
	Target     string `toml:"target"` // "stdout", "stderr", "split"
	Colorize   bool   `toml:"colorize"`
	BufferSize int64  `toml:"buffer_size"`
}

type FileSinkOptions struct {
	Directory string `toml:"directory"`
	Name      string `toml:"name"`
	//  Extension      string  `toml:"extension"`
	MaxSizeMB      int64   `toml:"max_size_mb"`
	MaxTotalSizeMB int64   `toml:"max_total_size_mb"`
	MinDiskFreeMB  int64   `toml:"min_disk_free_mb"`
	RetentionHours float64 `toml:"retention_hours"`
	BufferSize     int64   `toml:"buffer_size"`
	FlushInterval  int64   `toml:"flush_interval_ms"`
}

type HTTPSinkOptions struct {
	Host         string            `toml:"host"`
	Port         int64             `toml:"port"`
	StreamPath   string            `toml:"stream_path"`
	StatusPath   string            `toml:"status_path"`
	BufferSize   int64             `toml:"buffer_size"`
	WriteTimeout int64             `toml:"write_timeout_ms"`
	Heartbeat    *HeartbeatConfig  `toml:"heartbeat"`
	NetLimit     *NetLimitConfig   `toml:"net_limit"`
	TLS          *TLSConfig        `toml:"tls"`
	Auth         *ServerAuthConfig `toml:"auth"`
}

type TCPSinkOptions struct {
	Host            string            `toml:"host"`
	Port            int64             `toml:"port"`
	BufferSize      int64             `toml:"buffer_size"`
	WriteTimeout    int64             `toml:"write_timeout_ms"`
	KeepAlive       bool              `toml:"keep_alive"`
	KeepAlivePeriod int64             `toml:"keep_alive_period_ms"`
	Heartbeat       *HeartbeatConfig  `toml:"heartbeat"`
	NetLimit        *NetLimitConfig   `toml:"net_limit"`
	Auth            *ServerAuthConfig `toml:"auth"`
}

type HTTPClientSinkOptions struct {
	URL                string            `toml:"url"`
	Headers            map[string]string `toml:"headers"`
	BufferSize         int64             `toml:"buffer_size"`
	BatchSize          int64             `toml:"batch_size"`
	BatchDelayMS       int64             `toml:"batch_delay_ms"`
	Timeout            int64             `toml:"timeout_seconds"`
	MaxRetries         int64             `toml:"max_retries"`
	RetryDelayMS       int64             `toml:"retry_delay_ms"`
	RetryBackoff       float64           `toml:"retry_backoff"`
	InsecureSkipVerify bool              `toml:"insecure_skip_verify"`
	TLS                *TLSConfig        `toml:"tls"`
	Auth               *ClientAuthConfig `toml:"auth"`
}

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

// Defines the action to take when a rate limit is exceeded.
type RateLimitPolicy int

const (
	// PolicyPass allows all logs through, effectively disabling the limiter.
	PolicyPass RateLimitPolicy = iota
	// PolicyDrop drops logs that exceed the rate limit.
	PolicyDrop
)

// Defines the configuration for pipeline-level rate limiting.
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

// Represents the filter type
type FilterType string

const (
	FilterTypeInclude FilterType = "include" // Whitelist - only matching logs pass
	FilterTypeExclude FilterType = "exclude" // Blacklist - matching logs are dropped
)

// Represents how multiple patterns are combined
type FilterLogic string

const (
	FilterLogicOr  FilterLogic = "or"  // Match any pattern
	FilterLogicAnd FilterLogic = "and" // Match all patterns
)

// Represents filter configuration
type FilterConfig struct {
	Type     FilterType  `toml:"type"`
	Logic    FilterLogic `toml:"logic"`
	Patterns []string    `toml:"patterns"`
}

// --- Formatter Options ---

type FormatConfig struct {
	// Format configuration - polymorphic like sources/sinks
	Type string `toml:"type"` // "json", "text", "raw"

	// Only one will be populated based on format type
	JSONFormatOptions *JSONFormatterOptions `toml:"json_format,omitempty"`
	TextFormatOptions *TextFormatterOptions `toml:"text_format,omitempty"`
	RawFormatOptions  *RawFormatterOptions  `toml:"raw_format,omitempty"`
}

type JSONFormatterOptions struct {
	Pretty         bool   `toml:"pretty"`
	TimestampField string `toml:"timestamp_field"`
	LevelField     string `toml:"level_field"`
	MessageField   string `toml:"message_field"`
	SourceField    string `toml:"source_field"`
}

type TextFormatterOptions struct {
	Template        string `toml:"template"`
	TimestampFormat string `toml:"timestamp_format"`
}

type RawFormatterOptions struct {
	AddNewLine bool `toml:"add_new_line"`
}

// --- Server-side Auth (for sources) ---

type BasicAuthConfig struct {
	Users []BasicAuthUser `toml:"users"`
	Realm string          `toml:"realm"`
}

type BasicAuthUser struct {
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"` // Argon2
}

type ScramAuthConfig struct {
	Users []ScramUser `toml:"users"`
}

type ScramUser struct {
	Username     string `toml:"username"`
	StoredKey    string `toml:"stored_key"` // base64
	ServerKey    string `toml:"server_key"` // base64
	Salt         string `toml:"salt"`       // base64
	ArgonTime    uint32 `toml:"argon_time"`
	ArgonMemory  uint32 `toml:"argon_memory"`
	ArgonThreads uint8  `toml:"argon_threads"`
}

type TokenAuthConfig struct {
	Tokens []string `toml:"tokens"`
}

// Server auth wrapper (for sources accepting connections)
type ServerAuthConfig struct {
	Type  string           `toml:"type"` // "none", "basic", "token", "scram"
	Basic *BasicAuthConfig `toml:"basic,omitempty"`
	Token *TokenAuthConfig `toml:"token,omitempty"`
	Scram *ScramAuthConfig `toml:"scram,omitempty"`
}