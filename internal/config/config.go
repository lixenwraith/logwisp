package config

// --- LogWisp Configuration Options ---

// Config is the top-level configuration structure for the LogWisp application
type Config struct {
	// Top-level flags for application control
	ShowVersion bool `toml:"version"`
	Quiet       bool `toml:"quiet"`

	// Runtime behavior flags
	StatusReporter   bool `toml:"status_reporter"`
	ConfigAutoReload bool `toml:"auto_reload"`

	// Configuration file path
	ConfigFile string `toml:"config_file"`

	// Existing fields
	Logging   *LogConfig       `toml:"logging"`
	Pipelines []PipelineConfig `toml:"pipelines"`
}

// --- Logging Options ---

// LogConfig represents the logging configuration for the LogWisp application itself
type LogConfig struct {
	// Output mode: "file", "stdout", "stderr", "split", "all", "none"
	Output string `toml:"output"`

	// Log level: "debug", "info", "warn", "error"
	Level string `toml:"level"`

	// Format: "raw", "txt", "json"
	Format string `toml:"format"`

	// Sanitization policy for console output
	Sanitization string `toml:"sanitization"`

	// File output settings (when Output includes "file" or "all")
	File *LogFileConfig `toml:"file"`

	// Console output settings
	Console *LogConsoleConfig `toml:"console"`
}

// LogFileConfig defines settings for file-based application logging
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

// LogConsoleConfig defines settings for console-based application logging
type LogConsoleConfig struct {
	// Target for console output: "stdout", "stderr"
	Target string `toml:"target"`
}

// --- Pipeline ---

// PipelineConfig defines a complete data flow from sources to sinks
type PipelineConfig struct {
	Name string      `toml:"name"`
	Flow *FlowConfig `toml:"flow"`

	PluginSources []PluginSourceConfig `toml:"plugin_sources,omitempty"`
	PluginSinks   []PluginSinkConfig   `toml:"plugin_sinks,omitempty"`
}

// --- Flow ---

// FlowConfig consolidates all processing stages between sources and sinks
type FlowConfig struct {
	Heartbeat *HeartbeatConfig `toml:"heartbeat"`
	RateLimit *RateLimitConfig `toml:"rate_limit"`
	Filters   []FilterConfig   `toml:"filters"`
	Format    *FormatConfig    `toml:"format"`
}

// --- Heartbeat Options ---

// HeartbeatConfig defines settings for periodic keep-alive or status messages
type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled"`
	IntervalMS       int64  `toml:"interval_ms"`
	IncludeTimestamp bool   `toml:"include_timestamp"`
	IncludeStats     bool   `toml:"include_stats"`
	Format           string `toml:"format"`
}

// --- Formatter Options ---

// FormatConfig is a polymorphic struct representing log entry formatting options
type FormatConfig struct {
	Type            string `toml:"type"` // "json", "txt", "raw"
	Flags           int64  `toml:"flags"`
	TimestampFormat string `toml:"timestamp_format"`
	SanitizerPolicy string `toml:"sanitizer_policy"` // "raw", "json", "txt", "shell"
}

// --- Rate Limit Options ---

// RateLimitPolicy defines the action to take when a rate limit is exceeded
type RateLimitPolicy int

const (
	// PolicyPass allows all logs through, effectively disabling the limiter
	PolicyPass RateLimitPolicy = iota
	// PolicyDrop drops logs that exceed the rate limit
	PolicyDrop
)

// RateLimitConfig defines the configuration for pipeline-level rate limiting
type RateLimitConfig struct {
	// Rate is the number of log entries allowed per second. Default: 0 (disabled)
	Rate float64 `toml:"rate"`
	// Burst is the maximum number of log entries that can be sent in a short burst. Defaults to the Rate
	Burst float64 `toml:"burst"`
	// Policy defines the action to take when the limit is exceeded. "pass" or "drop"
	Policy string `toml:"policy"`
	// MaxEntrySizeBytes is the maximum allowed size for a single log entry. 0 = no limit
	MaxEntrySizeBytes int64 `toml:"max_entry_size_bytes"`
}

// --- Filter Options ---

// FilterType represents the filter's behavior (include or exclude)
type FilterType string

const (
	// FilterTypeInclude specifies that only matching logs will pass
	FilterTypeInclude FilterType = "include" // Whitelist - only matching logs pass
	// FilterTypeExclude specifies that matching logs will be dropped
	FilterTypeExclude FilterType = "exclude" // Blacklist - matching logs are dropped
)

// FilterLogic represents how multiple filter patterns are combined
type FilterLogic string

const (
	// FilterLogicOr specifies that a match on any pattern is sufficient
	FilterLogicOr FilterLogic = "or" // Match any pattern
	// FilterLogicAnd specifies that all patterns must match
	FilterLogicAnd FilterLogic = "and" // Match all patterns
)

// FilterConfig represents the configuration for a single filter
type FilterConfig struct {
	Type     FilterType  `toml:"type"`
	Logic    FilterLogic `toml:"logic"`
	Patterns []string    `toml:"patterns"`
}

// --- Source Options ---

// PluginSourceConfig represents a source plugin instance configuration
type PluginSourceConfig struct {
	ID         string         `toml:"id"`
	Type       string         `toml:"type"`
	Config     map[string]any `toml:"config"`
	ConfigFile string         `toml:"config_file,omitempty"` // TODO: support for include/source mechanism for nested config
}

// // SourceConfig is a polymorphic struct representing a single data source
// type SourceConfig struct {
// 	Type string `toml:"type"`
//
// 	// Polymorphic - only one populated based on type
// 	File    *FileSourceOptions    `toml:"file,omitempty"`
// 	Console *ConsoleSourceOptions `toml:"console,omitempty"`
// }

// NullSourceOptions defines settings for a null source (no configuration needed)
type NullSourceOptions struct{}

// RandomSourceOptions defines settings for a random log generator source
type RandomSourceOptions struct {
	IntervalMS int64  `toml:"interval_ms"`
	JitterMS   int64  `toml:"jitter_ms"`
	Format     string `toml:"format"`
	Length     int64  `toml:"length"`
	Special    bool   `toml:"special"`
}

// FileSourceOptions defines settings for a file-based source
type FileSourceOptions struct {
	Directory       string `toml:"directory"`
	Pattern         string `toml:"pattern"` // glob pattern
	CheckIntervalMS int64  `toml:"check_interval_ms"`
}

// ConsoleSourceOptions defines settings for a stdin-based source
type ConsoleSourceOptions struct {
	BufferSize int64 `toml:"buffer_size"`
}

// TCPChainSourceOptions defines settings for a stdlib TCP listener ingesting
// NDJSON entries from upstream logwisp tcp_chain sinks
type TCPChainSourceOptions struct {
	Host           string `toml:"host"`
	Port           int64  `toml:"port"`
	BufferSize     int64  `toml:"buffer_size"`
	MaxConnections int64  `toml:"max_connections"`  // 0 = unlimited
	ReadTimeoutMS  int64  `toml:"read_timeout_ms"`  // per-connection idle deadline, 0 = none
	HelloTimeoutMS int64  `toml:"hello_timeout_ms"` // preamble deadline
	TrustNode      bool   `toml:"trust_node"`       // false: force node label from remote address
	// Future: TLS/auth options
}

// HTTPChainSourceOptions defines settings for a stdlib HTTP listener ingesting
// NDJSON batches from upstream logwisp http_chain sinks
type HTTPChainSourceOptions struct {
	Host          string `toml:"host"`
	Port          int64  `toml:"port"`
	IngestPath    string `toml:"ingest_path"`
	BufferSize    int64  `toml:"buffer_size"`
	MaxBodyBytes  int64  `toml:"max_body_bytes"`  // per-request cap
	ReadTimeoutMS int64  `toml:"read_timeout_ms"` // full request read deadline
	TrustNode     bool   `toml:"trust_node"`      // false: force node label from remote address
	// Future: TLS/auth options
}

// --- Sink Options ---

// PluginSinkConfig represents a sink plugin instance configuration
type PluginSinkConfig struct {
	ID         string         `toml:"id"`
	Type       string         `toml:"type"`
	Config     map[string]any `toml:"config"`
	ConfigFile string         `toml:"config_file,omitempty"` // TODO: support for include/source mechanism for nested config
}

// // SinkConfig is a polymorphic struct representing a single data sink
// type SinkConfig struct {
// 	Type string `toml:"type"`
//
// 	// Polymorphic - only one populated based on type
// 	Console *ConsoleSinkOptions `toml:"console,omitempty"`
// 	File    *FileSinkOptions    `toml:"file,omitempty"`
// }

// NullSinkOptions defines settings for a null sink (no configuration needed)
type NullSinkOptions struct{}

// ConsoleSinkOptions defines settings for a console-based sink
type ConsoleSinkOptions struct {
	Target     string `toml:"target"` // "stdout", "stderr"
	BufferSize int64  `toml:"buffer_size"`
}

// FileSinkOptions defines settings for a file-based sink
type FileSinkOptions struct {
	Directory       string  `toml:"directory"`
	Name            string  `toml:"name"`
	MaxSizeMB       int64   `toml:"max_size_mb"`
	MaxTotalSizeMB  int64   `toml:"max_total_size_mb"`
	MinDiskFreeMB   int64   `toml:"min_disk_free_mb"`
	RetentionHours  float64 `toml:"retention_hours"`
	BufferSize      int64   `toml:"buffer_size"`
	FlushIntervalMs int64   `toml:"flush_interval_ms"`
}

// TCPSinkOptions defines settings for a TCP server sink
type TCPSinkOptions struct {
	Host              string `toml:"host"`
	Port              int64  `toml:"port"`
	BufferSize        int64  `toml:"buffer_size"`        // sink input queue
	ClientBufferSize  int64  `toml:"client_buffer_size"` // per-client send queue
	WriteTimeoutMS    int64  `toml:"write_timeout_ms"`   // per-write deadline
	KeepAlive         bool   `toml:"keep_alive"`
	KeepAlivePeriodMS int64  `toml:"keep_alive_period_ms"`
	MaxConnections    int64  `toml:"max_connections"` // 0 = unlimited
	// Future: TLS (cert_file/key_file/client_ca), auth (token/mTLS) blocks
}

// HTTPSinkOptions defines settings for an HTTP SSE server sink
type HTTPSinkOptions struct {
	Host             string `toml:"host"`
	Port             int64  `toml:"port"`
	StreamPath       string `toml:"stream_path"`
	StatusPath       string `toml:"status_path"`
	BufferSize       int64  `toml:"buffer_size"`        // sink input queue
	ClientBufferSize int64  `toml:"client_buffer_size"` // per-client send queue
	WriteTimeoutMS   int64  `toml:"write_timeout_ms"`   // per-SSE-write deadline, 0 = none
	MaxConnections   int64  `toml:"max_connections"`    // 0 = unlimited
	// Future: TLS (server.TLSConfig), auth middleware options
}

// TCPChainSinkOptions defines settings for a stdlib TCP client forwarding
// entries to a downstream logwisp tcp_chain source
type TCPChainSinkOptions struct {
	Node              string `toml:"node"` // origin label, default: os.Hostname()
	Host              string `toml:"host"`
	Port              int64  `toml:"port"`
	BufferSize        int64  `toml:"buffer_size"`
	DialTimeoutMS     int64  `toml:"dial_timeout_ms"`
	WriteTimeoutMS    int64  `toml:"write_timeout_ms"`
	BackoffMinMS      int64  `toml:"backoff_min_ms"`
	BackoffMaxMS      int64  `toml:"backoff_max_ms"`
	KeepAlivePeriodMS int64  `toml:"keep_alive_period_ms"`
	KeepAlive         bool   `toml:"keep_alive"`
	// Future: TLS/auth options
}

// HTTPChainSinkOptions defines settings for a stdlib HTTP client posting
// NDJSON batches to a downstream logwisp http_chain source
type HTTPChainSinkOptions struct {
	Node             string `toml:"node"` // origin label, default: os.Hostname()
	Host             string `toml:"host"`
	Port             int64  `toml:"port"`
	IngestPath       string `toml:"ingest_path"`
	BufferSize       int64  `toml:"buffer_size"`
	MaxBatchCount    int64  `toml:"max_batch_count"`
	MaxBatchBytes    int64  `toml:"max_batch_bytes"`
	FlushIntervalMS  int64  `toml:"flush_interval_ms"`
	RequestTimeoutMS int64  `toml:"request_timeout_ms"` // covers dial + write + response
	BackoffMinMS     int64  `toml:"backoff_min_ms"`
	BackoffMaxMS     int64  `toml:"backoff_max_ms"`
	// Future: TLS/auth options
}
