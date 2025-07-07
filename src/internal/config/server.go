// FILE: src/internal/config/server.go
package config

type TCPConfig struct {
	Enabled    bool `toml:"enabled"`
	Port       int  `toml:"port"`
	BufferSize int  `toml:"buffer_size"`

	// SSL/TLS Configuration
	SSL *SSLConfig `toml:"ssl"`

	// Rate limiting
	RateLimit *RateLimitConfig `toml:"rate_limit"`

	// Heartbeat
	Heartbeat HeartbeatConfig `toml:"heartbeat"`
}

type HTTPConfig struct {
	Enabled    bool `toml:"enabled"`
	Port       int  `toml:"port"`
	BufferSize int  `toml:"buffer_size"`

	// Endpoint paths
	StreamPath string `toml:"stream_path"`
	StatusPath string `toml:"status_path"`

	// SSL/TLS Configuration
	SSL *SSLConfig `toml:"ssl"`

	// Rate limiting
	RateLimit *RateLimitConfig `toml:"rate_limit"`

	// Heartbeat
	Heartbeat HeartbeatConfig `toml:"heartbeat"`
}

type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled"`
	IntervalSeconds  int    `toml:"interval_seconds"`
	IncludeTimestamp bool   `toml:"include_timestamp"`
	IncludeStats     bool   `toml:"include_stats"`
	Format           string `toml:"format"` // "comment" or "json"
}

type RateLimitConfig struct {
	// Enable rate limiting
	Enabled bool `toml:"enabled"`

	// Requests per second per client
	RequestsPerSecond float64 `toml:"requests_per_second"`

	// Burst size (token bucket)
	BurstSize int `toml:"burst_size"`

	// Rate limit by: "ip", "user", "token"
	LimitBy string `toml:"limit_by"`

	// Response when rate limited
	ResponseCode    int    `toml:"response_code"`    // Default: 429
	ResponseMessage string `toml:"response_message"` // Default: "Rate limit exceeded"
}