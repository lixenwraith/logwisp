// File: logwisp/src/internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

// Config holds the complete configuration
type Config struct {
	Port    int           `toml:"port"`
	Monitor MonitorConfig `toml:"monitor"`
	Stream  StreamConfig  `toml:"stream"`
}

// MonitorConfig holds monitoring settings
type MonitorConfig struct {
	CheckIntervalMs int             `toml:"check_interval_ms"`
	Targets         []MonitorTarget `toml:"targets"`
}

// MonitorTarget represents a path to monitor
type MonitorTarget struct {
	Path    string `toml:"path"`    // File or directory path
	Pattern string `toml:"pattern"` // Glob pattern for directories
	IsFile  bool   `toml:"is_file"` // True if monitoring specific file
}

// StreamConfig holds streaming settings
type StreamConfig struct {
	BufferSize int             `toml:"buffer_size"`
	RateLimit  RateLimitConfig `toml:"rate_limit"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled           bool  `toml:"enabled"`
	RequestsPerSecond int   `toml:"requests_per_second"`
	BurstSize         int   `toml:"burst_size"`
	CleanupIntervalS  int64 `toml:"cleanup_interval_s"`
}

// defaults returns configuration with default values
func defaults() *Config {
	return &Config{
		Port: 8080,
		Monitor: MonitorConfig{
			CheckIntervalMs: 100,
			Targets: []MonitorTarget{
				{Path: "./", Pattern: "*.log", IsFile: false},
			},
		},
		Stream: StreamConfig{
			BufferSize: 1000,
			RateLimit: RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 10,
				BurstSize:         20,
				CleanupIntervalS:  60,
			},
		},
	}
}

// Load reads configuration using lixenwraith/config Builder pattern
func Load() (*Config, error) {
	configPath := GetConfigPath()

	cfg, err := lconfig.NewBuilder().
		WithDefaults(defaults()).
		WithEnvPrefix("LOGWISP_").
		WithFile(configPath).
		WithEnvTransform(customEnvTransform).
		WithSources(
			lconfig.SourceEnv,
			lconfig.SourceFile,
			lconfig.SourceDefault,
		).
		Build()

	if err != nil {
		// Only fail on actual errors, not missing config file
		if !strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Special handling for LOGWISP_MONITOR_TARGETS env var
	if err := handleMonitorTargetsEnv(cfg); err != nil {
		return nil, err
	}

	// Scan into final config
	finalConfig := &Config{}
	if err := cfg.Scan("", finalConfig); err != nil {
		return nil, fmt.Errorf("failed to scan config: %w", err)
	}

	return finalConfig, finalConfig.validate()
}

// LoadWithCLI loads configuration and applies CLI arguments
func LoadWithCLI(cliArgs []string) (*Config, error) {
	configPath := GetConfigPath()

	// Convert CLI args to config format
	convertedArgs := convertCLIArgs(cliArgs)

	cfg, err := lconfig.NewBuilder().
		WithDefaults(defaults()).
		WithEnvPrefix("LOGWISP_").
		WithFile(configPath).
		WithArgs(convertedArgs).
		WithEnvTransform(customEnvTransform).
		WithSources(
			lconfig.SourceCLI, // CLI highest priority
			lconfig.SourceEnv,
			lconfig.SourceFile,
			lconfig.SourceDefault,
		).
		Build()

	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Handle special env var
	if err := handleMonitorTargetsEnv(cfg); err != nil {
		return nil, err
	}

	// Scan into final config
	finalConfig := &Config{}
	if err := cfg.Scan("", finalConfig); err != nil {
		return nil, fmt.Errorf("failed to scan config: %w", err)
	}

	return finalConfig, finalConfig.validate()
}

// customEnvTransform handles LOGWISP_ prefix environment variables
func customEnvTransform(path string) string {
	// Standard transform
	env := strings.ReplaceAll(path, ".", "_")
	env = strings.ToUpper(env)
	env = "LOGWISP_" + env

	// Handle common variations
	switch env {
	case "LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SECOND":
		if _, exists := os.LookupEnv("LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SEC"); exists {
			return "LOGWISP_STREAM_RATE_LIMIT_REQUESTS_PER_SEC"
		}
	case "LOGWISP_STREAM_RATE_LIMIT_CLEANUP_INTERVAL_S":
		if _, exists := os.LookupEnv("LOGWISP_STREAM_RATE_LIMIT_CLEANUP_INTERVAL"); exists {
			return "LOGWISP_STREAM_RATE_LIMIT_CLEANUP_INTERVAL"
		}
	}

	return env
}

// convertCLIArgs converts CLI args to config package format
func convertCLIArgs(args []string) []string {
	var converted []string

	for _, arg := range args {
		switch {
		case arg == "-c" || arg == "--color":
			// Color mode is handled separately by main.go
			continue
		case strings.HasPrefix(arg, "--config="):
			// Config file path handled separately
			continue
		case strings.HasPrefix(arg, "--"):
			// Pass through other long flags
			converted = append(converted, arg)
		}
	}

	return converted
}

// GetConfigPath returns the configuration file path
func GetConfigPath() string {
	// Check explicit config file paths
	if configFile := os.Getenv("LOGWISP_CONFIG_FILE"); configFile != "" {
		if filepath.IsAbs(configFile) {
			return configFile
		}
		if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
			return filepath.Join(configDir, configFile)
		}
		return configFile
	}

	if configDir := os.Getenv("LOGWISP_CONFIG_DIR"); configDir != "" {
		return filepath.Join(configDir, "logwisp.toml")
	}

	// Default location
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".config", "logwisp.toml")
	}

	return "logwisp.toml"
}

// handleMonitorTargetsEnv handles comma-separated monitor targets env var
func handleMonitorTargetsEnv(cfg *lconfig.Config) error {
	if targetsStr := os.Getenv("LOGWISP_MONITOR_TARGETS"); targetsStr != "" {
		// Clear any existing targets from file/defaults
		cfg.Set("monitor.targets", []MonitorTarget{})

		// Parse comma-separated format: path:pattern:isfile,path2:pattern2:isfile
		parts := strings.Split(targetsStr, ",")
		for i, part := range parts {
			targetParts := strings.Split(part, ":")
			if len(targetParts) >= 1 && targetParts[0] != "" {
				path := fmt.Sprintf("monitor.targets.%d.path", i)
				cfg.Set(path, targetParts[0])

				if len(targetParts) >= 2 && targetParts[1] != "" {
					pattern := fmt.Sprintf("monitor.targets.%d.pattern", i)
					cfg.Set(pattern, targetParts[1])
				} else {
					pattern := fmt.Sprintf("monitor.targets.%d.pattern", i)
					cfg.Set(pattern, "*.log")
				}

				if len(targetParts) >= 3 {
					isFile := fmt.Sprintf("monitor.targets.%d.is_file", i)
					cfg.Set(isFile, targetParts[2] == "true")
				} else {
					isFile := fmt.Sprintf("monitor.targets.%d.is_file", i)
					cfg.Set(isFile, false)
				}
			}
		}
	}

	return nil
}

// validate ensures configuration is valid
func (c *Config) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	if c.Monitor.CheckIntervalMs < 10 {
		return fmt.Errorf("check interval too small: %d ms", c.Monitor.CheckIntervalMs)
	}

	if len(c.Monitor.Targets) == 0 {
		return fmt.Errorf("no monitor targets specified")
	}

	for i, target := range c.Monitor.Targets {
		if target.Path == "" {
			return fmt.Errorf("target %d: empty path", i)
		}

		if !target.IsFile && target.Pattern == "" {
			return fmt.Errorf("target %d: pattern required for directory monitoring", i)
		}

		// SECURITY: Validate paths don't contain directory traversal
		if strings.Contains(target.Path, "..") {
			return fmt.Errorf("target %d: path contains directory traversal", i)
		}
	}

	if c.Stream.BufferSize < 1 {
		return fmt.Errorf("buffer size must be positive: %d", c.Stream.BufferSize)
	}

	if c.Stream.RateLimit.Enabled {
		if c.Stream.RateLimit.RequestsPerSecond < 1 {
			return fmt.Errorf("rate limit requests per second must be positive: %d",
				c.Stream.RateLimit.RequestsPerSecond)
		}
		if c.Stream.RateLimit.BurstSize < 1 {
			return fmt.Errorf("rate limit burst size must be positive: %d",
				c.Stream.RateLimit.BurstSize)
		}
		if c.Stream.RateLimit.CleanupIntervalS < 1 {
			return fmt.Errorf("rate limit cleanup interval must be positive: %d",
				c.Stream.RateLimit.CleanupIntervalS)
		}
	}

	return nil
}