// FILE: src/internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

type Config struct {
	Monitor    MonitorConfig `toml:"monitor"`
	TCPServer  TCPConfig     `toml:"tcpserver"`
	HTTPServer HTTPConfig    `toml:"httpserver"`
}

type MonitorConfig struct {
	CheckIntervalMs int             `toml:"check_interval_ms"`
	Targets         []MonitorTarget `toml:"targets"`
}

type MonitorTarget struct {
	Path    string `toml:"path"`
	Pattern string `toml:"pattern"`
	IsFile  bool   `toml:"is_file"`
}

type TCPConfig struct {
	Enabled     bool            `toml:"enabled"`
	Port        int             `toml:"port"`
	BufferSize  int             `toml:"buffer_size"`
	SSLEnabled  bool            `toml:"ssl_enabled"`
	SSLCertFile string          `toml:"ssl_cert_file"`
	SSLKeyFile  string          `toml:"ssl_key_file"`
	Heartbeat   HeartbeatConfig `toml:"heartbeat"`
}

type HTTPConfig struct {
	Enabled     bool            `toml:"enabled"`
	Port        int             `toml:"port"`
	BufferSize  int             `toml:"buffer_size"`
	SSLEnabled  bool            `toml:"ssl_enabled"`
	SSLCertFile string          `toml:"ssl_cert_file"`
	SSLKeyFile  string          `toml:"ssl_key_file"`
	Heartbeat   HeartbeatConfig `toml:"heartbeat"`
}

type HeartbeatConfig struct {
	Enabled          bool   `toml:"enabled"`
	IntervalSeconds  int    `toml:"interval_seconds"`
	IncludeTimestamp bool   `toml:"include_timestamp"`
	IncludeStats     bool   `toml:"include_stats"`
	Format           string `toml:"format"` // "comment" or "json"
}

func defaults() *Config {
	return &Config{
		Monitor: MonitorConfig{
			CheckIntervalMs: 100,
			Targets: []MonitorTarget{
				{Path: "./", Pattern: "*.log", IsFile: false},
			},
		},
		TCPServer: TCPConfig{
			Enabled:    false,
			Port:       9090,
			BufferSize: 1000,
			Heartbeat: HeartbeatConfig{
				Enabled:          false,
				IntervalSeconds:  30,
				IncludeTimestamp: true,
				IncludeStats:     false,
				Format:           "json",
			},
		},
		HTTPServer: HTTPConfig{
			Enabled:    true,
			Port:       8080,
			BufferSize: 1000,
			Heartbeat: HeartbeatConfig{
				Enabled:          true,
				IntervalSeconds:  30,
				IncludeTimestamp: true,
				IncludeStats:     false,
				Format:           "comment",
			},
		},
	}
}

func LoadWithCLI(cliArgs []string) (*Config, error) {
	configPath := GetConfigPath()

	cfg, err := lconfig.NewBuilder().
		WithDefaults(defaults()).
		WithEnvPrefix("LOGWISP_").
		WithFile(configPath).
		WithArgs(cliArgs).
		WithEnvTransform(customEnvTransform).
		WithSources(
			lconfig.SourceCLI,
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

	if err := handleMonitorTargetsEnv(cfg); err != nil {
		return nil, err
	}

	finalConfig := &Config{}
	if err := cfg.Scan("", finalConfig); err != nil {
		return nil, fmt.Errorf("failed to scan config: %w", err)
	}

	return finalConfig, finalConfig.validate()
}

func customEnvTransform(path string) string {
	env := strings.ReplaceAll(path, ".", "_")
	env = strings.ToUpper(env)
	env = "LOGWISP_" + env
	return env
}

func GetConfigPath() string {
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

	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".config", "logwisp.toml")
	}

	return "logwisp.toml"
}

func handleMonitorTargetsEnv(cfg *lconfig.Config) error {
	if targetsStr := os.Getenv("LOGWISP_MONITOR_TARGETS"); targetsStr != "" {
		cfg.Set("monitor.targets", []MonitorTarget{})

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

func (c *Config) validate() error {
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
		if strings.Contains(target.Path, "..") {
			return fmt.Errorf("target %d: path contains directory traversal", i)
		}
	}

	if c.TCPServer.Enabled {
		if c.TCPServer.Port < 1 || c.TCPServer.Port > 65535 {
			return fmt.Errorf("invalid TCP port: %d", c.TCPServer.Port)
		}
		if c.TCPServer.BufferSize < 1 {
			return fmt.Errorf("TCP buffer size must be positive: %d", c.TCPServer.BufferSize)
		}
	}

	if c.HTTPServer.Enabled {
		if c.HTTPServer.Port < 1 || c.HTTPServer.Port > 65535 {
			return fmt.Errorf("invalid HTTP port: %d", c.HTTPServer.Port)
		}
		if c.HTTPServer.BufferSize < 1 {
			return fmt.Errorf("HTTP buffer size must be positive: %d", c.HTTPServer.BufferSize)
		}
	}

	if c.TCPServer.Enabled && c.TCPServer.Heartbeat.Enabled {
		if c.TCPServer.Heartbeat.IntervalSeconds < 1 {
			return fmt.Errorf("TCP heartbeat interval must be positive: %d", c.TCPServer.Heartbeat.IntervalSeconds)
		}
		if c.TCPServer.Heartbeat.Format != "json" && c.TCPServer.Heartbeat.Format != "comment" {
			return fmt.Errorf("TCP heartbeat format must be 'json' or 'comment': %s", c.TCPServer.Heartbeat.Format)
		}
	}

	if c.HTTPServer.Enabled && c.HTTPServer.Heartbeat.Enabled {
		if c.HTTPServer.Heartbeat.IntervalSeconds < 1 {
			return fmt.Errorf("HTTP heartbeat interval must be positive: %d", c.HTTPServer.Heartbeat.IntervalSeconds)
		}
		if c.HTTPServer.Heartbeat.Format != "json" && c.HTTPServer.Heartbeat.Format != "comment" {
			return fmt.Errorf("HTTP heartbeat format must be 'json' or 'comment': %s", c.HTTPServer.Heartbeat.Format)
		}
	}

	return nil
}