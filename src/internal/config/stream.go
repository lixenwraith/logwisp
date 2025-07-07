// FILE: src/internal/config/stream.go
package config

type StreamConfig struct {
	// Stream identifier (used in logs and metrics)
	Name string `toml:"name"`

	// Monitor configuration for this stream
	Monitor *StreamMonitorConfig `toml:"monitor"`

	// Server configurations
	TCPServer  *TCPConfig  `toml:"tcpserver"`
	HTTPServer *HTTPConfig `toml:"httpserver"`

	// Authentication/Authorization
	Auth *AuthConfig `toml:"auth"`
}

type StreamMonitorConfig struct {
	CheckIntervalMs int             `toml:"check_interval_ms"`
	Targets         []MonitorTarget `toml:"targets"`
}

type MonitorTarget struct {
	Path    string `toml:"path"`
	Pattern string `toml:"pattern"`
	IsFile  bool   `toml:"is_file"`
}

func (s *StreamConfig) GetTargets(defaultTargets []MonitorTarget) []MonitorTarget {
	if s.Monitor != nil && len(s.Monitor.Targets) > 0 {
		return s.Monitor.Targets
	}
	return nil
}

func (s *StreamConfig) GetCheckInterval(defaultInterval int) int {
	if s.Monitor != nil && s.Monitor.CheckIntervalMs > 0 {
		return s.Monitor.CheckIntervalMs
	}
	return defaultInterval
}