// FILE: logwisp/src/internal/config/logging.go
package config

import "fmt"

// LogConfig represents logging configuration for LogWisp
type LogConfig struct {
	// Output mode: "file", "stdout", "stderr", "both", "none"
	Output string `toml:"output"`

	// Log level: "debug", "info", "warn", "error"
	Level string `toml:"level"`

	// File output settings (when Output includes "file" or "both")
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

// DefaultLogConfig returns sensible logging defaults
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		Output: "stderr",
		Level:  "info",
		File: &LogFileConfig{
			Directory:      "./log",
			Name:           "logwisp",
			MaxSizeMB:      100,
			MaxTotalSizeMB: 1000,
			RetentionHours: 168, // 7 days
		},
		Console: &LogConsoleConfig{
			Target: "stderr",
			Format: "txt",
		},
	}
}

func validateLogConfig(cfg *LogConfig) error {
	validOutputs := map[string]bool{
		"file": true, "stdout": true, "stderr": true,
		"both": true, "none": true,
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