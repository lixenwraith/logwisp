// FILE: src/cmd/logwisp/flags.go
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Command-line flags
var (
	// General flags
	configFile  = flag.String("config", "", "Config file path")
	useRouter   = flag.Bool("router", false, "Use HTTP router for path-based routing")
	showVersion = flag.Bool("version", false, "Show version information")
	background  = flag.Bool("background", false, "Run as background process")

	// Logging flags
	logOutput  = flag.String("log-output", "", "Log output: file, stdout, stderr, both, none (overrides config)")
	logLevel   = flag.String("log-level", "", "Log level: debug, info, warn, error (overrides config)")
	logFile    = flag.String("log-file", "", "Log file path (when using file output)")
	logDir     = flag.String("log-dir", "", "Log directory (when using file output)")
	logConsole = flag.String("log-console", "", "Console target: stdout, stderr, split (overrides config)")

	// Quiet mode flag
	quiet = flag.Bool("quiet", false, "Suppress all LogWisp logging output (sink outputs remain unaffected)")
)

// FlagConfig holds parsed command-line flags
type FlagConfig struct {
	ConfigFile  string
	UseRouter   bool
	ShowVersion bool
	Background  bool
	LogOutput   string
	LogLevel    string
	LogFile     string
	LogDir      string
	LogConsole  string
	Quiet       bool
}

// ParseFlags parses command-line arguments and returns configuration
func ParseFlags() (*FlagConfig, error) {
	// Set custom usage before parsing
	flag.Usage = customUsage
	flag.Parse()

	fc := &FlagConfig{
		ConfigFile:  *configFile,
		UseRouter:   *useRouter,
		ShowVersion: *showVersion,
		Background:  *background,
		LogOutput:   *logOutput,
		LogLevel:    *logLevel,
		LogFile:     *logFile,
		LogDir:      *logDir,
		LogConsole:  *logConsole,
		Quiet:       *quiet,
	}

	// Validate log-output flag if provided
	if fc.LogOutput != "" {
		validOutputs := map[string]bool{
			"file": true, "stdout": true, "stderr": true,
			"both": true, "none": true,
		}
		if !validOutputs[fc.LogOutput] {
			return nil, fmt.Errorf("invalid log-output: %s (valid: file, stdout, stderr, both, none)", fc.LogOutput)
		}
	}

	// Validate log-level flag if provided
	if fc.LogLevel != "" {
		validLevels := map[string]bool{
			"debug": true, "info": true, "warn": true, "error": true,
		}
		if !validLevels[strings.ToLower(fc.LogLevel)] {
			return nil, fmt.Errorf("invalid log-level: %s (valid: debug, info, warn, error)", fc.LogLevel)
		}
	}

	// Validate log-console flag if provided
	if fc.LogConsole != "" {
		validTargets := map[string]bool{
			"stdout": true, "stderr": true, "split": true,
		}
		if !validTargets[fc.LogConsole] {
			return nil, fmt.Errorf("invalid log-console: %s (valid: stdout, stderr, split)", fc.LogConsole)
		}
	}

	return fc, nil
}

func customUsage() {
	fmt.Fprintf(os.Stderr, "LogWisp - Multi-Pipeline Log Processing Service\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Options:\n")

	// General options
	fmt.Fprintf(os.Stderr, "\nGeneral:\n")
	fmt.Fprintf(os.Stderr, "  -config string\n\tConfig file path\n")
	fmt.Fprintf(os.Stderr, "  -router\n\tUse HTTP router for path-based routing\n")
	fmt.Fprintf(os.Stderr, "  -version\n\tShow version information\n")
	fmt.Fprintf(os.Stderr, "  -background\n\tRun as background process\n")

	// Logging options
	fmt.Fprintf(os.Stderr, "\nLogging:\n")
	fmt.Fprintf(os.Stderr, "  -log-output string\n\tLog output: file, stdout, stderr, both, none (overrides config)\n")
	fmt.Fprintf(os.Stderr, "  -log-level string\n\tLog level: debug, info, warn, error (overrides config)\n")
	fmt.Fprintf(os.Stderr, "  -log-file string\n\tLog file path (when using file output)\n")
	fmt.Fprintf(os.Stderr, "  -log-dir string\n\tLog directory (when using file output)\n")
	fmt.Fprintf(os.Stderr, "  -log-console string\n\tConsole target: stdout, stderr, split (overrides config)\n")
	fmt.Fprintf(os.Stderr, "  -quiet\n\tSuppress all LogWisp logging output (sink outputs remain unaffected)\n")

	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  # Run with default config (logs to stderr)\n")
	fmt.Fprintf(os.Stderr, "  %s\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "  # Run with file logging\n")
	fmt.Fprintf(os.Stderr, "  %s --log-output file --log-dir /var/log/logwisp\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "  # Run with debug logging to both file and console\n")
	fmt.Fprintf(os.Stderr, "  %s --log-output both --log-level debug\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "  # Run with custom config and override log level\n")
	fmt.Fprintf(os.Stderr, "  %s --config /etc/logwisp.toml --log-level warn\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "  # Run in router mode with multiple pipelines\n")
	fmt.Fprintf(os.Stderr, "  %s --router --config /etc/logwisp/multi-pipeline.toml\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "Environment Variables:\n")
	fmt.Fprintf(os.Stderr, "  LOGWISP_CONFIG_FILE              Config file path\n")
	fmt.Fprintf(os.Stderr, "  LOGWISP_CONFIG_DIR               Config directory\n")
	fmt.Fprintf(os.Stderr, "  LOGWISP_DISABLE_STATUS_REPORTER  Disable periodic status reports (set to 1)\n")
	fmt.Fprintf(os.Stderr, "  LOGWISP_BACKGROUND               Internal use - background process marker\n")
	fmt.Fprintf(os.Stderr, "\nFor complete documentation, see: https://github.com/logwisp/logwisp/tree/main/doc\n")
}