// FILE: logwisp/src/cmd/logwisp/help.go
package main

import (
	"fmt"
	"os"
)

const helpText = `LogWisp: A flexible log transport and processing tool.

Usage: logwisp [options]

Application Control:
  -c, --config <path>      (string) Path to configuration file (default: logwisp.toml).
  -h, --help               Display this help message and exit.
  -v, --version            Display version information and exit.
  -b, --background         Run LogWisp in the background as a daemon.
  -q, --quiet              Suppress all console output, including errors.
      --router             Enable HTTP router mode for multiplexing pipelines.

Runtime Behavior:
      --disable-status-reporter  Disable the periodic status reporter.

Configuration Sources (Precedence: CLI > Env > File > Defaults):
  - CLI flags override all other settings.
  - Environment variables (e.g., LOGWISP_ROUTER=true) override file settings.
  - TOML configuration file is the primary method for defining pipelines.

Logging ([logging] section or LOGWISP_LOGGING_* env vars):
  output = "stderr"        (string) Log output: none, stdout, stderr, file, both.
  level = "info"           (string) Log level: debug, info, warn, error.
  [logging.file]           Settings for file logging (directory, name, rotation).
  [logging.console]        Settings for console logging (target, format).

Pipelines ([[pipelines]] array in TOML):
  Each pipeline defines a complete data flow from sources to sinks.
  name = "my_pipeline"     (string) Unique name for the pipeline.
  sources = [...]          (array)  Data inputs (e.g., directory, stdin, http, tcp).
  sinks = [...]            (array)  Data outputs (e.g., http, tcp, file, stdout, stderr, http_client).
  filters = [...]          (array)  Optional filters to include/exclude logs based on regex.
  rate_limit = {...}       (object) Optional rate limiting for the entire pipeline.
  auth = {...}             (object) Optional authentication for network sinks.
  format = "json"          (string) Optional output formatter for the pipeline (raw, text, json).

For detailed configuration options, please refer to the documentation.
`

// CheckAndDisplayHelp scans arguments for help flags and prints help text if found.
func CheckAndDisplayHelp(args []string) {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(os.Stdout, helpText)
			os.Exit(0)
		}
	}
}