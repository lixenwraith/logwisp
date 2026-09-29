package main

import (
	"fmt"
	"logwisp/internal/version"
	"os"
)

// helpText is the CLI usage reference. Flags map 1:1 to TOML config paths.
const helpText = `LogWisp %s - log collection, processing, and distribution

Usage:
  logwisp [options]
  logwisp help | -h | --help
  logwisp --version

Scalar configuration keys are settable as flags using their TOML paths:
  --<path>=<value>              e.g. --logging.level=debug

Common options:
  -c, --config <path>           Configuration file (default: ./logwisp.toml)
      --quiet                   Suppress console output
      --status_reporter=<bool>  Periodic status logging (default: true)
      --auto_reload=<bool>      Config hot reload on file change (default: false)

Logging:
      --logging.output=<mode>   file|stdout|stderr|split|all|none
      --logging.level=<level>   debug|info|warn|error
      --logging.file.directory=<path>

Pipelines, plugins and filters are configured in TOML; array-indexed CLI and
environment overrides are unsupported. -- ends option parsing.

Environment:
  LOGWISP_<PATH>                Config path, '.' -> '_', uppercase
                                e.g. LOGWISP_LOGGING_LEVEL=debug
  LOGWISP_CONFIG_FILE           Configuration file path
  LOGWISP_CONFIG_DIR            Configuration directory

Signals:
  SIGINT, SIGTERM               Graceful shutdown
  SIGHUP, SIGUSR1               Reload configuration

Exit codes:
  0  success
  1  general error
  2  configuration file not found
`

// handleHelp prints usage and exits if a help request is present in args
func handleHelp(args []string) {
	if len(args) > 0 && args[0] == "help" {
		printHelp()
	}
	for _, arg := range args {
		if arg == "--" {
			break // end of flags
		}
		if arg == "-h" || arg == "--help" {
			printHelp()
		}
	}
}

// printHelp writes usage to stdout and exits with success
func printHelp() {
	fmt.Printf(helpText, version.Short())
	os.Exit(0)
}
