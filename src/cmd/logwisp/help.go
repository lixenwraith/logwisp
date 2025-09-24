// FILE: logwisp/src/cmd/logwisp/help.go
package main

import (
	"fmt"
	"os"
)

const helpText = `LogWisp: A flexible log transport and processing tool.

Usage: 
  logwisp [command] [options]
  logwisp [options]

Commands:
  auth                     Generate authentication credentials
  version                  Display version information

Application Control:
  -c, --config <path>      Path to configuration file (default: logwisp.toml)
  -h, --help               Display this help message and exit
  -v, --version            Display version information and exit  
  -b, --background         Run LogWisp in the background as a daemon
  -q, --quiet              Suppress all console output, including errors

Runtime Behavior:
      --disable-status-reporter  Disable the periodic status reporter
      --config-auto-reload       Enable config reload on file change

For command-specific help:
  logwisp <command> --help

Configuration Sources (Precedence: CLI > Env > File > Defaults):
  - CLI flags override all other settings
  - Environment variables override file settings  
  - TOML configuration file is the primary method

Examples:
  # Generate password for admin user
  logwisp auth -u admin
  
  # Start service with custom config
  logwisp -c /etc/logwisp/prod.toml
  
  # Run in background
  logwisp -b --config-auto-reload

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