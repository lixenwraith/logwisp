// FILE: src/cmd/logwisp/commands/help.go
package commands

import (
	"fmt"
	"sort"
	"strings"
)

// generalHelpTemplate is the default help message shown when no specific command is requested.
const generalHelpTemplate = `LogWisp: A flexible log transport and processing tool.

Usage: 
  logwisp [command] [options]
  logwisp [options]

Commands:
%s

Application Options:
  -c, --config <path>      Path to configuration file (default: logwisp.toml)
  -h, --help               Display this help message and exit
  -v, --version            Display version information and exit  
  -b, --background         Run LogWisp in the background as a daemon
  -q, --quiet              Suppress all console output, including errors

Runtime Options:
  --disable-status-reporter  Disable the periodic status reporter
  --config-auto-reload       Enable config reload on file change

For command-specific help:
  logwisp help <command>
  logwisp <command> --help

Configuration Sources (Precedence: CLI > Env > File > Defaults):
  - CLI flags override all other settings
  - Environment variables override file settings  
  - TOML configuration file is the primary method

Examples:
  # Start service with custom config
  logwisp -c /etc/logwisp/prod.toml
  
  # Run in background with config reload
  logwisp -b --config-auto-reload

For detailed configuration options, please refer to the documentation.
`

// HelpCommand handles the display of general or command-specific help messages.
type HelpCommand struct {
	router *CommandRouter
}

// NewHelpCommand creates a new help command handler.
func NewHelpCommand(router *CommandRouter) *HelpCommand {
	return &HelpCommand{router: router}
}

// Execute displays the appropriate help message based on the provided arguments.
func (c *HelpCommand) Execute(args []string) error {
	// Check if help is requested for a specific command
	if len(args) > 0 && args[0] != "" {
		cmdName := args[0]

		if handler, exists := c.router.GetCommand(cmdName); exists {
			fmt.Print(handler.Help())
			return nil
		}

		return fmt.Errorf("unknown command: %s", cmdName)
	}

	// Display general help with command list
	fmt.Printf(generalHelpTemplate, c.formatCommandList())
	return nil
}

// Description returns a brief one-line description of the command.
func (c *HelpCommand) Description() string {
	return "Display help information"
}

// Help returns the detailed help text for the 'help' command itself.
func (c *HelpCommand) Help() string {
	return `Help Command - Display help information

Usage:
  logwisp help              Show general help
  logwisp help <command>    Show help for a specific command
  
Examples:
  logwisp help              # Show general help
  logwisp help auth         # Show auth command help
  logwisp auth --help       # Alternative way to get command help
`
}

// formatCommandList creates a formatted and aligned list of all available commands.
func (c *HelpCommand) formatCommandList() string {
	commands := c.router.GetCommands()

	// Sort command names for consistent output
	names := make([]string, 0, len(commands))
	maxLen := 0
	for name := range commands {
		names = append(names, name)
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}
	sort.Strings(names)

	// Format each command with aligned descriptions
	var lines []string
	for _, name := range names {
		handler := commands[name]
		padding := strings.Repeat(" ", maxLen-len(name)+2)
		lines = append(lines, fmt.Sprintf("  %s%s%s", name, padding, handler.Description()))
	}

	return strings.Join(lines, "\n")
}