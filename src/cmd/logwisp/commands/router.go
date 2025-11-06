// FILE: src/cmd/logwisp/commands/router.go
package commands

import (
	"fmt"
	"os"
)

// Handler defines the interface required for all subcommands.
type Handler interface {
	Execute(args []string) error
	Description() string
	Help() string
}

// CommandRouter handles the routing of CLI arguments to the appropriate subcommand handler.
type CommandRouter struct {
	commands map[string]Handler
}

// NewCommandRouter creates and initializes the command router with all available commands.
func NewCommandRouter() *CommandRouter {
	router := &CommandRouter{
		commands: make(map[string]Handler),
	}

	// Register available commands
	router.commands["tls"] = NewTLSCommand()
	router.commands["version"] = NewVersionCommand()
	router.commands["help"] = NewHelpCommand(router)

	return router
}

// Route checks for and executes a subcommand based on the provided CLI arguments.
func (r *CommandRouter) Route(args []string) (bool, error) {
	if len(args) < 2 {
		return false, nil // No command specified, let main app continue
	}

	cmdName := args[1]

	// Special case: help flag at any position shows general help
	for _, arg := range args[1:] {
		if arg == "-h" || arg == "--help" {
			// If it's after a valid command, show command-specific help
			if handler, exists := r.commands[cmdName]; exists && cmdName != "help" {
				fmt.Print(handler.Help())
				return true, nil
			}
			// Otherwise show general help
			return true, r.commands["help"].Execute(nil)
		}
	}

	// Check if this is a known command
	handler, exists := r.commands[cmdName]
	if !exists {
		// Check if it looks like a mistyped command (not a flag)
		if cmdName[0] != '-' {
			return false, fmt.Errorf("unknown command: %s\n\nRun 'logwisp help' for usage", cmdName)
		}
		// It's a flag, let main app handle it
		return false, nil
	}

	// Execute the command
	return true, handler.Execute(args[2:])
}

// GetCommand returns a specific command handler by its name.
func (r *CommandRouter) GetCommand(name string) (Handler, bool) {
	cmd, exists := r.commands[name]
	return cmd, exists
}

// GetCommands returns a map of all registered commands.
func (r *CommandRouter) GetCommands() map[string]Handler {
	return r.commands
}

// ShowCommands displays a list of available subcommands to stderr.
func (r *CommandRouter) ShowCommands() {
	for name, handler := range r.commands {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", name, handler.Description())
	}
	fmt.Fprintln(os.Stderr, "\nUse 'logwisp <command> --help' for command-specific help")
}

// coalesceString returns the first non-empty string from a list of arguments.
func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// coalesceInt returns the first non-default integer from a list of arguments.
func coalesceInt(primary, secondary, defaultVal int) int {
	if primary != defaultVal {
		return primary
	}
	if secondary != defaultVal {
		return secondary
	}
	return defaultVal
}

// coalesceBool returns true if any of the boolean arguments is true.
func coalesceBool(values ...bool) bool {
	for _, v := range values {
		if v {
			return true
		}
	}
	return false
}