// FILE: src/cmd/logwisp/commands.go
package main

import (
	"fmt"
	"os"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/tls"
	"logwisp/src/internal/version"
)

// Handles subcommand routing before main app initialization
type CommandRouter struct {
	commands map[string]CommandHandler
}

// Defines the interface for subcommands
type CommandHandler interface {
	Execute(args []string) error
	Description() string
}

// Creates and initializes the command router
func NewCommandRouter() *CommandRouter {
	router := &CommandRouter{
		commands: make(map[string]CommandHandler),
	}

	// Register available commands
	router.commands["auth"] = &authCommand{}
	router.commands["version"] = &versionCommand{}
	router.commands["help"] = &helpCommand{}
	router.commands["tls"] = &tlsCommand{}

	return router
}

// Checks for and executes subcommands
func (r *CommandRouter) Route(args []string) error {
	if len(args) < 1 {
		return nil
	}

	// Check for help flags anywhere in args
	for _, arg := range args[1:] { // Skip program name
		if arg == "-h" || arg == "--help" || arg == "help" {
			// Show main help and exit regardless of other flags
			r.commands["help"].Execute(nil)
			os.Exit(0)
		}
	}

	// Check for commands
	if len(args) > 1 {
		cmdName := args[1]

		if handler, exists := r.commands[cmdName]; exists {
			if err := handler.Execute(args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}

		// Check if it looks like a mistyped command (not a flag)
		if cmdName[0] != '-' {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
			fmt.Fprintln(os.Stderr, "\nAvailable commands:")
			r.ShowCommands()
			os.Exit(1)
		}
	}

	return nil
}

// Displays available subcommands
func (r *CommandRouter) ShowCommands() {
	fmt.Fprintln(os.Stderr, "  auth       Generate authentication credentials")
	fmt.Fprintln(os.Stderr, "  tls        Generate TLS certificates")
	fmt.Fprintln(os.Stderr, "  version    Show version information")
	fmt.Fprintln(os.Stderr, "  help       Display help information")
	fmt.Fprintln(os.Stderr, "\nUse 'logwisp <command> --help' for command-specific help")
}

// TODO: Future: refactor with a new command interface
type helpCommand struct{}

func (c *helpCommand) Execute(args []string) error {
	// Check if help is requested for a specific command
	if len(args) > 0 {
		// TODO: Future: show command-specific help
		// For now, just show general help
	}
	fmt.Print(helpText)
	return nil
}

func (c *helpCommand) Description() string {
	return "Display help information"
}

// authCommand wrapper
type authCommand struct{}

func (c *authCommand) Execute(args []string) error {
	gen := auth.NewGeneratorCommand()
	return gen.Execute(args)
}

func (c *authCommand) Description() string {
	return "Generate authentication credentials (passwords, tokens)"
}

// versionCommand wrapper
type versionCommand struct{}

func (c *versionCommand) Execute(args []string) error {
	fmt.Println(version.String())
	return nil
}

func (c *versionCommand) Description() string {
	return "Show version information"
}

// tlsCommand wrapper
type tlsCommand struct{}

func (c *tlsCommand) Execute(args []string) error {
	gen := tls.NewCertGeneratorCommand()
	return gen.Execute(args)
}

func (c *tlsCommand) Description() string {
	return "Generate TLS certificates (CA, server, client)"
}