// FILE: src/cmd/logwisp/commands/version.go
package commands

import (
	"fmt"

	"logwisp/src/internal/version"
)

// VersionCommand handles the display of the application's version information.
type VersionCommand struct{}

// NewVersionCommand creates a new version command handler.
func NewVersionCommand() *VersionCommand {
	return &VersionCommand{}
}

// Execute prints the detailed version string to stdout.
func (c *VersionCommand) Execute(args []string) error {
	fmt.Println(version.String())
	return nil
}

// Description returns a brief one-line description of the command.
func (c *VersionCommand) Description() string {
	return "Show version information"
}

// Help returns the detailed help text for the command.
func (c *VersionCommand) Help() string {
	return `Version Command - Show LogWisp version information

Usage:
  logwisp version
  logwisp -v
  logwisp --version

Output includes:
  - Version number
  - Build date
  - Git commit hash (if available)
  - Go version used for compilation
`
}