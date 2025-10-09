// FILE: src/cmd/logwisp/commands/version.go
package commands

import (
	"fmt"

	"logwisp/src/internal/version"
)

// VersionCommand handles version display
type VersionCommand struct{}

// NewVersionCommand creates a new version command
func NewVersionCommand() *VersionCommand {
	return &VersionCommand{}
}

func (c *VersionCommand) Execute(args []string) error {
	fmt.Println(version.String())
	return nil
}

func (c *VersionCommand) Description() string {
	return "Show version information"
}

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