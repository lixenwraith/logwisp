// FILE: logwisp/src/internal/config/saver.go
package config

import (
	"fmt"

	lconfig "github.com/lixenwraith/config"
)

// Saves the configuration to the specified file path.
func (c *Config) SaveToFile(path string) error {
	if path == "" {
		return fmt.Errorf("cannot save config: path is empty")
	}

	// Create a temporary lconfig instance just for saving
	// This avoids the need to track lconfig throughout the application
	lcfg, err := lconfig.NewBuilder().
		WithFile(path).
		WithTarget(c).
		WithFileFormat("toml").
		Build()
	if err != nil {
		return fmt.Errorf("failed to create config builder: %w", err)
	}

	// Use lconfig's Save method which handles atomic writes
	if err := lcfg.Save(path); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}