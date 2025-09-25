// FILE: src/internal/auth/generator.go
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// Handles auth credential generation
type GeneratorCommand struct {
	output io.Writer
	errOut io.Writer
}

// Creates a new auth generator command handler
func NewGeneratorCommand() *GeneratorCommand {
	return &GeneratorCommand{
		output: os.Stdout,
		errOut: os.Stderr,
	}
}

// Runs the auth generation command with provided arguments
func (g *GeneratorCommand) Execute(args []string) error {
	cmd := flag.NewFlagSet("auth", flag.ContinueOnError)
	cmd.SetOutput(g.errOut)

	var (
		username = cmd.String("u", "", "Username for basic auth")
		password = cmd.String("p", "", "Password to hash (will prompt if not provided)")
		cost     = cmd.Int("c", 10, "Bcrypt cost (10-31)")
		genToken = cmd.Bool("t", false, "Generate random bearer token")
		tokenLen = cmd.Int("l", 32, "Token length in bytes")
	)

	cmd.Usage = func() {
		fmt.Fprintln(g.errOut, "Generate authentication credentials for LogWisp")
		fmt.Fprintln(g.errOut, "\nUsage: logwisp auth [options]")
		fmt.Fprintln(g.errOut, "\nExamples:")
		fmt.Fprintln(g.errOut, "  # Generate bcrypt hash for user")
		fmt.Fprintln(g.errOut, "  logwisp auth -u admin")
		fmt.Fprintln(g.errOut, "  ")
		fmt.Fprintln(g.errOut, "  # Generate 64-byte bearer token")
		fmt.Fprintln(g.errOut, "  logwisp auth -t -l 64")
		fmt.Fprintln(g.errOut, "\nOptions:")
		cmd.PrintDefaults()
	}

	if err := cmd.Parse(args); err != nil {
		return err
	}

	// Token generation mode
	if *genToken {
		return g.generateToken(*tokenLen)
	}

	// Password hash generation mode
	if *username == "" {
		cmd.Usage()
		return fmt.Errorf("username required for password hash generation")
	}

	return g.generatePasswordHash(*username, *password, *cost)
}

func (g *GeneratorCommand) generatePasswordHash(username, password string, cost int) error {
	// Validate cost
	if cost < 10 || cost > 31 {
		return fmt.Errorf("bcrypt cost must be between 10 and 31")
	}

	// Get password if not provided
	if password == "" {
		pass1 := g.promptPassword("Enter password: ")
		pass2 := g.promptPassword("Confirm password: ")
		if pass1 != pass2 {
			return fmt.Errorf("passwords don't match")
		}
		password = pass1
	}

	// Generate hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return fmt.Errorf("failed to generate hash: %w", err)
	}

	// Output configuration snippets
	fmt.Fprintln(g.output, "\n# TOML Configuration (add to logwisp.toml):")
	fmt.Fprintln(g.output, "[[pipelines.auth.basic_auth.users]]")
	fmt.Fprintf(g.output, "username = %q\n", username)
	fmt.Fprintf(g.output, "password_hash = %q\n\n", string(hash))

	fmt.Fprintln(g.output, "# Users File Format (for external auth file):")
	fmt.Fprintf(g.output, "%s:%s\n", username, hash)

	return nil
}

func (g *GeneratorCommand) generateToken(length int) error {
	if length < 16 {
		fmt.Fprintln(g.errOut, "Warning: tokens < 16 bytes are cryptographically weak")
	}
	if length > 512 {
		return fmt.Errorf("token length exceeds maximum (512 bytes)")
	}

	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Generate both encodings
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(token)
	hex := fmt.Sprintf("%x", token)

	// Output configuration
	fmt.Fprintln(g.output, "\n# TOML Configuration (add to logwisp.toml):")
	fmt.Fprintf(g.output, "tokens = [%q]\n\n", b64)

	fmt.Fprintln(g.output, "# Generated Token:")
	fmt.Fprintf(g.output, "Base64: %s\n", b64)
	fmt.Fprintf(g.output, "Hex:    %s\n", hex)

	return nil
}

func (g *GeneratorCommand) promptPassword(prompt string) string {
	fmt.Fprint(g.errOut, prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(g.errOut)
	if err != nil {
		// Fatal error - can't continue without password
		fmt.Fprintf(g.errOut, "Failed to read password: %v\n", err)
		os.Exit(1)
	}
	return string(password)
}