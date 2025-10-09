// FILE: src/cmd/logwisp/commands/auth.go
package commands

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"logwisp/src/internal/auth"
	"logwisp/src/internal/core"

	"golang.org/x/term"
)

type AuthCommand struct {
	output io.Writer
	errOut io.Writer
}

func NewAuthCommand() *AuthCommand {
	return &AuthCommand{
		output: os.Stdout,
		errOut: os.Stderr,
	}
}

func (ac *AuthCommand) Execute(args []string) error {
	cmd := flag.NewFlagSet("auth", flag.ContinueOnError)
	cmd.SetOutput(ac.errOut)

	var (
		// User credentials
		username     = cmd.String("u", "", "Username")
		usernameLong = cmd.String("user", "", "Username")
		password     = cmd.String("p", "", "Password (will prompt if not provided)")
		passwordLong = cmd.String("password", "", "Password (will prompt if not provided)")

		// Auth type selection (multiple ways to specify)
		authType     = cmd.String("t", "", "Auth type: basic, scram, or token")
		authTypeLong = cmd.String("type", "", "Auth type: basic, scram, or token")
		useScram     = cmd.Bool("s", false, "Generate SCRAM credentials (TCP)")
		useScramLong = cmd.Bool("scram", false, "Generate SCRAM credentials (TCP)")
		useBasic     = cmd.Bool("b", false, "Generate basic auth credentials (HTTP)")
		useBasicLong = cmd.Bool("basic", false, "Generate basic auth credentials (HTTP)")

		// Token generation
		genToken     = cmd.Bool("k", false, "Generate random bearer token")
		genTokenLong = cmd.Bool("token", false, "Generate random bearer token")
		tokenLen     = cmd.Int("l", 32, "Token length in bytes")
		tokenLenLong = cmd.Int("length", 32, "Token length in bytes")

		// Migration option
		migrate     = cmd.Bool("m", false, "Convert basic auth PHC to SCRAM")
		migrateLong = cmd.Bool("migrate", false, "Convert basic auth PHC to SCRAM")
		phcHash     = cmd.String("phc", "", "PHC hash to migrate (required with --migrate)")
	)

	cmd.Usage = func() {
		fmt.Fprintln(ac.errOut, "Generate authentication credentials for LogWisp")
		fmt.Fprintln(ac.errOut, "\nUsage: logwisp auth [options]")
		fmt.Fprintln(ac.errOut, "\nExamples:")
		fmt.Fprintln(ac.errOut, "  # Generate basic auth hash for HTTP sources/sinks")
		fmt.Fprintln(ac.errOut, "  logwisp auth -u admin -b")
		fmt.Fprintln(ac.errOut, "  logwisp auth --user=admin --basic")
		fmt.Fprintln(ac.errOut, "  ")
		fmt.Fprintln(ac.errOut, "  # Generate SCRAM credentials for TCP")
		fmt.Fprintln(ac.errOut, "  logwisp auth -u tcpuser -s")
		fmt.Fprintln(ac.errOut, "  logwisp auth --user=tcpuser --scram")
		fmt.Fprintln(ac.errOut, "  ")
		fmt.Fprintln(ac.errOut, "  # Generate bearer token")
		fmt.Fprintln(ac.errOut, "  logwisp auth -k -l 64")
		fmt.Fprintln(ac.errOut, "  logwisp auth --token --length=64")
		fmt.Fprintln(ac.errOut, "\nOptions:")
		cmd.PrintDefaults()
	}

	if err := cmd.Parse(args); err != nil {
		return err
	}

	// Check for unparsed arguments
	if cmd.NArg() > 0 {
		return fmt.Errorf("unexpected argument(s): %s", strings.Join(cmd.Args(), " "))
	}

	// Merge short and long form values
	finalUsername := coalesceString(*username, *usernameLong)
	finalPassword := coalesceString(*password, *passwordLong)
	finalAuthType := coalesceString(*authType, *authTypeLong)
	finalGenToken := coalesceBool(*genToken, *genTokenLong)
	finalTokenLen := coalesceInt(*tokenLen, *tokenLenLong, core.DefaultTokenLength)
	finalUseScram := coalesceBool(*useScram, *useScramLong)
	finalUseBasic := coalesceBool(*useBasic, *useBasicLong)
	finalMigrate := coalesceBool(*migrate, *migrateLong)

	// Handle migration mode
	if finalMigrate {
		if *phcHash == "" || finalUsername == "" || finalPassword == "" {
			return fmt.Errorf("--migrate requires --user, --password, and --phc flags")
		}
		return ac.migrateToScram(finalUsername, finalPassword, *phcHash)
	}

	// Determine auth type from flags
	if finalGenToken || finalAuthType == "token" {
		return ac.generateToken(finalTokenLen)
	}

	// Determine credential type
	credType := "basic" // default

	// Check explicit type flags
	if finalUseScram || finalAuthType == "scram" {
		credType = "scram"
	} else if finalUseBasic || finalAuthType == "basic" {
		credType = "basic"
	} else if finalAuthType != "" {
		return fmt.Errorf("invalid auth type: %s (valid: basic, scram, token)", finalAuthType)
	}

	// Username required for password-based auth
	if finalUsername == "" {
		cmd.Usage()
		return fmt.Errorf("username required for %s auth generation", credType)
	}

	return ac.generatePasswordHash(finalUsername, finalPassword, credType)
}

func (ac *AuthCommand) Description() string {
	return "Generate authentication credentials (passwords, tokens, SCRAM)"
}

func (ac *AuthCommand) Help() string {
	return `Auth Command - Generate authentication credentials for LogWisp

Usage: 
  logwisp auth [options]

Authentication Types:
  HTTP/HTTPS Sources & Sinks (TLS required):
    - Basic Auth: Username/password with Argon2id hashing
    - Bearer Token: Random cryptographic tokens
  
  TCP Sources & Sinks (No TLS):
    - SCRAM: Argon2-SCRAM-SHA256 for plaintext connections

Options:
  -u, --user <name>        Username for credential generation
  -p, --password <pass>    Password (will prompt if not provided)
  -t, --type <type>        Auth type: "basic", "scram", or "token"
  -b, --basic              Generate basic auth credentials (HTTP/HTTPS)
  -s, --scram              Generate SCRAM credentials (TCP)
  -k, --token              Generate random bearer token
  -l, --length <bytes>     Token length in bytes (default: 32)

Examples:
Examples:
  # Generate basic auth hash for HTTP/HTTPS (with TLS)
  logwisp auth -u admin -b
  logwisp auth --user=admin --basic
  
  # Generate SCRAM credentials for TCP (without TLS)  
  logwisp auth -u tcpuser -s
  logwisp auth --user=tcpuser --type=scram
  
  # Generate 64-byte bearer token
  logwisp auth -k -l 64
  logwisp auth --token --length=64
  
  # Convert existing basic auth to SCRAM (HTTPS to TCP conversion)
  logwisp auth -u admin -m --phc='$argon2id$v=19$m=65536...' --password='secret'

Output:
  The command outputs configuration snippets ready to paste into logwisp.toml
  and the raw credential values for external auth files.

Security Notes:
  - Basic auth and tokens require TLS encryption for HTTP connections
  - SCRAM provides authentication but NOT encryption for TCP connections
  - Use strong passwords (12+ characters with mixed case, numbers, symbols)
  - Store credentials securely and never commit them to version control
`
}

func (ac *AuthCommand) generatePasswordHash(username, password, credType string) error {
	// Get password if not provided
	if password == "" {
		var err error
		password, err = ac.promptForPassword()
		if err != nil {
			return err
		}
	}

	switch credType {
	case "basic":
		return ac.generateBasicAuth(username, password)
	case "scram":
		return ac.generateScramAuth(username, password)
	default:
		return fmt.Errorf("invalid credential type: %s", credType)
	}
}

// promptForPassword handles password prompting with confirmation
func (ac *AuthCommand) promptForPassword() (string, error) {
	pass1 := ac.promptPassword("Enter password: ")
	pass2 := ac.promptPassword("Confirm password: ")
	if pass1 != pass2 {
		return "", fmt.Errorf("passwords don't match")
	}
	return pass1, nil
}

func (ac *AuthCommand) promptPassword(prompt string) string {
	fmt.Fprint(ac.errOut, prompt)
	password, err := term.ReadPassword(syscall.Stdin)
	fmt.Fprintln(ac.errOut)
	if err != nil {
		fmt.Fprintf(ac.errOut, "Failed to read password: %v\n", err)
		os.Exit(1)
	}
	return string(password)
}

// generateBasicAuth creates Argon2id hash for HTTP basic auth
func (ac *AuthCommand) generateBasicAuth(username, password string) error {
	// Generate salt
	salt := make([]byte, core.Argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate Argon2id hash
	cred, err := auth.DeriveCredential(username, password, salt,
		core.Argon2Time, core.Argon2Memory, core.Argon2Threads)
	if err != nil {
		return fmt.Errorf("failed to derive credential: %w", err)
	}

	// Output configuration snippets
	fmt.Fprintln(ac.output, "\n# Basic Auth Configuration (HTTP sources/sinks)")
	fmt.Fprintln(ac.output, "# REQUIRES HTTPS/TLS for security")
	fmt.Fprintln(ac.output, "# Add to logwisp.toml under [[pipelines]]:")
	fmt.Fprintln(ac.output, "")
	fmt.Fprintln(ac.output, "[pipelines.auth]")
	fmt.Fprintln(ac.output, `type = "basic"`)
	fmt.Fprintln(ac.output, "")
	fmt.Fprintln(ac.output, "[[pipelines.auth.basic_auth.users]]")
	fmt.Fprintf(ac.output, "username = %q\n", username)
	fmt.Fprintf(ac.output, "password_hash = %q\n\n", cred.PHCHash)

	fmt.Fprintln(ac.output, "# For external users file:")
	fmt.Fprintf(ac.output, "%s:%s\n", username, cred.PHCHash)

	return nil
}

// generateScramAuth creates Argon2id-SCRAM-SHA256 credentials for TCP
func (ac *AuthCommand) generateScramAuth(username, password string) error {
	// Generate salt
	salt := make([]byte, core.Argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Use internal auth package to derive SCRAM credentials
	cred, err := auth.DeriveCredential(username, password, salt,
		core.Argon2Time, core.Argon2Memory, core.Argon2Threads)
	if err != nil {
		return fmt.Errorf("failed to derive SCRAM credential: %w", err)
	}

	// Output SCRAM configuration
	fmt.Fprintln(ac.output, "\n# SCRAM Auth Configuration (TCP sources/sinks)")
	fmt.Fprintln(ac.output, "# Provides authentication but NOT encryption")
	fmt.Fprintln(ac.output, "# Add to logwisp.toml under [[pipelines]]:")
	fmt.Fprintln(ac.output, "")
	fmt.Fprintln(ac.output, "[pipelines.auth]")
	fmt.Fprintln(ac.output, `type = "scram"`)
	fmt.Fprintln(ac.output, "")
	fmt.Fprintln(ac.output, "[[pipelines.auth.scram_auth.users]]")
	fmt.Fprintf(ac.output, "username = %q\n", username)
	fmt.Fprintf(ac.output, "stored_key = %q\n", base64.StdEncoding.EncodeToString(cred.StoredKey))
	fmt.Fprintf(ac.output, "server_key = %q\n", base64.StdEncoding.EncodeToString(cred.ServerKey))
	fmt.Fprintf(ac.output, "salt = %q\n", base64.StdEncoding.EncodeToString(cred.Salt))
	fmt.Fprintf(ac.output, "argon_time = %d\n", cred.ArgonTime)
	fmt.Fprintf(ac.output, "argon_memory = %d\n", cred.ArgonMemory)
	fmt.Fprintf(ac.output, "argon_threads = %d\n\n", cred.ArgonThreads)

	fmt.Fprintln(ac.output, "# Note: SCRAM provides authentication only.")
	fmt.Fprintln(ac.output, "# Use TLS/mTLS for encryption if needed.")

	return nil
}

func (ac *AuthCommand) generateToken(length int) error {
	if length < 16 {
		fmt.Fprintln(ac.errOut, "Warning: tokens < 16 bytes are cryptographically weak")
	}
	if length > 512 {
		return fmt.Errorf("token length exceeds maximum (512 bytes)")
	}

	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(token)
	hex := fmt.Sprintf("%x", token)

	fmt.Fprintln(ac.output, "\n# Token Configuration")
	fmt.Fprintln(ac.output, "# Add to logwisp.toml:")
	fmt.Fprintf(ac.output, "tokens = [%q]\n\n", b64)

	fmt.Fprintln(ac.output, "# Generated Token:")
	fmt.Fprintf(ac.output, "Base64: %s\n", b64)
	fmt.Fprintf(ac.output, "Hex:    %s\n", hex)

	return nil
}

// migrateToScram converts basic auth PHC hash to SCRAM credentials
func (ac *AuthCommand) migrateToScram(username, password, phcHash string) error {
	// CHANGED: Moved from internal/auth to CLI command layer
	cred, err := auth.MigrateFromPHC(username, password, phcHash)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	// Output SCRAM configuration (reuse format from generateScramAuth)
	fmt.Fprintln(ac.output, "\n# Migrated SCRAM Credentials")
	fmt.Fprintln(ac.output, "# Add to logwisp.toml under [[pipelines]]:")
	fmt.Fprintln(ac.output, "")
	fmt.Fprintln(ac.output, "[pipelines.auth]")
	fmt.Fprintln(ac.output, `type = "scram"`)
	fmt.Fprintln(ac.output, "")
	fmt.Fprintln(ac.output, "[[pipelines.auth.scram_auth.users]]")
	fmt.Fprintf(ac.output, "username = %q\n", username)
	fmt.Fprintf(ac.output, "stored_key = %q\n", base64.StdEncoding.EncodeToString(cred.StoredKey))
	fmt.Fprintf(ac.output, "server_key = %q\n", base64.StdEncoding.EncodeToString(cred.ServerKey))
	fmt.Fprintf(ac.output, "salt = %q\n", base64.StdEncoding.EncodeToString(cred.Salt))
	fmt.Fprintf(ac.output, "argon_time = %d\n", cred.ArgonTime)
	fmt.Fprintf(ac.output, "argon_memory = %d\n", cred.ArgonMemory)
	fmt.Fprintf(ac.output, "argon_threads = %d\n", cred.ArgonThreads)

	return nil
}