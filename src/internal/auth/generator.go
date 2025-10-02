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

	"logwisp/src/internal/scram"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// Argon2id parameters
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2SaltLen = 16
	argon2KeyLen  = 32
)

type AuthGeneratorCommand struct {
	output io.Writer
	errOut io.Writer
}

func NewAuthGeneratorCommand() *AuthGeneratorCommand {
	return &AuthGeneratorCommand{
		output: os.Stdout,
		errOut: os.Stderr,
	}
}

func (ag *AuthGeneratorCommand) Execute(args []string) error {
	cmd := flag.NewFlagSet("auth", flag.ContinueOnError)
	cmd.SetOutput(ag.errOut)

	var (
		username = cmd.String("u", "", "Username")
		password = cmd.String("p", "", "Password (will prompt if not provided)")
		authType = cmd.String("type", "basic", "Auth type: basic (HTTP) or scram (TCP)")
		genToken = cmd.Bool("t", false, "Generate random bearer token")
		tokenLen = cmd.Int("l", 32, "Token length in bytes (min 16, max 512)")
	)

	cmd.Usage = func() {
		fmt.Fprintln(ag.errOut, "Generate authentication credentials for LogWisp")
		fmt.Fprintln(ag.errOut, "\nUsage: logwisp auth [options]")
		fmt.Fprintln(ag.errOut, "\nExamples:")
		fmt.Fprintln(ag.errOut, "  # Generate basic auth hash for HTTP sources/sinks")
		fmt.Fprintln(ag.errOut, "  logwisp auth -u admin -type basic")
		fmt.Fprintln(ag.errOut, "  ")
		fmt.Fprintln(ag.errOut, "  # Generate SCRAM credentials for TCP sources/sinks")
		fmt.Fprintln(ag.errOut, "  logwisp auth -u admin -type scram")
		fmt.Fprintln(ag.errOut, "  ")
		fmt.Fprintln(ag.errOut, "  # Generate 64-byte bearer token")
		fmt.Fprintln(ag.errOut, "  logwisp auth -t -l 64")
		fmt.Fprintln(ag.errOut, "\nOptions:")
		cmd.PrintDefaults()
		fmt.Fprintln(ag.errOut)
	}

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if *genToken {
		return ag.generateToken(*tokenLen)
	}

	if *username == "" {
		cmd.Usage()
		return fmt.Errorf("username required for credential generation")
	}

	switch *authType {
	case "basic":
		return ag.generateBasicAuth(*username, *password)
	case "scram":
		return ag.generateScramAuth(*username, *password)
	default:
		return fmt.Errorf("invalid auth type: %s (use 'basic' or 'scram')", *authType)
	}
}

func (ag *AuthGeneratorCommand) generateBasicAuth(username, password string) error {
	// Get password if not provided
	if password == "" {
		pass1 := ag.promptPassword("Enter password: ")
		pass2 := ag.promptPassword("Confirm password: ")
		if pass1 != pass2 {
			return fmt.Errorf("passwords don't match")
		}
		password = pass1
	}

	// Generate salt
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate Argon2id hash
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encode in PHC format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	phcHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads, saltB64, hashB64)

	// Output configuration snippets
	fmt.Fprintln(ag.output, "\n# Basic Auth Configuration (HTTP sources/sinks)")
	fmt.Fprintln(ag.output, "# REQUIRES HTTPS/TLS for security")
	fmt.Fprintln(ag.output, "# Add to logwisp.toml under [[pipelines]]:")
	fmt.Fprintln(ag.output, "")
	fmt.Fprintln(ag.output, "[pipelines.auth]")
	fmt.Fprintln(ag.output, `type = "basic"`)
	fmt.Fprintln(ag.output, "")
	fmt.Fprintln(ag.output, "[[pipelines.auth.basic_auth.users]]")
	fmt.Fprintf(ag.output, "username = %q\n", username)
	fmt.Fprintf(ag.output, "password_hash = %q\n\n", phcHash)

	return nil
}

func (ag *AuthGeneratorCommand) generateScramAuth(username, password string) error {
	// Get password if not provided
	if password == "" {
		pass1 := ag.promptPassword("Enter password: ")
		pass2 := ag.promptPassword("Confirm password: ")
		if pass1 != pass2 {
			return fmt.Errorf("passwords don't match")
		}
		password = pass1
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive SCRAM credential
	cred, err := scram.DeriveCredential(username, password, salt, 3, 65536, 4)
	if err != nil {
		return fmt.Errorf("failed to derive SCRAM credential: %w", err)
	}

	// Output SCRAM configuration
	fmt.Fprintln(ag.output, "\n# SCRAM Auth Configuration (for TCP sources/sinks)")
	fmt.Fprintln(ag.output, "# Add to logwisp.toml:")
	fmt.Fprintln(ag.output, "[[pipelines.auth.scram_auth.users]]")
	fmt.Fprintf(ag.output, "username = %q\n", username)
	fmt.Fprintf(ag.output, "stored_key = %q\n", base64.StdEncoding.EncodeToString(cred.StoredKey))
	fmt.Fprintf(ag.output, "server_key = %q\n", base64.StdEncoding.EncodeToString(cred.ServerKey))
	fmt.Fprintf(ag.output, "salt = %q\n", base64.StdEncoding.EncodeToString(cred.Salt))
	fmt.Fprintf(ag.output, "argon_time = %d\n", cred.ArgonTime)
	fmt.Fprintf(ag.output, "argon_memory = %d\n", cred.ArgonMemory)
	fmt.Fprintf(ag.output, "argon_threads = %d\n\n", cred.ArgonThreads)

	return nil
}

func (ag *AuthGeneratorCommand) generateToken(length int) error {
	if length < 16 {
		fmt.Fprintln(ag.errOut, "Warning: tokens < 16 bytes are cryptographically weak")
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

	fmt.Fprintln(ag.output, "\n# Bearer Token Configuration")
	fmt.Fprintln(ag.output, "# Add to logwisp.toml:")
	fmt.Fprintf(ag.output, "tokens = [%q]\n\n", b64)

	fmt.Fprintln(ag.output, "# Generated Token:")
	fmt.Fprintf(ag.output, "Base64: %s\n", b64)
	fmt.Fprintf(ag.output, "Hex:    %s\n", hex)

	return nil
}

func (ag *AuthGeneratorCommand) promptPassword(prompt string) string {
	fmt.Fprint(ag.errOut, prompt)
	password, err := term.ReadPassword(syscall.Stdin)
	fmt.Fprintln(ag.errOut)
	if err != nil {
		fmt.Fprintf(ag.errOut, "Failed to read password: %v\n", err)
		os.Exit(1)
	}
	return string(password)
}