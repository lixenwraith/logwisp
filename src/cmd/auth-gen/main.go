// FILE: logwisp/src/cmd/auth-gen/main.go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	var (
		username = flag.String("u", "", "Username for basic auth")
		password = flag.String("p", "", "Password to hash (will prompt if not provided)")
		cost     = flag.Int("c", 10, "Bcrypt cost (10-31)")
		genToken = flag.Bool("t", false, "Generate random bearer token")
		tokenLen = flag.Int("l", 32, "Token length in bytes")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "LogWisp Authentication Utility\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Generate bcrypt hash:  %s -u <username> [-p <password>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Generate bearer token: %s -t [-l <length>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *genToken {
		generateToken(*tokenLen)
		return
	}

	if *username == "" {
		fmt.Fprintf(os.Stderr, "Error: Username required for basic auth\n")
		flag.Usage()
		os.Exit(1)
	}

	// Get password
	pass := *password
	if pass == "" {
		pass = promptPassword("Enter password: ")
		confirm := promptPassword("Confirm password: ")
		if pass != confirm {
			fmt.Fprintf(os.Stderr, "Error: Passwords don't match\n")
			os.Exit(1)
		}
	}

	// Generate bcrypt hash
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), *cost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating hash: %v\n", err)
		os.Exit(1)
	}

	// Output TOML config format
	fmt.Println("\n# Add to logwisp.toml under [[pipelines.auth.basic_auth.users]]:")
	fmt.Printf("[[pipelines.auth.basic_auth.users]]\n")
	fmt.Printf("username = \"%s\"\n", *username)
	fmt.Printf("password_hash = \"%s\"\n", string(hash))

	// Also output for users file format
	fmt.Println("\n# Or add to users file:")
	fmt.Printf("%s:%s\n", *username, string(hash))
}

func promptPassword(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}
	return string(password)
}

func generateToken(length int) {
	if length < 16 {
		fmt.Fprintf(os.Stderr, "Warning: Token length < 16 bytes is insecure\n")
	}

	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	// Output in various formats
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(token)
	hex := fmt.Sprintf("%x", token)

	fmt.Println("\n# Add to logwisp.toml under [pipelines.auth.bearer_auth]:")
	fmt.Printf("tokens = [\"%s\"]\n", b64)

	fmt.Println("\n# Alternative hex encoding:")
	fmt.Printf("# tokens = [\"%s\"]\n", hex)

	fmt.Printf("\n# Token (base64): %s\n", b64)
	fmt.Printf("# Token (hex):    %s\n", hex)
}