// FILE: src/internal/config/auth.go
package config

import "fmt"

type AuthConfig struct {
	// Authentication type: "none", "basic", "bearer", "mtls"
	Type string `toml:"type"`

	// Basic auth
	BasicAuth *BasicAuthConfig `toml:"basic_auth"`

	// Bearer token auth
	BearerAuth *BearerAuthConfig `toml:"bearer_auth"`

	// IP-based access control
	IPWhitelist []string `toml:"ip_whitelist"`
	IPBlacklist []string `toml:"ip_blacklist"`
}

type BasicAuthConfig struct {
	// Static users (for simple deployments)
	Users []BasicAuthUser `toml:"users"`

	// External auth file
	UsersFile string `toml:"users_file"`

	// Realm for WWW-Authenticate header
	Realm string `toml:"realm"`
}

type BasicAuthUser struct {
	Username string `toml:"username"`
	// Password hash (bcrypt)
	PasswordHash string `toml:"password_hash"`
}

type BearerAuthConfig struct {
	// Static tokens
	Tokens []string `toml:"tokens"`

	// JWT validation
	JWT *JWTConfig `toml:"jwt"`
}

type JWTConfig struct {
	// JWKS URL for key discovery
	JWKSURL string `toml:"jwks_url"`

	// Static signing key (if not using JWKS)
	SigningKey string `toml:"signing_key"`

	// Expected issuer
	Issuer string `toml:"issuer"`

	// Expected audience
	Audience string `toml:"audience"`
}

func validateAuth(pipelineName string, auth *AuthConfig) error {
	if auth == nil {
		return nil
	}

	validTypes := map[string]bool{"none": true, "basic": true, "bearer": true, "mtls": true}
	if !validTypes[auth.Type] {
		return fmt.Errorf("pipeline '%s': invalid auth type: %s", pipelineName, auth.Type)
	}

	if auth.Type == "basic" && auth.BasicAuth == nil {
		return fmt.Errorf("pipeline '%s': basic auth type specified but config missing", pipelineName)
	}

	if auth.Type == "bearer" && auth.BearerAuth == nil {
		return fmt.Errorf("pipeline '%s': bearer auth type specified but config missing", pipelineName)
	}

	return nil
}