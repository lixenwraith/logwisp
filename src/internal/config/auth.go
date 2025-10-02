// FILE: logwisp/src/internal/config/auth.go
package config

import (
	"fmt"
)

type AuthConfig struct {
	// Authentication type: "none", "basic", "scram", "bearer", "mtls"
	Type string `toml:"type"`

	BasicAuth  *BasicAuthConfig  `toml:"basic_auth"`
	ScramAuth  *ScramAuthConfig  `toml:"scram_auth"`
	BearerAuth *BearerAuthConfig `toml:"bearer_auth"`
}

type BasicAuthConfig struct {
	Users []BasicAuthUser `toml:"users"`
	Realm string          `toml:"realm"`
}

type BasicAuthUser struct {
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"` // Argon2
}

type ScramAuthConfig struct {
	Users []ScramUser `toml:"users"`
}

type ScramUser struct {
	Username     string `toml:"username"`
	StoredKey    string `toml:"stored_key"` // base64
	ServerKey    string `toml:"server_key"` // base64
	Salt         string `toml:"salt"`       // base64
	ArgonTime    uint32 `toml:"argon_time"`
	ArgonMemory  uint32 `toml:"argon_memory"`
	ArgonThreads uint8  `toml:"argon_threads"`
}

type BearerAuthConfig struct {
	// Static tokens
	Tokens []string `toml:"tokens"`

	// TODO: Maybe future development
	// // JWT validation
	// JWT *JWTConfig `toml:"jwt"`
}

// TODO: Maybe future development
// type JWTConfig struct {
// 	JWKSURL    string `toml:"jwks_url"`
// 	SigningKey string `toml:"signing_key"`
// 	Issuer     string `toml:"issuer"`
// 	Audience   string `toml:"audience"`
// }

func validateAuth(pipelineName string, auth *AuthConfig) error {
	if auth == nil {
		return nil
	}

	validTypes := map[string]bool{"none": true, "basic": true, "scram": true, "bearer": true, "mtls": true}
	if !validTypes[auth.Type] {
		return fmt.Errorf("pipeline '%s': invalid auth type: %s", pipelineName, auth.Type)
	}

	if auth.Type == "basic" && auth.BasicAuth == nil {
		return fmt.Errorf("pipeline '%s': basic auth type specified but config missing", pipelineName)
	}

	if auth.Type == "scram" && auth.ScramAuth == nil {
		return fmt.Errorf("pipeline '%s': scram auth type specified but config missing", pipelineName)
	}

	if auth.Type == "bearer" && auth.BearerAuth == nil {
		return fmt.Errorf("pipeline '%s': bearer auth type specified but config missing", pipelineName)
	}

	return nil
}