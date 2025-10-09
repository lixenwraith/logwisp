// FILE: src/internal/auth/scram_manager.go
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"logwisp/src/internal/config"
)

// ScramManager provides high-level SCRAM operations with rate limiting
type ScramManager struct {
	server *ScramServer
}

// NewScramManager creates SCRAM manager
func NewScramManager(scramAuthCfg *config.ScramAuthConfig) *ScramManager {
	manager := &ScramManager{
		server: NewScramServer(),
	}

	// Load users from SCRAM config
	for _, user := range scramAuthCfg.Users {
		storedKey, err := base64.StdEncoding.DecodeString(user.StoredKey)
		if err != nil {
			// Skip user with invalid stored key
			continue
		}

		serverKey, err := base64.StdEncoding.DecodeString(user.ServerKey)
		if err != nil {
			// Skip user with invalid server key
			continue
		}

		salt, err := base64.StdEncoding.DecodeString(user.Salt)
		if err != nil {
			// Skip user with invalid salt
			continue
		}

		cred := &Credential{
			Username:     user.Username,
			StoredKey:    storedKey,
			ServerKey:    serverKey,
			Salt:         salt,
			ArgonTime:    user.ArgonTime,
			ArgonMemory:  user.ArgonMemory,
			ArgonThreads: user.ArgonThreads,
		}
		manager.server.AddCredential(cred)
	}

	return manager
}

// RegisterUser creates new user credential
func (sm *ScramManager) RegisterUser(username, password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt generation failed: %w", err)
	}

	cred, err := DeriveCredential(username, password, salt,
		sm.server.DefaultTime, sm.server.DefaultMemory, sm.server.DefaultThreads)
	if err != nil {
		return err
	}

	sm.server.AddCredential(cred)
	return nil
}

// HandleClientFirst wraps server's HandleClientFirst
func (sm *ScramManager) HandleClientFirst(msg *ClientFirst) (*ServerFirst, error) {
	return sm.server.HandleClientFirst(msg)
}

// HandleClientFinal wraps server's HandleClientFinal
func (sm *ScramManager) HandleClientFinal(msg *ClientFinal) (*ServerFinal, error) {
	return sm.server.HandleClientFinal(msg)
}