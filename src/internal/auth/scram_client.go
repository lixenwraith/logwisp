// FILE: src/internal/auth/scram_client.go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Client handles SCRAM client-side authentication
type ScramClient struct {
	Username string
	Password string

	// Handshake state
	clientNonce string
	serverFirst *ServerFirst
	authMessage string
	serverKey   []byte
}

// NewScramClient creates SCRAM client
func NewScramClient(username, password string) *ScramClient {
	return &ScramClient{
		Username: username,
		Password: password,
	}
}

// StartAuthentication generates ClientFirst message
func (c *ScramClient) StartAuthentication() (*ClientFirst, error) {
	// Generate client nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	c.clientNonce = base64.StdEncoding.EncodeToString(nonce)

	return &ClientFirst{
		Username:    c.Username,
		ClientNonce: c.clientNonce,
	}, nil
}

// ProcessServerFirst handles server challenge
func (c *ScramClient) ProcessServerFirst(msg *ServerFirst) (*ClientFinal, error) {
	c.serverFirst = msg

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(msg.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	// Derive keys using Argon2id
	saltedPassword := argon2.IDKey([]byte(c.Password), salt,
		msg.ArgonTime, msg.ArgonMemory, msg.ArgonThreads, 32)

	clientKey := computeHMAC(saltedPassword, []byte("Client Key"))
	serverKey := computeHMAC(saltedPassword, []byte("Server Key"))
	storedKey := sha256.Sum256(clientKey)

	// Build auth message
	clientFirstBare := fmt.Sprintf("u=%s,n=%s", c.Username, c.clientNonce)
	clientFinalBare := fmt.Sprintf("r=%s", msg.FullNonce)
	c.authMessage = clientFirstBare + "," + msg.Marshal() + "," + clientFinalBare

	// Compute client proof
	clientSignature := computeHMAC(storedKey[:], []byte(c.authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	// Store server key for verification
	c.serverKey = serverKey

	return &ClientFinal{
		FullNonce:   msg.FullNonce,
		ClientProof: base64.StdEncoding.EncodeToString(clientProof),
	}, nil
}

// VerifyServerFinal validates server signature
func (c *ScramClient) VerifyServerFinal(msg *ServerFinal) error {
	if c.authMessage == "" || c.serverKey == nil {
		return fmt.Errorf("invalid handshake state")
	}

	// Compute expected server signature
	expectedSig := computeHMAC(c.serverKey, []byte(c.authMessage))

	// Decode received signature
	receivedSig, err := base64.StdEncoding.DecodeString(msg.ServerSignature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// ☢ SECURITY: Constant-time comparison
	if subtle.ConstantTimeCompare(expectedSig, receivedSig) != 1 {
		return fmt.Errorf("server authentication failed")
	}

	return nil
}