// FILE: src/internal/auth/scram_server.go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"logwisp/src/internal/core"
)

// Server handles SCRAM authentication
type ScramServer struct {
	credentials map[string]*Credential
	handshakes  map[string]*HandshakeState
	mu          sync.RWMutex

	// TODO: configurability useful? to be included in config or refactor to use core.const directly for simplicity
	// Default Argon2 params for new registrations
	DefaultTime    uint32
	DefaultMemory  uint32
	DefaultThreads uint8
}

// HandshakeState tracks ongoing authentication
type HandshakeState struct {
	Username    string
	ClientNonce string
	ServerNonce string
	FullNonce   string
	Credential  *Credential
	CreatedAt   time.Time
}

// NewScramServer creates SCRAM server
func NewScramServer() *ScramServer {
	return &ScramServer{
		credentials:    make(map[string]*Credential),
		handshakes:     make(map[string]*HandshakeState),
		DefaultTime:    core.Argon2Time,
		DefaultMemory:  core.Argon2Memory,
		DefaultThreads: core.Argon2Threads,
	}
}

// AddCredential registers user credential
func (s *ScramServer) AddCredential(cred *Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[cred.Username] = cred
}

// HandleClientFirst processes initial auth request
func (s *ScramServer) HandleClientFirst(msg *ClientFirst) (*ServerFirst, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user exists
	cred, exists := s.credentials[msg.Username]
	if !exists {
		// Prevent user enumeration - still generate response
		salt := make([]byte, 16)
		rand.Read(salt)
		serverNonce := generateNonce()

		return &ServerFirst{
			FullNonce:    msg.ClientNonce + serverNonce,
			Salt:         base64.StdEncoding.EncodeToString(salt),
			ArgonTime:    s.DefaultTime,
			ArgonMemory:  s.DefaultMemory,
			ArgonThreads: s.DefaultThreads,
		}, fmt.Errorf("invalid credentials")
	}

	// Generate server nonce
	serverNonce := generateNonce()
	fullNonce := msg.ClientNonce + serverNonce

	// Store handshake state
	state := &HandshakeState{
		Username:    msg.Username,
		ClientNonce: msg.ClientNonce,
		ServerNonce: serverNonce,
		FullNonce:   fullNonce,
		Credential:  cred,
		CreatedAt:   time.Now(),
	}
	s.handshakes[fullNonce] = state

	// Cleanup old handshakes
	s.cleanupHandshakes()

	return &ServerFirst{
		FullNonce:    fullNonce,
		Salt:         base64.StdEncoding.EncodeToString(cred.Salt),
		ArgonTime:    cred.ArgonTime,
		ArgonMemory:  cred.ArgonMemory,
		ArgonThreads: cred.ArgonThreads,
	}, nil
}

// HandleClientFinal verifies client proof
func (s *ScramServer) HandleClientFinal(msg *ClientFinal) (*ServerFinal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.handshakes[msg.FullNonce]
	if !exists {
		return nil, fmt.Errorf("invalid nonce or expired handshake")
	}
	defer delete(s.handshakes, msg.FullNonce)

	// Check timeout
	if time.Since(state.CreatedAt) > 60*time.Second {
		return nil, fmt.Errorf("handshake timeout")
	}

	// Decode client proof
	clientProof, err := base64.StdEncoding.DecodeString(msg.ClientProof)
	if err != nil {
		return nil, fmt.Errorf("invalid proof encoding")
	}

	// Build auth message
	clientFirstBare := fmt.Sprintf("u=%s,n=%s", state.Username, state.ClientNonce)
	serverFirst := &ServerFirst{
		FullNonce:    state.FullNonce,
		Salt:         base64.StdEncoding.EncodeToString(state.Credential.Salt),
		ArgonTime:    state.Credential.ArgonTime,
		ArgonMemory:  state.Credential.ArgonMemory,
		ArgonThreads: state.Credential.ArgonThreads,
	}
	clientFinalBare := fmt.Sprintf("r=%s", msg.FullNonce)
	authMessage := clientFirstBare + "," + serverFirst.Marshal() + "," + clientFinalBare

	// Compute client signature
	clientSignature := computeHMAC(state.Credential.StoredKey, []byte(authMessage))

	// XOR to get ClientKey
	clientKey := xorBytes(clientProof, clientSignature)

	// Verify by computing StoredKey
	computedStoredKey := sha256.Sum256(clientKey)
	if subtle.ConstantTimeCompare(computedStoredKey[:], state.Credential.StoredKey) != 1 {
		return nil, fmt.Errorf("authentication failed")
	}

	// Generate server signature for mutual auth
	serverSignature := computeHMAC(state.Credential.ServerKey, []byte(authMessage))

	return &ServerFinal{
		ServerSignature: base64.StdEncoding.EncodeToString(serverSignature),
		SessionID:       generateSessionID(),
	}, nil
}

func (s *ScramServer) cleanupHandshakes() {
	cutoff := time.Now().Add(-60 * time.Second)
	for nonce, state := range s.handshakes {
		if state.CreatedAt.Before(cutoff) {
			delete(s.handshakes, nonce)
		}
	}
}

func generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}