// FILE: src/internal/auth/scram_credential.go
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"logwisp/src/internal/core"

	"golang.org/x/crypto/argon2"
)

// Credential stores SCRAM authentication data
type Credential struct {
	Username     string
	Salt         []byte // 16+ bytes
	ArgonTime    uint32 // e.g., 3
	ArgonMemory  uint32 // e.g., 64*1024 KiB
	ArgonThreads uint8  // e.g., 4
	StoredKey    []byte // SHA256(ClientKey)
	ServerKey    []byte // For server auth
	PHCHash      string
}

// DeriveCredential creates SCRAM credential from password
func DeriveCredential(username, password string, salt []byte, time, memory uint32, threads uint8) (*Credential, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes")
	}

	// Derive salted password using Argon2id
	saltedPassword := argon2.IDKey([]byte(password), salt, time, memory, threads, core.Argon2KeyLen)

	// Construct PHC format for basic auth compatibility
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(saltedPassword)
	phcHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads, saltB64, hashB64)

	// Derive keys
	clientKey := computeHMAC(saltedPassword, []byte("Client Key"))
	serverKey := computeHMAC(saltedPassword, []byte("Server Key"))
	storedKey := sha256.Sum256(clientKey)

	return &Credential{
		Username:     username,
		Salt:         salt,
		ArgonTime:    time,
		ArgonMemory:  memory,
		ArgonThreads: threads,
		StoredKey:    storedKey[:],
		ServerKey:    serverKey,
		PHCHash:      phcHash,
	}, nil
}

// MigrateFromPHC converts existing Argon2 PHC hash to SCRAM credential
func MigrateFromPHC(username, password, phcHash string) (*Credential, error) {
	// Parse PHC: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, fmt.Errorf("invalid PHC format")
	}

	var memory, time uint32
	var threads uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid hash encoding: %w", err)
	}

	// Verify password matches
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))
	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return nil, fmt.Errorf("password verification failed")
	}

	// Now derive SCRAM credential
	return DeriveCredential(username, password, salt, time, memory, threads)
}

func computeHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor length mismatch")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}