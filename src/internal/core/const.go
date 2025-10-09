// FILE: logwisp/src/internal/core/const.go
package core

// Argon2id parameters
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4
	Argon2SaltLen = 16
	Argon2KeyLen  = 32
)

const DefaultTokenLength = 32