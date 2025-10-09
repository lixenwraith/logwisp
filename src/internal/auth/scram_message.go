// FILE: src/internal/auth/scram_message.go
package auth

import (
	"fmt"
)

// ClientFirst initiates authentication
type ClientFirst struct {
	Username    string `json:"u"`
	ClientNonce string `json:"n"`
}

// ServerFirst contains server challenge
type ServerFirst struct {
	FullNonce    string `json:"r"` // client_nonce + server_nonce
	Salt         string `json:"s"` // base64
	ArgonTime    uint32 `json:"t"`
	ArgonMemory  uint32 `json:"m"`
	ArgonThreads uint8  `json:"p"`
}

// ClientFinal contains client proof
type ClientFinal struct {
	FullNonce   string `json:"r"`
	ClientProof string `json:"p"` // base64
}

// ServerFinal contains server signature for mutual auth
type ServerFinal struct {
	ServerSignature string `json:"v"` // base64
	SessionID       string `json:"sid,omitempty"`
}

func (sf *ServerFirst) Marshal() string {
	return fmt.Sprintf("r=%s,s=%s,t=%d,m=%d,p=%d",
		sf.FullNonce, sf.Salt, sf.ArgonTime, sf.ArgonMemory, sf.ArgonThreads)
}