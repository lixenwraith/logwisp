// FILE: src/internal/scram/message.go
package scram

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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

// Marshal/Unmarshal helpers for TCP protocol (line-based)
func (cf *ClientFirst) Marshal() string {
	return fmt.Sprintf("u=%s,n=%s", cf.Username, cf.ClientNonce)
}

func ParseClientFirst(data string) (*ClientFirst, error) {
	parts := strings.Split(data, ",")
	msg := &ClientFirst{}
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "u":
			msg.Username = kv[1]
		case "n":
			msg.ClientNonce = kv[1]
		}
	}
	if msg.Username == "" || msg.ClientNonce == "" {
		return nil, fmt.Errorf("missing required fields")
	}
	return msg, nil
}

func (sf *ServerFirst) Marshal() string {
	return fmt.Sprintf("r=%s,s=%s,t=%d,m=%d,p=%d",
		sf.FullNonce, sf.Salt, sf.ArgonTime, sf.ArgonMemory, sf.ArgonThreads)
}

func ParseServerFirst(data string) (*ServerFirst, error) {
	parts := strings.Split(data, ",")
	msg := &ServerFirst{}
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "r":
			msg.FullNonce = kv[1]
		case "s":
			msg.Salt = kv[1]
		case "t":
			fmt.Sscanf(kv[1], "%d", &msg.ArgonTime)
		case "m":
			fmt.Sscanf(kv[1], "%d", &msg.ArgonMemory)
		case "p":
			fmt.Sscanf(kv[1], "%d", &msg.ArgonThreads)
		}
	}
	return msg, nil
}

// JSON variants for HTTP
func (cf *ClientFirst) MarshalJSON() ([]byte, error) {
	return json.Marshal(*cf)
}

func (sf *ServerFirst) MarshalJSON() ([]byte, error) {
	sf.Salt = base64.StdEncoding.EncodeToString([]byte(sf.Salt))
	return json.Marshal(*sf)
}