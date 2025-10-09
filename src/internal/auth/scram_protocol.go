// FILE: src/internal/auth/scram_protocol.go
package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lixenwraith/log"
	"github.com/panjf2000/gnet/v2"
)

// ScramProtocolHandler handles SCRAM message exchange for TCP
type ScramProtocolHandler struct {
	manager *ScramManager
	logger  *log.Logger
}

// NewScramProtocolHandler creates protocol handler
func NewScramProtocolHandler(manager *ScramManager, logger *log.Logger) *ScramProtocolHandler {
	return &ScramProtocolHandler{
		manager: manager,
		logger:  logger,
	}
}

// HandleAuthMessage processes a complete auth line from buffer
func (sph *ScramProtocolHandler) HandleAuthMessage(line []byte, conn gnet.Conn) (authenticated bool, session *Session, err error) {
	// Parse SCRAM messages
	parts := strings.Fields(string(line))
	if len(parts) < 2 {
		conn.AsyncWrite([]byte("SCRAM-FAIL Invalid message format\n"), nil)
		return false, nil, fmt.Errorf("invalid message format")
	}

	switch parts[0] {
	case "SCRAM-FIRST":
		// Parse ClientFirst JSON
		var clientFirst ClientFirst
		if err := json.Unmarshal([]byte(parts[1]), &clientFirst); err != nil {
			conn.AsyncWrite([]byte("SCRAM-FAIL Invalid JSON\n"), nil)
			return false, nil, fmt.Errorf("invalid JSON")
		}

		// Process with SCRAM server
		serverFirst, err := sph.manager.HandleClientFirst(&clientFirst)
		if err != nil {
			// Still send challenge to prevent user enumeration
			response, _ := json.Marshal(serverFirst)
			conn.AsyncWrite([]byte(fmt.Sprintf("SCRAM-CHALLENGE %s\n", response)), nil)
			return false, nil, err
		}

		// Send ServerFirst challenge
		response, _ := json.Marshal(serverFirst)
		conn.AsyncWrite([]byte(fmt.Sprintf("SCRAM-CHALLENGE %s\n", response)), nil)
		return false, nil, nil // Not authenticated yet

	case "SCRAM-PROOF":
		// Parse ClientFinal JSON
		var clientFinal ClientFinal
		if err := json.Unmarshal([]byte(parts[1]), &clientFinal); err != nil {
			conn.AsyncWrite([]byte("SCRAM-FAIL Invalid JSON\n"), nil)
			return false, nil, fmt.Errorf("invalid JSON")
		}

		// Verify proof
		serverFinal, err := sph.manager.HandleClientFinal(&clientFinal)
		if err != nil {
			conn.AsyncWrite([]byte("SCRAM-FAIL Authentication failed\n"), nil)
			return false, nil, err
		}

		// Authentication successful
		session = &Session{
			ID:         serverFinal.SessionID,
			Method:     "scram-sha-256",
			RemoteAddr: conn.RemoteAddr().String(),
			CreatedAt:  time.Now(),
		}

		// Send ServerFinal with signature
		response, _ := json.Marshal(serverFinal)
		conn.AsyncWrite([]byte(fmt.Sprintf("SCRAM-OK %s\n", response)), nil)

		return true, session, nil

	default:
		conn.AsyncWrite([]byte("SCRAM-FAIL Unknown command\n"), nil)
		return false, nil, fmt.Errorf("unknown command: %s", parts[0])
	}
}

// FormatSCRAMRequest formats a SCRAM protocol message for TCP
func FormatSCRAMRequest(command string, data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal %s: %w", command, err)
	}
	return fmt.Sprintf("%s %s\n", command, jsonData), nil
}

// ParseSCRAMResponse parses a SCRAM protocol response from TCP
func ParseSCRAMResponse(response string) (command string, data string, err error) {
	response = strings.TrimSpace(response)
	parts := strings.SplitN(response, " ", 2)
	if len(parts) < 1 {
		return "", "", fmt.Errorf("empty response")
	}

	command = parts[0]
	if len(parts) > 1 {
		data = parts[1]
	}
	return command, data, nil
}