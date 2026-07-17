package chain

import (
	"encoding/json"
	"fmt"
	"logwisp/src/internal/core"
	"math/rand/v2"
	"time"
)

// ProtocolVersion is declared in the hello preamble
const ProtocolVersion = 1

// Hello is the first NDJSON line sent by the dialing side after connect.
// Reserved for future revisions: auth credential, feature flags (ack, compression).
type Hello struct {
	LogWisp int    `json:"logwisp"`
	Node    string `json:"node,omitempty"`
	// Auth     string   `json:"auth,omitempty"`
	// Features []string `json:"features,omitempty"`
}

// HTTP transport mapping of the chain protocol.
// Hello preamble equivalent: protocol + node carried as request headers.
// Reserved extension point: Authorization header for auth, TLS at transport.
const (
	HeaderProtocol    = "X-Logwisp-Protocol"
	HeaderNode        = "X-Logwisp-Node"
	HeaderAccepted    = "X-Logwisp-Accepted"
	ContentTypeNDJSON = "application/x-ndjson"
)

// EncodeHello serializes a newline-terminated hello preamble
func EncodeHello(node string) ([]byte, error) {
	b, err := json.Marshal(Hello{LogWisp: ProtocolVersion, Node: node})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeHello parses and validates a hello preamble line
func DecodeHello(line []byte) (Hello, error) {
	var h Hello
	if err := json.Unmarshal(line, &h); err != nil {
		return h, fmt.Errorf("malformed hello: %w", err)
	}
	if h.LogWisp != ProtocolVersion {
		return h, fmt.Errorf("unsupported protocol version: %d", h.LogWisp)
	}
	return h, nil
}

// DecodeEntry parses a canonical LogEntry line and applies the node trust policy
func DecodeEntry(line []byte, connNode string, trustNode bool) (core.LogEntry, error) {
	var entry core.LogEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return core.LogEntry{}, err
	}
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	if entry.Node == "" || !trustNode {
		entry.Node = connNode
	}
	entry.RawSize = int64(len(line))
	return entry, nil
}

// EntryFromEvent extracts the structured entry, stamping node identity at
// first hop. Second return is true when synthesized from a formatted payload.
func EntryFromEvent(event core.TransportEvent, node, fallbackSource string) (core.LogEntry, bool) {
	entry := event.Entry
	synthesized := false
	if entry.Time.IsZero() {
		synthesized = true
		entry = core.LogEntry{
			Time:    event.Time,
			Source:  fallbackSource,
			Message: string(event.Payload),
		}
	}
	if entry.Node == "" {
		entry.Node = node
	}
	return entry, synthesized
}

// BackoffDelay computes exponential backoff with ±20% jitter
func BackoffDelay(minD, maxD time.Duration, failures int) time.Duration {
	d := maxD
	if failures < 63 {
		if v := minD << uint(failures-1); v > 0 && v < maxD {
			d = v
		}
	}
	return d - d/5 + time.Duration(rand.Int64N(int64(2*d/5)+1))
}
