package chain

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
)

// ProtocolVersion is declared in the hello preamble
const ProtocolVersion = 1

// Hello is the first NDJSON line a dialer sends after connect. Fields are
// optional so older peers ignore what they do not know; a field a peer must
// understand needs a ProtocolVersion bump. Scram opens an authentication
// exchange (authz owns its content), so chain need not know the auth library.
type Hello struct {
	LogWisp int             `json:"logwisp"`
	Node    string          `json:"node,omitempty"`
	Scram   json.RawMessage `json:"scram,omitempty"`
}

// HTTP transport mapping of the chain protocol: protocol and node travel as
// request headers, SCRAM runs on AuthPath and yields a bearer token.
const (
	HeaderProtocol    = "X-Logwisp-Protocol"
	HeaderNode        = "X-Logwisp-Node"
	HeaderAccepted    = "X-Logwisp-Accepted"
	ContentTypeNDJSON = "application/x-ndjson"
	AuthPath          = "/auth"
)

// EncodeHello serializes a newline-terminated hello preamble
func EncodeHello(h Hello) ([]byte, error) {
	h.LogWisp = ProtocolVersion
	b, err := json.Marshal(h)
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
