// Package chain is the protocol between logwisp nodes: the hello a dialer
// opens with (ProtocolVersion, node, SCRAM), the NDJSON entries after it, the
// headers and /auth path of its HTTP mapping, and the reconnect backoff the
// chain sinks share.
package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
	"unicode"

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

// ErrEntryTooLong refuses an entry line a chain source would refuse
var ErrEntryTooLong = fmt.Errorf("entry line over %d bytes", core.MaxLogEntryBytes)

// Encoder appends entry lines to a caller's buffer, for one goroutine: a
// sink's run loop
type Encoder struct {
	out   appender
	enc   *json.Encoder
	entry core.LogEntry // encoded by pointer: by value json copies it twice
}

// appender is the Encoder's writer: the caller's buffer, during one Append
type appender struct{ b []byte }

func (a *appender) Write(p []byte) (int, error) {
	a.b = append(a.b, p...)
	return len(p), nil
}

// NewEncoder returns an Encoder
func NewEncoder() *Encoder {
	e := new(Encoder)
	e.enc = json.NewEncoder(&e.out)
	e.enc.SetEscapeHTML(false) // decoded at the source, never put in a page
	return e
}

// Append appends entry's newline-terminated line to dst. Escapes can take an
// entry under the 1 MiB line cap past it, and a source refusing the line costs
// the link (tcp) or the whole batch (http), so such a line is not appended.
func (e *Encoder) Append(dst []byte, entry core.LogEntry) ([]byte, error) {
	e.entry, e.out.b = entry, dst
	err := e.enc.Encode(&e.entry)
	line := e.out.b
	e.out.b = nil
	switch {
	case err != nil:
		return dst, err
	case len(line)-len(dst) > core.MaxLogEntryBytes: // the newline counts, as at the source
		return dst, ErrEntryTooLong
	}
	return line, nil
}

// MaxNodeBytes bounds a node label, well past a host name's 255 bytes
const MaxNodeBytes = 256

// CheckNode refuses a node label lw could not log, key sessions by or stamp
// on entries as it is: a control byte would reach lw's own log raw (a forged
// line, a terminal escape), and a peer's label has no other bound
func CheckNode(node string) error {
	if len(node) > MaxNodeBytes {
		return fmt.Errorf("node label longer than %d bytes", MaxNodeBytes)
	}
	if strings.ContainsFunc(node, unicode.IsControl) {
		return errors.New("node label holds a control character")
	}
	return nil
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
	if err := CheckNode(h.Node); err != nil {
		return h, fmt.Errorf("hello: %w", err)
	}
	return h, nil
}

// DecodeEntry parses a canonical LogEntry line into entry, which its caller
// keeps from line to line so none moves to the heap, and applies the node
// trust policy. entry is reset first: Unmarshal would append Fields into the
// array of the entry decoded before, which subscribers hold.
func DecodeEntry(entry *core.LogEntry, line []byte, connNode string, trustNode bool) error {
	*entry = core.LogEntry{}
	if err := json.Unmarshal(line, entry); err != nil {
		return err
	}
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	if entry.Node == "" || !trustNode {
		entry.Node = connNode
	}
	entry.RawSize = int64(len(line))
	return nil
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
