package chain

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
)

// An entry line is kept up to the length a chain source's scanner takes and
// refused past it, escapes counted: a short message of control bytes is refused
func TestEntryLineIsRefusedWhereASourceWouldRefuseIt(t *testing.T) {
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	enc := NewEncoder()
	encode := func(msg string) ([]byte, error) { return enc.Append(nil, core.LogEntry{Time: at, Message: msg}) }
	one, err := encode("x")
	if err != nil {
		t.Fatal(err)
	}
	fits := strings.Repeat("x", core.MaxLogEntryBytes-len(one)+1)
	line, err := encode(fits)
	if err != nil || len(line) != core.MaxLogEntryBytes {
		t.Fatalf("a %d-byte line: %v", len(line), err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(line))
	scanner.Buffer(make([]byte, 0, 64*1024), core.MaxLogEntryBytes)
	if !scanner.Scan() {
		t.Fatalf("a source refuses the longest line kept: %v", scanner.Err())
	}
	for _, msg := range []string{fits + "x", strings.Repeat("\x01", core.MaxLogEntryBytes/6+1)} {
		if _, err := encode(msg); !errors.Is(err, ErrEntryTooLong) {
			t.Fatalf("a %d-byte message encoded: %v", len(msg), err)
		}
	}
}

// A hello's node label is refused past 256 bytes or with a control byte: lw
// logs it, keys sessions by it and stamps it on entries
func TestNodeLabelPastTheBoundOrWithAControlByteIsRefused(t *testing.T) {
	for label, ok := range map[string]bool{
		strings.Repeat("n", MaxNodeBytes):   true,
		"edge-01 (rack 3)":                  true,
		strings.Repeat("n", MaxNodeBytes+1): false,
		"edge\n2026-11-13T00:00:00Z INFO x": false,
		"edge\x1b]0;title\x07":              false,
		"edge\u0085":                        false, // C1 next line
	} {
		line, err := EncodeHello(Hello{Node: label})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeHello(line); (err == nil) != ok {
			t.Errorf("label %q: %v", label, err)
		}
	}
}
