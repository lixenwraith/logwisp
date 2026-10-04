package tcp

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/testutil"

	"github.com/lixenwraith/log"
)

// A peer that connects and never completes the TLS handshake does not hold
// Stop for the handshake timeout: shutdown reaches connections before they
// become clients.
func TestStopDoesNotWaitForSilentHandshake(t *testing.T) {
	pki := testutil.NewPKI(t, "viewer")
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.ParseInt(port, 10, 64)

	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewTCPSinkPlugin("out", map[string]any{
		"host": "127.0.0.1",
		"port": p,
		"tls":  map[string]any{"enabled": true, "cert_file": pki.ServerCert, "key_file": pki.ServerKey},
	}, log.NewLogger(), session.NewProxy(manager, "out"))
	if err != nil {
		t.Fatal(err)
	}
	sink := created.(*TCPSink)
	if err := sink.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for deadline := time.Now().Add(2 * time.Second); sink.activeConns.Load() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("connection never reached the handshake")
		}
	}

	start := time.Now()
	sink.Stop()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Stop took %v with a silent peer in the handshake", d)
	}
}
