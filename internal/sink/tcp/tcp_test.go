package tcp

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
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

// Stop writes what is queued, in the sink and per client, to a client that
// keeps reading, whatever another that stopped reading does: the end of a
// finite input reaches it whole, and Stop returns at the flush bound.
func TestStopWritesQueuedEventsToReadingClients(t *testing.T) {
	const n = 2000 // of 8 KiB: more than a silent peer's socket buffers hold
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
		"host": "127.0.0.1", "port": p, "buffer_size": int64(n), "client_buffer_size": int64(64),
		"write_timeout_ms": int64(2000),
	}, log.NewLogger(), session.NewProxy(manager, "out"))
	if err != nil {
		t.Fatal(err)
	}
	sink := created.(*TCPSink)
	if err := sink.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	for range 2 {
		conn, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conns = append(conns, conn)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		sink.clientsMu.Lock()
		registered := len(sink.clients)
		sink.clientsMu.Unlock()
		if registered == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("clients never registered")
		}
	}
	lines := make(chan int)
	go func() {
		count, scanner := 0, bufio.NewScanner(conns[0])
		scanner.Buffer(nil, 64*1024)
		for scanner.Scan() {
			count++
		}
		lines <- count
	}()
	// Held, the lock keeps the input queued until Stop has begun its flush
	sink.clientsMu.Lock()
	padding := strings.Repeat("x", 8192)
	for i := range n {
		sink.Input() <- core.TransportEvent{Payload: fmt.Appendf(nil, "line %d %s\n", i, padding)}
	}
	stopped := make(chan time.Duration)
	go func() {
		start := time.Now()
		sink.Stop()
		stopped <- time.Since(start)
	}()
	time.Sleep(100 * time.Millisecond)
	sink.clientsMu.Unlock()
	if d := <-stopped; d > 3500*time.Millisecond {
		t.Errorf("Stop took %v past a 2 s flush bound", d)
	}
	if got := <-lines; got != n {
		t.Fatalf("reading client received %d of %d lines", got, n)
	}
}
