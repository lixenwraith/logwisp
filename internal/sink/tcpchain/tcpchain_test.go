package tcpchain

import (
	"bufio"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"logwisp/internal/core"
	"logwisp/internal/session"

	"github.com/lixenwraith/log"
)

// A source that refuses each link right after the hello, as a scram source
// does to a sink without credentials, is retried with growing delays, not in
// a tight loop that logs an established link every round.
func TestRefusingSourceIsRetriedWithBackoff(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepts atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			bufio.NewReader(conn).ReadString('\n')
			conn.Write([]byte(`{"error":"authentication required"}` + "\n"))
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.ParseInt(port, 10, 64)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	created, err := NewTCPChainSinkPlugin("fwd", map[string]any{
		"host": "127.0.0.1", "port": p, "backoff_min_ms": int64(20), "backoff_max_ms": int64(5000),
	}, log.NewLogger(), session.NewProxy(manager, "fwd"))
	if err != nil {
		t.Fatal(err)
	}
	sink := created.(*TCPChainSink)
	if err := sink.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Stop)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case sink.Input() <- core.TransportEvent{Time: time.Now(), Payload: []byte("entry")}:
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	// 20 ms doubling reaches 1.5 s in about 7 attempts; a constant delay
	// would take dozens
	if n := accepts.Load(); n > 10 {
		t.Fatalf("%d connections in 1.5 s against a refusing source", n)
	}
}
