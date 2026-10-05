package tcpchain

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/session"

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

// Stop delivers what is queued, so the end of a finite input reaches the
// source whole, and returns at the flush bound when the source stops reading.
func TestStopDeliversTheQueueWithinTheBound(t *testing.T) {
	const n = 2000 // of 8 KiB: more than a stalled source's socket buffers hold
	padding := strings.Repeat("x", 8192)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	// stop queues n entries, starts and stops a sink, and returns how long
	// Stop took and how many entries a reading source received
	stop := func(reading bool) (time.Duration, int) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		lines := make(chan int, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			if !reading {
				<-t.Context().Done()
				return
			}
			count, scanner := -1, bufio.NewScanner(conn) // -1: the hello
			scanner.Buffer(nil, 64*1024)
			for scanner.Scan() {
				count++
			}
			lines <- count
		}()
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.ParseInt(port, 10, 64)
		created, err := NewTCPChainSinkPlugin("fwd", map[string]any{
			"host": "127.0.0.1", "port": p, "buffer_size": int64(n), // writes time out at 5 s
		}, log.NewLogger(), session.NewProxy(manager, "fwd"))
		if err != nil {
			t.Fatal(err)
		}
		sink := created.(*TCPChainSink)
		for i := range n {
			sink.Input() <- core.TransportEvent{Time: time.Now(), Payload: fmt.Appendf(nil, "entry %d %s", i, padding)}
		}
		if err := sink.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		sink.Stop()
		d := time.Since(start)
		if !reading {
			return d, 0
		}
		select {
		case got := <-lines:
			return d, got
		case <-time.After(5 * time.Second):
			return d, 0
		}
	}
	if _, got := stop(true); got != n {
		t.Fatalf("the source received %d of %d entries", got, n)
	}
	if d, _ := stop(false); d > 3500*time.Millisecond {
		t.Fatalf("Stop took %v past a 2 s flush bound", d)
	}
}
