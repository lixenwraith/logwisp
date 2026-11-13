package tcpchain

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/session"

	"github.com/lixenwraith/log"
)

// A burst of connections is admitted up to max_connections and no further:
// each takes its slot before the check, not once its handler runs
func TestBurstIsAdmittedUpToMaxConnections(t *testing.T) {
	const limit, burst = 4, 300
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
	created, err := NewTCPChainSourcePlugin("in", map[string]any{"host": "127.0.0.1", "port": p, "max_connections": int64(limit)},
		log.NewLogger(), session.NewProxy(manager, "in"))
	if err != nil {
		t.Fatal(err)
	}
	src := created.(*TCPChainSource)
	if err := src.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.Stop)
	// A refused connection is closed at once; an admitted one waits for its hello
	open := make(chan bool, burst)
	for range burst {
		go func() {
			conn, err := net.Dial("tcp4", addr)
			if err != nil {
				open <- false
				return
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(time.Second))
			_, err = conn.Read(make([]byte, 1))
			open <- os.IsTimeout(err)
		}()
	}
	admitted := 0
	for range burst {
		if <-open {
			admitted++
		}
	}
	if admitted != limit {
		t.Fatalf("admitted %d of a burst of %d, max_connections %d", admitted, burst, limit)
	}
}

// An accept error that persists, such as EMFILE, is retried after a growing
// delay, not at once in a loop that pins a CPU and floods the log
func TestAcceptErrorsAreRetriedAfterADelay(t *testing.T) {
	l := &failingListener{closed: make(chan struct{})}
	src := &TCPChainSource{listener: l, logger: log.NewLogger()}
	ctx, cancel := context.WithCancel(t.Context())
	src.ctx = ctx
	src.wg.Add(1)
	go src.acceptLoop()
	time.Sleep(200 * time.Millisecond)
	cancel()
	close(l.closed)
	src.wg.Wait()
	// 5, 10, 20, 40, 80 ms: six tries fit in 200 ms
	if n := l.calls.Load(); n > 8 {
		t.Fatalf("%d accepts in 200 ms of errors", n)
	}
}

type failingListener struct {
	net.Listener
	calls  atomic.Int64
	closed chan struct{}
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, syscall.EMFILE
	}
}
