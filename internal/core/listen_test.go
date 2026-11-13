package core

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

// A hostname listener binds one of its addresses, IPv4 when it has one, in
// that address's family alone, a name for a wildcard address too.
func TestHostnameListenerKeepsToOneFamily(t *testing.T) {
	names := map[string][]netip.Addr{
		"wild4": {netip.MustParseAddr("0.0.0.0")},
		"wild6": {netip.MustParseAddr("::")},
		"both":  {netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:127.0.0.1")},
	}
	saved := lookupNetIP
	t.Cleanup(func() { lookupNetIP = saved })
	lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) { return names[host], nil }
	for _, tc := range []struct{ network, addr, wantNetwork, wantAddr string }{
		{"tcp", "wild4:80", "tcp4", "0.0.0.0:80"},
		{"tcp", "wild6:80", "tcp6", "[::]:80"},
		{"tcp", "both:80", "tcp4", "127.0.0.1:80"},
		{"tcp6", "[::1]:80", "tcp6", "[::1]:80"},
	} {
		network, addr, err := pinFamily(t.Context(), tc.network, tc.addr)
		if err != nil || network != tc.wantNetwork || addr != tc.wantAddr {
			t.Errorf("%s %s: %s %s, %v; want %s %s", tc.network, tc.addr, network, addr, err, tc.wantNetwork, tc.wantAddr)
		}
	}
	if _, _, err := pinFamily(t.Context(), "tcp", "none:80"); err == nil {
		t.Error("a name without addresses was accepted")
	}
}

// A closed listener's socket stays bound: a client connecting meanwhile waits
// in its backlog, and the next listener on the address accepts it, with its
// own keep-alive setting. A second listener on an address in use fails, and
// ReleaseIdle closes the socket no listener uses.
func TestNextListenerTakesOverTheSocket(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	t.Cleanup(ReleaseIdle)
	lc := &net.ListenConfig{KeepAlive: -1}
	first, err := Listen(t.Context(), lc, "tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(t.Context(), lc, "tcp4", addr); err == nil {
		t.Fatal("two listeners took one address")
	}
	first.Close()
	client, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("refused between listeners: %v", err)
	}
	defer client.Close()
	client.Write([]byte("x"))
	next, err := Listen(t.Context(), lc, "tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := next.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := make([]byte, 1)
	if _, err := io.ReadFull(conn, got); err != nil || got[0] != 'x' {
		t.Fatalf("read %q, %v from the waiting client", got, err)
	}
	keepAlive := -1
	raw, _ := conn.(*net.TCPConn).SyscallConn()
	raw.Control(func(fd uintptr) {
		keepAlive, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	})
	if keepAlive != 0 {
		t.Errorf("SO_KEEPALIVE %d on a listener told none", keepAlive)
	}
	next.Close()
	ReleaseIdle()
	if c, err := net.Dial("tcp4", addr); !errors.Is(err, syscall.ECONNREFUSED) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("dial after ReleaseIdle: %v, want refused", err)
	}
}
