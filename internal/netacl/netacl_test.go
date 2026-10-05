package netacl

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/log"
)

func mustNew(t *testing.T, host string, allow, deny []string) *Policy {
	t.Helper()
	p, err := New(&config.ACLOptions{Allow: allow, Deny: deny}, host, log.NewLogger(), "test", "acl")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Deny wins over allow, a set allow list admits only its entries, an empty
// one admits all not denied, an IPv4-mapped peer matches as IPv4, and a peer
// of unknown address is refused.
func TestDenyWinsThenAllowListAdmitsOnlyItsEntries(t *testing.T) {
	listed := mustNew(t, "0.0.0.0", []string{"127.0.0.0/8"}, []string{"127.0.0.2"})
	denyOnly := mustNew(t, "0.0.0.0", nil, []string{"10.0.0.0/8"})
	for _, c := range []struct {
		p    *Policy
		addr string
		want bool
	}{
		{listed, "127.0.0.1", true},
		{listed, "127.0.0.2", false},
		{listed, "192.0.2.1", false},
		{denyOnly, "10.1.2.3", false},
		{denyOnly, "192.0.2.1", true},
		{denyOnly, "::ffff:10.1.2.3", false},
		{denyOnly, "", false},
	} {
		addr, _ := netip.ParseAddr(c.addr)
		if got := c.p.admits(addr); got != c.want {
			t.Errorf("%s under %s: admitted %v", c.addr, c.p.Describe(), got)
		}
	}
}

// Entries are of the family core.Network gives the listener's host, as its
// sockets carry no other: IPv4 on an IPv4 listener, IPv6 on an IPv6 one,
// either behind a hostname; never IPv4-mapped, never with a zone.
func TestEntriesFollowTheListenerFamily(t *testing.T) {
	for _, c := range []struct {
		host, entry string
		ok          bool
	}{
		{"0.0.0.0", "10.0.0.0/8", true},
		{"0.0.0.0", "2001:db8::/32", false},
		{"::", "2001:db8::1", true},
		{"::", "10.0.0.1", false},
		{"::", "::ffff:10.0.0.1", false},
		{"::", "fe80::1%eth0", false},
		{"logs.example", "10.0.0.0/8", true},
		{"logs.example", "2001:db8::/32", true},
	} {
		_, err := New(&config.ACLOptions{Deny: []string{c.entry}}, c.host, log.NewLogger(), "test", "acl")
		if (err == nil) != c.ok {
			t.Errorf("%s on %q: %v", c.entry, c.host, err)
		}
	}
}

// A link-local peer carries its interface zone, which no prefix contains:
// it is matched without it, or a deny of fe80::/10 would admit it.
func TestZonedPeerMatchesItsPrefix(t *testing.T) {
	p := mustNew(t, "::", nil, []string{"fe80::/10"})
	if p.admits(netip.MustParseAddr("fe80::1%eth0")) {
		t.Fatal("a zoned link-local peer passed the deny of its prefix")
	}
}

// A refused peer is closed as it is accepted and counted: the plugin's
// Accept returns the next admitted one.
func TestRefusedPeerNeverReachesAccept(t *testing.T) {
	inner := &fakeListener{conns: make(chan net.Conn, 2)}
	refused, refusedPeer := net.Pipe()
	admitted, _ := net.Pipe()
	inner.conns <- remoteAt(refused, "192.0.2.1")
	inner.conns <- remoteAt(admitted, "127.0.0.1")
	ln := mustNew(t, "127.0.0.1", nil, []string{"192.0.2.0/24"}).Listener(inner)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.RemoteAddr().String(); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("Accept returned %s", got)
	}
	refusedPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := refusedPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the refused peer reads %v, want EOF", err)
	}
	if n := ln.(*listener).p.Stats()["acl_denied"]; n != uint64(1) {
		t.Fatalf("acl_denied = %v", n)
	}
}

type fakeListener struct {
	net.Listener
	conns chan net.Conn
}

func (f *fakeListener) Accept() (net.Conn, error) { return <-f.conns, nil }

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

func remoteAt(c net.Conn, addr string) net.Conn {
	return remoteConn{c, net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addr), 40000))}
}
