package netacl

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/log"
)

func mustNew(t *testing.T, host string, o config.ACLOptions) *Policy {
	t.Helper()
	p, err := New(&o, host, log.NewLogger(), "test", "acl")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Deny wins over allow, a set allow list admits only its entries, an empty
// one admits all not denied, an IPv4-mapped peer matches as IPv4, and a peer
// of unknown address is refused.
func TestDenyWinsThenAllowListAdmitsOnlyItsEntries(t *testing.T) {
	listed := mustNew(t, "0.0.0.0", config.ACLOptions{Allow: []string{"127.0.0.0/8"}, Deny: []string{"127.0.0.2"}})
	denyOnly := mustNew(t, "0.0.0.0", config.ACLOptions{Deny: []string{"10.0.0.0/8"}})
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
// either behind a hostname; never IPv4-mapped, never with a zone. Behind
// proxy_from, which keeps that family, deny takes both: the proxy names either.
func TestEntriesFollowTheListenerFamily(t *testing.T) {
	for _, c := range []struct {
		host, from, entry string
		ok                bool
	}{
		{"0.0.0.0", "", "10.0.0.0/8", true},
		{"0.0.0.0", "", "2001:db8::/32", false},
		{"::", "", "2001:db8::1", true},
		{"::", "", "10.0.0.1", false},
		{"::", "", "::ffff:10.0.0.1", false},
		{"::", "", "fe80::1%eth0", false},
		{"logs.example", "", "10.0.0.0/8", true},
		{"logs.example", "", "2001:db8::/32", true},
		{"0.0.0.0", "10.0.0.5", "2001:db8::/32", true},
		{"0.0.0.0", "2001:db8::5", "10.0.0.0/8", false},
	} {
		o := &config.ACLOptions{Deny: []string{c.entry}}
		if c.from != "" {
			o.ProxyProtocol, o.ProxyFrom = "required", []string{c.from}
		}
		if _, err := New(o, c.host, log.NewLogger(), "test", "acl"); (err == nil) != c.ok {
			t.Errorf("%s behind %q on %q: %v", c.entry, c.from, c.host, err)
		}
	}
}

// A link-local peer carries its interface zone, which no prefix contains: the
// rules match it without, or a deny of fe80::/10 would admit it. It is never
// a proxy, as any link can claim its address.
func TestZonedPeerMatchesRulesButIsNoProxy(t *testing.T) {
	p := mustNew(t, "::", config.ACLOptions{Deny: []string{"fe80::/10"}, ProxyProtocol: "required", ProxyFrom: []string{"fe80::/10"}})
	if zoned := netip.MustParseAddr("fe80::1%eth0"); p.admits(zoned) || p.proxies(zoned) {
		t.Fatal("a zoned link-local peer passed the deny of its prefix, or as a proxy")
	}
}

// A refused peer is closed as it is accepted and counted: the plugin's
// Accept returns the next admitted one.
func TestRefusedPeerNeverReachesAccept(t *testing.T) {
	p := mustNew(t, "127.0.0.1", config.ACLOptions{Deny: []string{"192.0.2.0/24"}})
	ln, dial := listening(t, p)
	refused := dial("192.0.2.1")
	dial("127.0.0.1")
	if got := accept(t, ln).RemoteAddr().String(); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("Accept returned %s", got)
	}
	closed(t, refused)
	if n := p.Stats()["acl_denied"]; n != uint64(1) {
		t.Fatalf("acl_denied = %v", n)
	}
}

// proxy_protocol and proxy_from come together: either alone is a mistake, as
// is a mode that is none of off, optional and required
func TestProxyProtocolAndProxyFromComeTogether(t *testing.T) {
	for _, c := range []struct {
		mode string
		from []string
		ok   bool
	}{
		{"required", nil, false},
		{"", []string{"127.0.0.1"}, false},
		{"off", []string{"127.0.0.1"}, false},
		{"always", nil, false},
		{"optional", []string{"127.0.0.1"}, true},
	} {
		_, err := New(&config.ACLOptions{ProxyProtocol: c.mode, ProxyFrom: c.from}, "127.0.0.1", log.NewLogger(), "test", "acl")
		if (err == nil) != c.ok {
			t.Errorf("proxy_protocol %q with proxy_from %v: %v", c.mode, c.from, err)
		}
	}
}

// A v1 or v2 header names the client, IPv4-mapped as IPv4 (as throttling
// keys it), and leaves the bytes after it, TLVs skipped.
func TestHeaderNamesItsClient(t *testing.T) {
	for _, c := range []struct{ header, client string }{
		{"PROXY TCP4 198.51.100.1 192.0.2.1 40000 443\r\n", "198.51.100.1:40000"},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 40000 443\r\n", "[2001:db8::1]:40000"},
		{"PROXY TCP6 ::ffff:198.51.100.1 ::ffff:192.0.2.1 40000 443\r\n", "198.51.100.1:40000"},
		{v2(0x21, 0x11, block("198.51.100.1", "192.0.2.1")), "198.51.100.1:40000"},
		{v2(0x21, 0x21, block("2001:db8::1", "2001:db8::2", 0x04, 0x00, 0x01, 0xff)), "[2001:db8::1]:40000"},
		{v2(0x21, 0x21, block("::ffff:198.51.100.1", "::ffff:192.0.2.1")), "198.51.100.1:40000"},
	} {
		client, found, rest, err := parseHeader(c.header + "rest")
		if err != nil || !found || client.String() != c.client || rest != "rest" {
			t.Errorf("%q: client %v found %v rest %q: %v", c.header, client, found, rest, err)
		}
	}
}

// LOCAL, UNKNOWN and the families v2 leaves unspecified keep the socket
// address, whatever address block they carry
func TestLocalAndUnknownKeepTheSocketAddress(t *testing.T) {
	for _, header := range []string{
		"PROXY UNKNOWN\r\n",
		"PROXY UNKNOWN " + strings.Repeat("x", 91) + "\r\n", // 107 bytes
		v2(0x20, 0x11, block("198.51.100.1", "192.0.2.1")),
		v2(0x20, 0x00, nil),
		v2(0x21, 0x00, nil),
		v2(0x21, 0x12, block("198.51.100.1", "192.0.2.1")),
		v2(0x21, 0x31, make([]byte, 216)),
	} {
		client, found, rest, err := parseHeader(header + "rest")
		if err != nil || !found || client.IsValid() || rest != "rest" {
			t.Errorf("%q: client %v found %v rest %q: %v", header, client, found, rest, err)
		}
	}
}

// A malformed, oversized or truncated header is an error, never a client
func TestMalformedHeaderIsRefused(t *testing.T) {
	inet := v2(0x21, 0x11, block("198.51.100.1", "192.0.2.1"))
	for _, header := range []string{
		"PROXY UNKNOWN 198.51.100.1 192.0.2.1 40000 443\n",
		"PROXY UNKNOWN " + strings.Repeat("x", 92) + "\r\n",
		"PROXY TCP4 2001:db8::1 192.0.2.1 40000 443\r\n",
		"PROXY TCP4 198.51.100.1 2001:db8::2 40000 443\r\n",
		"PROXY TCP6 198.51.100.1 192.0.2.1 40000 443\r\n",
		"PROXY TCP4 198.51.100.1 192.0.2.1 70000 443\r\n",
		"PROXY TCP4 198.51.100.1 192.0.2.1 40000\r\n",
		"PROXY TCP6 fe80::1%eth0 fe80::2 40000 443\r\n",
		"PROXY UDP4 198.51.100.1 192.0.2.1 40000 443\r\n",
		"PROXY TCP4 198.51.100.1 192.0.2.1 40000 443",
		"PROX",
		v2(0x11, 0x11, block("198.51.100.1", "192.0.2.1")),
		v2(0x22, 0x11, block("198.51.100.1", "192.0.2.1")),
		v2(0x21, 0x41, block("198.51.100.1", "192.0.2.1")),
		v2(0x21, 0x11, make([]byte, v2Max+1)),
		v2(0x21, 0x11, block("198.51.100.1", "192.0.2.1")[:8]) + "rest",
		inet[:14],
		inet[:20],
	} {
		if client, found, _, err := parseHeader(header); err == nil || found {
			t.Errorf("%q: client %v found %v, no error", header, client, found)
		}
	}
}

// A peer outside proxy_from that sends a header is refused at its first
// read, as the header is spoofable; its other bytes pass untouched
func TestHeaderFromUnlistedPeerIsRefused(t *testing.T) {
	p := mustNew(t, "127.0.0.1", config.ACLOptions{ProxyProtocol: "optional", ProxyFrom: []string{"10.0.0.1"}})
	ln, dial := listening(t, p)
	for _, c := range []struct {
		send    string
		refused bool
	}{
		{"PROXY TCP4 198.51.100.1 192.0.2.1 40000 443\r\n", true},
		{v2(0x21, 0x11, block("198.51.100.1", "192.0.2.1")), true},
		{"POST / HTTP/1.1\r\n", false},
	} {
		go dial("192.0.2.9").Write([]byte(c.send))
		b := make([]byte, len(c.send))
		_, err := io.ReadFull(accept(t, ln), b)
		if (err != nil) != c.refused || !c.refused && string(b) != c.send {
			t.Errorf("%q from an unlisted peer: read %q, %v", c.send, b, err)
		}
	}
	if n := p.Denied(); n != 2 {
		t.Fatalf("acl_denied = %d", n)
	}
}

// Under required a peer in proxy_from must send a header; under optional
// one that sends none keeps its socket address and its bytes
func TestRequiredRefusesAListedPeerWithoutHeader(t *testing.T) {
	for mode, refused := range map[string]bool{"required": true, "optional": false} {
		p := mustNew(t, "127.0.0.1", config.ACLOptions{ProxyProtocol: mode, ProxyFrom: []string{"127.0.0.1"}})
		ln, dial := listening(t, p)
		peer := dial("127.0.0.1")
		peer.Write([]byte("GET /"))
		if refused {
			closed(t, peer)
			continue
		}
		conn := accept(t, ln)
		b := make([]byte, 5)
		if _, err := io.ReadFull(conn, b); err != nil || string(b) != "GET /" || conn.RemoteAddr().String() != "127.0.0.1:40000" {
			t.Errorf("optional: %s read %q: %v", conn.RemoteAddr(), b, err)
		}
	}
}

// The client a header names is what the rules, RemoteAddr and the stats see;
// the proxy stays as PeerAddr, under TLS too
func TestRulesSeeTheClientAHeaderNames(t *testing.T) {
	p := mustNew(t, "127.0.0.1", config.ACLOptions{ProxyProtocol: "required", ProxyFrom: []string{"127.0.0.1"}, Deny: []string{"198.51.100.2"}})
	ln, dial := listening(t, p)
	denied := dial("127.0.0.1")
	denied.Write([]byte("PROXY TCP4 198.51.100.2 192.0.2.1 40000 443\r\n"))
	go dial("127.0.0.1").Write([]byte("PROXY TCP4 198.51.100.1 192.0.2.1 40000 443\r\nhello"))
	conn := accept(t, ln)
	b := make([]byte, 5)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "hello" {
		t.Fatalf("read %q: %v", b, err)
	}
	if got, peer := conn.RemoteAddr().String(), PeerAddr(tls.Server(conn, nil)); got != "198.51.100.1:40000" || peer != "127.0.0.1:40000" {
		t.Fatalf("RemoteAddr %s, PeerAddr %q", got, peer)
	}
	closed(t, denied)
	if s := p.Stats(); s["acl_proxy_headers"] != uint64(2) || s["acl_denied"] != uint64(1) {
		t.Fatalf("stats %v", s)
	}
}

// A header still on its way holds only its own connection, and is refused
// at the deadline
func TestSlowHeaderHoldsOnlyItsConnection(t *testing.T) {
	p := mustNew(t, "127.0.0.1", config.ACLOptions{ProxyProtocol: "required", ProxyFrom: []string{"127.0.0.1"}})
	p.headerWait = time.Second
	ln, dial := listening(t, p)
	slow := dial("127.0.0.1")
	slow.Write([]byte("PROXY TCP4 198"))
	dial("192.0.2.9")
	if got := accept(t, ln).RemoteAddr().String(); !strings.HasPrefix(got, "192.0.2.9:") || p.Denied() != 0 {
		t.Fatalf("Accept returned %s after %d refusals", got, p.Denied())
	}
	closed(t, slow)
	if n := p.Denied(); n != 1 {
		t.Fatalf("acl_denied = %d", n)
	}
}

// Close also closes the connections whose header has not arrived
func TestCloseReleasesHeadersInFlight(t *testing.T) {
	p := mustNew(t, "127.0.0.1", config.ACLOptions{ProxyProtocol: "required", ProxyFrom: []string{"127.0.0.1"}})
	ln, dial := listening(t, p)
	slow := dial("127.0.0.1")
	slow.Write([]byte("PROXY "))
	ln.Close()
	closed(t, slow)
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
}

// Whatever the bytes, the parser neither panics nor reads past a header's
// bound, consumes nothing when no header starts the stream, and names a
// client only unmapped and without a zone.
func FuzzReadHeader(f *testing.F) {
	for _, seed := range []string{
		"PROXY TCP4 198.51.100.1 192.0.2.1 40000 443\r\nrest",
		"PROXY TCP6 2001:db8::1 2001:db8::2 40000 443\r\n",
		"PROXY UNKNOWN\r\n",
		v2(0x21, 0x11, block("198.51.100.1", "192.0.2.1")),
		v2(0x21, 0x21, block("2001:db8::1", "2001:db8::2", 0x04, 0x00, 0x01, 0xff)),
		v2(0x20, 0x00, nil),
		"GET / HTTP/1.1\r\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		br := bufio.NewReaderSize(r, v1Max)
		client, found, err := readHeader(br)
		consumed := len(data) - br.Buffered() - r.Len()
		a := client.Addr()
		switch {
		case consumed > 16+v2Max:
			t.Fatalf("consumed %d bytes", consumed)
		case err == nil && !found && consumed != 0:
			t.Fatalf("consumed %d bytes with no header", consumed)
		case client.IsValid() && (!found || a.Is4In6() || a.Zone() != ""):
			t.Fatalf("client %v, found %v", client, found)
		}
	})
}

func parseHeader(s string) (client netip.AddrPort, found bool, rest string, err error) {
	br := bufio.NewReaderSize(strings.NewReader(s), v1Max)
	client, found, err = readHeader(br)
	b, _ := io.ReadAll(br)
	return client, found, string(b), err
}

// v2 is a PROXY v2 header: version and command, family, then the block
func v2(cmd, fam byte, block []byte) string {
	h := append(slices.Clone(sigV2), cmd, fam, byte(len(block)>>8), byte(len(block)))
	return string(append(h, block...))
}

// block is a v2 address block from src:40000 to dst:443, then tlv
func block(src, dst string, tlv ...byte) []byte {
	b := append(netip.MustParseAddr(src).AsSlice(), netip.MustParseAddr(dst).AsSlice()...)
	return append(append(b, 0x9c, 0x40, 0x01, 0xbb), tlv...)
}

// listening runs p's listener over a fake one; dial connects a peer from
// addr:40000 and returns its end
func listening(t *testing.T, p *Policy) (net.Listener, func(addr string) net.Conn) {
	inner := &fakeListener{conns: make(chan net.Conn, 4)}
	ln := p.Listener(inner)
	t.Cleanup(func() { ln.Close() })
	return ln, func(addr string) net.Conn {
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close() })
		inner.conns <- remoteConn{server, net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addr), 40000))}
		return client
	}
}

func accept(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	got := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); got <- c }()
	select {
	case c := <-got:
		if c == nil {
			t.Fatal("Accept failed")
		}
		t.Cleanup(func() { c.Close() })
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("Accept returned nothing")
	}
	return nil
}

// closed waits for the listener to close peer's connection
func closed(t *testing.T, peer net.Conn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the peer reads %v, want EOF", err)
	}
}

type fakeListener struct {
	net.Listener
	conns chan net.Conn
	once  sync.Once
}

func (f *fakeListener) Accept() (net.Conn, error) {
	if c, ok := <-f.conns; ok {
		return c, nil
	}
	return nil, net.ErrClosed
}

func (f *fakeListener) Close() error { f.once.Do(func() { close(f.conns) }); return nil }

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }
