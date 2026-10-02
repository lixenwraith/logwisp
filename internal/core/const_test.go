package core

import (
	"net"
	"testing"

	"logwisp/internal/testutil"
)

// The host literal picks the family, strictly: an IPv4 literal or the empty
// host is IPv4 only, an IPv6 literal (the wildcard :: too) IPv6 only, and a
// hostname resolves. Brackets and ports belong to addresses, not hosts.
func TestNetworkFollowsTheHostLiteral(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"127.0.0.1", "tcp4"}, {"0.0.0.0", "tcp4"}, {"", "tcp4"},
		{"::1", "tcp6"}, {"::", "tcp6"}, {"fe80::1%eth0", "tcp6"},
		{"relay.example", "tcp"}, {"localhost", "tcp"},
		{"[::1]", ""}, {"::1]", ""}, {"10.0.0.1:80", ""},
	} {
		got, err := Network(tc.host)
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Errorf("Network(%q) = %q, %v; want %q", tc.host, got, err, tc.want)
		}
	}

	testutil.RequireIPv6(t)
	network, _ := Network("::")
	ln, err := net.Listen(network, "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port)); err == nil {
		c.Close()
		t.Error(":: accepted an IPv4 connection")
	}
	c, err := net.Dial("tcp6", net.JoinHostPort("::1", port))
	if err != nil {
		t.Fatalf(":: refused [::1]: %v", err)
	}
	c.Close()
}
