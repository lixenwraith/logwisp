package core

import (
	"context"
	"net/netip"
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
