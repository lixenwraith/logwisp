package core

import (
	"context"
	"fmt"
	"net"
)

// lookupNetIP resolves listener hostnames; tests replace it
var lookupNetIP = net.DefaultResolver.LookupNetIP

// Listen is lc.Listen, but a hostname first resolves to one address, IPv4 when
// it has one (as Go picks), listened on in that address's family alone: Go
// would bind a name for a wildcard address in both families.
func Listen(ctx context.Context, lc *net.ListenConfig, network, addr string) (net.Listener, error) {
	network, addr, err := pinFamily(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return lc.Listen(ctx, network, addr)
}

func pinFamily(ctx context.Context, network, addr string) (string, string, error) {
	if network != "tcp" {
		return network, addr, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	ips, err := lookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", "", err
	}
	if len(ips) == 0 {
		return "", "", fmt.Errorf("%s: no address", host)
	}
	ip := ips[0].Unmap()
	for _, a := range ips {
		if a.Unmap().Is4() {
			ip = a.Unmap()
			break
		}
	}
	if network, err = Network(ip.String()); err != nil {
		return "", "", err
	}
	return network, net.JoinHostPort(ip.String(), port), nil
}
