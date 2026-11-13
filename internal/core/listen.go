package core

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// lookupNetIP resolves listener hostnames; tests replace it
var lookupNetIP = net.DefaultResolver.LookupNetIP

// held is a bound socket lw keeps open while no listener uses it, by network
// and address, so that a reload's next service takes it over
var (
	heldMu sync.Mutex
	held   = map[string]*heldSocket{}
)

type heldSocket struct {
	file  *os.File
	inUse bool
}

// Listen is lc.Listen, but a hostname first resolves to one address, IPv4 when
// it has one (as Go picks), listened on in that address's family alone: Go
// would bind a name for a wildcard address in both families. A socket stays
// bound once its listener closes, until ReleaseIdle: the next Listen on its
// address takes it, so across a reload clients wait in its backlog instead of
// being refused, and no other process can take the port meanwhile.
func Listen(ctx context.Context, lc *net.ListenConfig, network, addr string) (net.Listener, error) {
	network, addr, err := pinFamily(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if _, port, _ := net.SplitHostPort(addr); port == "0" {
		return lc.Listen(ctx, network, addr)
	}
	key := network + " " + addr
	heldMu.Lock()
	defer heldMu.Unlock()
	h := held[key]
	switch {
	case h == nil:
		ln, err := lc.Listen(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		file, err := ln.(*net.TCPListener).File()
		ln.Close() // the socket lives on in file
		if err != nil {
			return nil, err
		}
		h = &heldSocket{file: file}
		held[key] = h
	case h.inUse:
		return nil, fmt.Errorf("listen %s %s: address already in use by another of lw's listeners", network, addr)
	}
	ln, err := net.FileListener(h.file)
	if err != nil {
		return nil, err
	}
	h.inUse = true
	return &heldListener{TCPListener: ln.(*net.TCPListener), socket: h, idle: lc.KeepAlive, alive: lc.KeepAliveConfig}, nil
}

// ReleaseIdle closes the held sockets no listener uses: after a reload those
// of the addresses it dropped, at exit all
func ReleaseIdle() {
	heldMu.Lock()
	defer heldMu.Unlock()
	for key, h := range held {
		if !h.inUse {
			h.file.Close()
			delete(held, key)
		}
	}
}

// heldListener is a listener on a held socket. Made from a descriptor, it
// accepts with Go's keep-alive defaults, so Accept sets the ListenConfig's.
type heldListener struct {
	*net.TCPListener
	socket *heldSocket
	idle   time.Duration
	alive  net.KeepAliveConfig
	once   sync.Once
}

func (l *heldListener) Accept() (net.Conn, error) {
	c, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if l.idle == 0 && l.alive == (net.KeepAliveConfig{}) {
		return c, nil
	}
	alive := l.alive
	if !alive.Enable && l.idle >= 0 { // as Go's own accept reads a ListenConfig
		alive = net.KeepAliveConfig{Enable: true, Idle: l.idle}
	}
	if alive.Enable {
		err = c.SetKeepAliveConfig(alive)
	} else {
		err = c.SetKeepAlive(false)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Close closes this listener; the socket stays held for the next
func (l *heldListener) Close() error {
	err := l.TCPListener.Close()
	l.once.Do(func() {
		heldMu.Lock()
		l.socket.inUse = false
		heldMu.Unlock()
	})
	return err
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
