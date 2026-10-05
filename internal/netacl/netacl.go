// Package netacl is the address seam of the network listeners, beside tlsx
// and authz: a Policy reads the PROXY header of the proxies it trusts, then
// refuses a peer by its client's address, before TLS or a byte of the
// protocol is read. New returns nil when nothing is set, and every method
// tolerates a nil receiver.
package netacl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/tlsx"

	"github.com/lixenwraith/log"
)

const (
	// warnEvery spaces the WARNs reporting refused peers; acl_denied counts all
	warnEvery = time.Minute
	v1Max     = 107  // the longest PROXY v1 line, CRLF included
	v2Max     = 2048 // the longest PROXY v2 address block, TLVs included
)

var (
	sigV1 = []byte("PROXY ")
	sigV2 = []byte("\r\n\r\n\x00\r\nQUIT\n")
	// local is where a proxy_from entry lies without a startup warning
	local = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::1/128"),
	}
	errScreened = errors.New("PROXY header from a peer outside proxy_from")
	// v2Families holds the family bytes v2 defines, each with the address
	// bytes taken under PROXY: TCP over IPv4 and IPv6 name the client, the
	// rest keep the socket address
	v2Families = map[byte]int{0x00: 0, 0x11: 12, 0x12: 0, 0x21: 36, 0x22: 0, 0x31: 0, 0x32: 0}
)

// Policy is the compiled form of config.ACLOptions for one listener
type Policy struct {
	allow, deny, proxyFrom []netip.Prefix
	mode                   string        // proxy_protocol, when proxy_from is set
	headerWait             time.Duration // for a proxy's header: tlsx.HandshakeTimeout
	logger                 *log.Logger
	component, id          string

	denied, headers atomic.Uint64
	epoch           time.Time    // a monotonic base: a stepped clock neither mutes nor floods the WARN
	nextWarn        atomic.Int64 // nanoseconds since epoch
}

// New compiles the rules of a listener on host and warns of what they leave
// open. Entries are of the family core.Network gives host, as one the sockets
// never carry is a mistake; behind proxy_from, allow and deny take both, as
// the proxy names clients of either.
func New(o *config.ACLOptions, host string, l *log.Logger, component, id string) (*Policy, error) {
	if o == nil {
		return nil, nil
	}
	proxied := o.ProxyProtocol == "optional" || o.ProxyProtocol == "required"
	switch {
	case !proxied && o.ProxyProtocol != "" && o.ProxyProtocol != "off":
		return nil, fmt.Errorf("acl: proxy_protocol %q is none of off, optional and required", o.ProxyProtocol)
	case proxied && len(o.ProxyFrom) == 0:
		return nil, fmt.Errorf("acl: proxy_protocol %s needs proxy_from, the proxies that may send the header", o.ProxyProtocol)
	case !proxied && len(o.ProxyFrom) > 0:
		return nil, errors.New("acl: proxy_from needs proxy_protocol optional or required")
	case len(o.Allow)+len(o.Deny)+len(o.ProxyFrom) == 0:
		return nil, nil
	}
	network, err := core.Network(host)
	if err != nil {
		return nil, err
	}
	var widened []string // entry, network pairs
	compile := func(key, network string, entries []string) ([]netip.Prefix, error) {
		var rules []netip.Prefix
		for _, e := range entries {
			prefix, err := parse(e, network)
			if err != nil {
				return nil, fmt.Errorf("acl: %s entry %q: %w", key, e, err)
			}
			if m := prefix.Masked(); m != prefix {
				widened = append(widened, e, m.String())
			}
			rules = append(rules, prefix.Masked())
		}
		return rules, nil
	}
	p := &Policy{mode: o.ProxyProtocol, headerWait: tlsx.HandshakeTimeout, logger: l, component: component, id: id, epoch: time.Now()}
	if p.proxyFrom, err = compile("proxy_from", network, o.ProxyFrom); err != nil {
		return nil, err
	}
	if proxied {
		network = "tcp"
	}
	if p.allow, err = compile("allow", network, o.Allow); err != nil {
		return nil, err
	}
	if p.deny, err = compile("deny", network, o.Deny); err != nil {
		return nil, err
	}
	p.logStartup(host, widened)
	return p, nil
}

func parse(entry, network string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		addr, aerr := netip.ParseAddr(entry)
		if aerr != nil || addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("neither an address nor a CIDR (and no zone)")
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	switch a := prefix.Addr(); {
	case a.Is4In6():
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped; write it as IPv4")
	case network == "tcp4" && !a.Is4(), network == "tcp6" && a.Is4():
		return netip.Prefix{}, fmt.Errorf("not of the listener's family (%s)", network)
	}
	return prefix, nil
}

func (p *Policy) logStartup(host string, widened []string) {
	for i := 0; i < len(widened); i += 2 {
		p.logger.Warn("msg", "acl entry has host bits set and matches its whole network",
			"component", p.component,
			"instance_id", p.id,
			"entry", widened[i],
			"network", widened[i+1])
	}
	for _, q := range p.allow {
		if q.Bits() == 0 {
			p.logger.Warn("msg", "acl.allow admits every address of its family",
				"component", p.component,
				"instance_id", p.id,
				"entry", q.String(),
				"hint", "list only the networks that may connect")
		}
	}
	if p.mode == "optional" {
		p.logger.Warn("msg", "acl.proxy_protocol optional: a client a proxy_from peer forwards without a header passes as the proxy",
			"component", p.component,
			"instance_id", p.id,
			"hint", "set required once every route from proxy_from sends the header")
	}
	for _, q := range p.proxyFrom {
		if !slices.ContainsFunc(local, func(l netip.Prefix) bool { return l.Bits() <= q.Bits() && l.Contains(q.Addr()) }) {
			p.logger.Warn("msg", "acl.proxy_from reaches public addresses, any of which may name any client",
				"component", p.component,
				"instance_id", p.id,
				"entry", q.String(),
				"hint", "list only the proxies' own addresses")
		}
	}
	if addr, err := netip.ParseAddr(host); len(p.allow) == 0 && len(p.deny) > 0 && (host == "" || err == nil && addr.IsUnspecified()) {
		p.logger.Warn("msg", "Listener on every address admits all that acl.deny does not list",
			"component", p.component,
			"instance_id", p.id,
			"hint", "set acl.allow to the networks that may connect")
	}
}

// in reports whether addr lies in a rule, matched unmapped and without its
// zone: a zoned address is in no prefix
func in(rules []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	return slices.ContainsFunc(rules, func(q netip.Prefix) bool { return q.Contains(addr) })
}

// admits applies the rules: deny wins, then a set allow list admits only its
// entries. A peer whose address is unknown is refused.
func (p *Policy) admits(addr netip.Addr) bool {
	return addr.IsValid() && !in(p.deny, addr) && (len(p.allow) == 0 || in(p.allow, addr))
}

// proxies reports a peer in proxy_from. A zoned one never is: a link-local
// address is any link's to claim.
func (p *Policy) proxies(addr netip.Addr) bool {
	addr = addr.Unmap()
	return slices.ContainsFunc(p.proxyFrom, func(q netip.Prefix) bool { return q.Contains(addr) })
}

func addrOf(c net.Conn) netip.Addr {
	if t, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return t.AddrPort().Addr()
	}
	return netip.Addr{}
}

// Listener returns ln deciding each peer before Accept returns it. Headers are
// read off the accept loop, so a slow proxy holds only its own connection; the
// loop starts at once, so call this in Start. A nil Policy returns ln.
func (p *Policy) Listener(ln net.Listener) net.Listener {
	if p == nil {
		return ln
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{Listener: ln, p: p, accepted: make(chan accepted), ctx: ctx, cancel: cancel}
	go l.run()
	return l
}

type listener struct {
	net.Listener
	p        *Policy
	accepted chan accepted
	ctx      context.Context // done at Close
	cancel   context.CancelFunc
}

type accepted struct {
	conn net.Conn
	err  error
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case a := <-l.accepted:
		return a.conn, a.err
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Close also closes the connections still sending a header
func (l *listener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

func (l *listener) run() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			if !l.deliver(nil, err) || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		switch {
		case l.p.proxies(addrOf(c)):
			go l.proxied(c)
		case len(l.p.proxyFrom) > 0:
			l.admit(&conn{Conn: c, r: bufio.NewReaderSize(c, v1Max), screen: l.p})
		default:
			l.admit(c)
		}
	}
}

// proxied reads the header of a peer in proxy_from, then admits the
// connection by the client it names
func (l *listener) proxied(c net.Conn) {
	stop := context.AfterFunc(l.ctx, func() { c.Close() })
	c.SetReadDeadline(time.Now().Add(l.p.headerWait))
	br := bufio.NewReaderSize(c, v1Max)
	client, found, err := readHeader(br)
	c.SetReadDeadline(time.Time{})
	if !stop() {
		return // closed with the listener
	}
	pc := &conn{Conn: c, r: br}
	switch {
	case err != nil:
		l.p.refuse(c, "PROXY header: "+err.Error())
		return
	case !found && l.p.mode == "required":
		l.p.refuse(c, "no PROXY header")
		return
	case found:
		l.p.headers.Add(1)
		if client.IsValid() {
			pc.client = net.TCPAddrFromAddrPort(client)
		}
	}
	l.admit(pc)
}

// admit hands c to Accept if the rules admit the address it ends with
func (l *listener) admit(c net.Conn) {
	if !l.p.admits(addrOf(c)) {
		l.p.refuse(c, "address rules")
		return
	}
	l.deliver(c, nil)
}

func (l *listener) deliver(c net.Conn, err error) bool {
	select {
	case l.accepted <- accepted{c, err}:
		return true
	case <-l.ctx.Done():
		if c != nil {
			c.Close()
		}
		return false
	}
}

// refuse closes c, counts it and WARNs at most once per warnEvery
func (p *Policy) refuse(c net.Conn, reason string) {
	n := p.denied.Add(1) // first: a peer that sees the close sees the count
	c.Close()
	now, next := int64(time.Since(p.epoch)), p.nextWarn.Load()
	if now < next || !p.nextWarn.CompareAndSwap(next, now+int64(warnEvery)) {
		return
	}
	fields := []any{"msg", "Connection refused by acl; more within a minute are only counted",
		"component", p.component,
		"instance_id", p.id,
		"remote_addr", fmt.Sprint(c.RemoteAddr()),
		"reason", reason,
		"acl_denied", n}
	if peer := PeerAddr(c); peer != "" {
		fields = append(fields, "peer_addr", peer)
	}
	p.logger.Warn(fields...)
}

// conn is read through the buffer its first bytes went to: past a PROXY
// header, whose client it reports, or under a screen refusing one from a peer
// outside proxy_from at the first Read
type conn struct {
	net.Conn
	r      *bufio.Reader
	client net.Addr // nil keeps the socket's
	screen *Policy
	once   sync.Once
	err    error
}

func (c *conn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		if c.screen == nil {
			return
		}
		if v, _ := signature(c.r); v != 0 {
			c.err = errScreened
			c.screen.refuse(c, errScreened.Error())
		}
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(b)
}

func (c *conn) RemoteAddr() net.Addr {
	if c.client != nil {
		return c.client
	}
	return c.Conn.RemoteAddr()
}

// PeerAddr is the proxy whose PROXY header named c's client, "" when c came
// direct; c may be the *tls.Conn over the listener's connection
func PeerAddr(c net.Conn) string {
	if t, ok := c.(interface{ NetConn() net.Conn }); ok {
		c = t.NetConn()
	}
	if pc, ok := c.(*conn); ok && pc.client != nil {
		return pc.Conn.RemoteAddr().String()
	}
	return ""
}

type peerKey struct{}

// ConnContext, as an http.Server's, carries PeerAddr to the requests of a
// connection for ContextPeerAddr
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if peer := PeerAddr(c); peer != "" {
		return context.WithValue(ctx, peerKey{}, peer)
	}
	return ctx
}

func ContextPeerAddr(ctx context.Context) string {
	peer, _ := ctx.Value(peerKey{}).(string)
	return peer
}

// signature reads as far as tells whether a PROXY header starts the stream:
// its version, or 0 when other bytes or none come first
func signature(br *bufio.Reader) (int, error) {
	for n := 1; ; n++ {
		b, err := br.Peek(n)
		switch {
		case len(b) == 0 || !bytes.HasPrefix(sigV1, b) && !bytes.HasPrefix(sigV2, b):
			return 0, nil
		case bytes.Equal(b, sigV1):
			return 1, nil
		case bytes.Equal(b, sigV2):
			return 2, nil
		case err != nil:
			return 0, fmt.Errorf("signature cut short: %w", err)
		}
	}
}

// readHeader reads the PROXY header starting br, if one does: found is false,
// with nothing consumed, when none does. The client is invalid for LOCAL,
// UNKNOWN and the families v2 leaves to the socket address.
func readHeader(br *bufio.Reader) (client netip.AddrPort, found bool, err error) {
	v, err := signature(br)
	switch v {
	case 1:
		client, err = readV1(br)
	case 2:
		client, err = readV2(br)
	}
	return client, v != 0 && err == nil, err
}

// readV1 reads "PROXY TCP4|TCP6 src dst sport dport\r\n" or "PROXY UNKNOWN...\r\n"
func readV1(br *bufio.Reader) (netip.AddrPort, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return netip.AddrPort{}, fmt.Errorf("v1 line over %d bytes", v1Max)
	} else if err != nil {
		return netip.AddrPort{}, fmt.Errorf("v1 line cut short: %w", err)
	}
	s, crlf := strings.CutSuffix(string(line), "\r\n")
	f := strings.Split(s, " ")
	switch {
	case !crlf:
		return netip.AddrPort{}, errors.New("v1 line not ended by CRLF")
	case f[1] == "UNKNOWN":
		return netip.AddrPort{}, nil
	case len(f) != 6 || f[1] != "TCP4" && f[1] != "TCP6":
		return netip.AddrPort{}, fmt.Errorf("malformed v1 line %q", s)
	}
	src, err1 := netip.ParseAddr(f[2])
	dst, err2 := netip.ParseAddr(f[3])
	port, err3 := strconv.ParseUint(f[4], 10, 16)
	_, err4 := strconv.ParseUint(f[5], 10, 16)
	four := f[1] == "TCP4"
	if errors.Join(err1, err2, err3, err4) != nil || src.Zone()+dst.Zone() != "" || src.Is4() != four || dst.Is4() != four {
		return netip.AddrPort{}, fmt.Errorf("malformed v1 line %q", s)
	}
	return netip.AddrPortFrom(src.Unmap(), uint16(port)), nil
}

// readV2 reads the 16-byte prefix and the block after it, taking the address
// of TCP over IPv4 or IPv6 and skipping the rest, TLVs included
func readV2(br *bufio.Reader) (netip.AddrPort, error) {
	h, err := br.Peek(16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("v2 prefix cut short: %w", err)
	}
	cmd, fam, n := h[12], h[13], int(binary.BigEndian.Uint16(h[14:]))
	need, known := v2Families[fam]
	if cmd&0xf != 1 {
		need, known = 0, true // LOCAL ignores the block
	}
	switch {
	case cmd>>4 != 2 || cmd&0xf > 1:
		return netip.AddrPort{}, fmt.Errorf("v2 version and command %#x", cmd)
	case !known:
		return netip.AddrPort{}, fmt.Errorf("v2 family %#x", fam)
	case n > v2Max:
		return netip.AddrPort{}, fmt.Errorf("v2 block of %d bytes over %d", n, v2Max)
	case n < need:
		return netip.AddrPort{}, fmt.Errorf("v2 block of %d bytes short for family %#x", n, fam)
	}
	br.Discard(16)
	var client netip.AddrPort
	if need > 0 {
		b, err := br.Peek(need)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("v2 block cut short: %w", err)
		}
		addr, _ := netip.AddrFromSlice(b[:(need-4)/2]) // source, destination, two ports
		client = netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(b[need-4:]))
	}
	if _, err := br.Discard(n); err != nil {
		return netip.AddrPort{}, fmt.Errorf("v2 block cut short: %w", err)
	}
	return client, nil
}

// Describe renders the policy for log lines, stats and the status endpoint
func (p *Policy) Describe() string {
	if p == nil {
		return "none"
	}
	allow := "any"
	if len(p.allow) > 0 {
		allow = fmt.Sprint(len(p.allow))
	}
	s := fmt.Sprintf("allow=%s deny=%d", allow, len(p.deny))
	if len(p.proxyFrom) > 0 {
		s += fmt.Sprintf(" proxy_protocol=%s proxy_from=%d", p.mode, len(p.proxyFrom))
	}
	return s
}

func (p *Policy) Denied() uint64 {
	if p == nil {
		return 0
	}
	return p.denied.Load()
}

// Stats reports the policy for a plugin's stats details, merged in with
// maps.Copy beside authz's. A nil Policy reports nothing.
func (p *Policy) Stats() map[string]any {
	if p == nil {
		return nil
	}
	return map[string]any{"acl": p.Describe(), "acl_denied": p.denied.Load(), "acl_proxy_headers": p.headers.Load()}
}
