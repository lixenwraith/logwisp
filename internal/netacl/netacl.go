// Package netacl is the address seam of the network listeners, beside tlsx
// and authz: a Policy refuses a peer by its address as the socket is
// accepted, before TLS or a byte of the protocol is read. New returns nil
// when no rule is set, and every method tolerates a nil receiver.
package netacl

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/log"
)

// warnEvery spaces the WARNs reporting refused peers; acl_denied counts all
const warnEvery = time.Minute

// Policy is the compiled form of config.ACLOptions for one listener
type Policy struct {
	allow, deny   []netip.Prefix
	logger        *log.Logger
	component, id string

	denied   atomic.Uint64
	epoch    time.Time    // a monotonic base: a stepped clock neither mutes nor floods the WARN
	nextWarn atomic.Int64 // nanoseconds since epoch
}

// New compiles the rules of a listener on host and warns of what they leave
// open. Each entry must be of the family core.Network gives host: one the
// listener's sockets can never carry is a mistake, not a rule.
func New(o *config.ACLOptions, host string, l *log.Logger, component, id string) (*Policy, error) {
	if o == nil || len(o.Allow)+len(o.Deny) == 0 {
		return nil, nil
	}
	network, err := core.Network(host)
	if err != nil {
		return nil, err
	}
	var widened []string // entry, network pairs
	compile := func(key string, entries []string) ([]netip.Prefix, error) {
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
	p := &Policy{logger: l, component: component, id: id, epoch: time.Now()}
	if p.allow, err = compile("allow", o.Allow); err != nil {
		return nil, err
	}
	if p.deny, err = compile("deny", o.Deny); err != nil {
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
	if addr, err := netip.ParseAddr(host); len(p.allow) == 0 && (host == "" || err == nil && addr.IsUnspecified()) {
		p.logger.Warn("msg", "Listener on every address admits all that acl.deny does not list",
			"component", p.component,
			"instance_id", p.id,
			"hint", "set acl.allow to the networks that may connect")
	}
}

// admits applies the rules: deny wins, then a set allow list admits only its
// entries. A peer whose address is unknown is refused.
func (p *Policy) admits(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("") // a zoned address is in no prefix
	in := func(q netip.Prefix) bool { return q.Contains(addr) }
	return addr.IsValid() && !slices.ContainsFunc(p.deny, in) &&
		(len(p.allow) == 0 || slices.ContainsFunc(p.allow, in))
}

// Listener returns ln refusing the peers the rules exclude as it accepts them,
// so the plugin never sees one. Close stays ln's: a sink's shutdown flush
// reaches it unchanged. A nil Policy returns ln.
func (p *Policy) Listener(ln net.Listener) net.Listener {
	if p == nil {
		return ln
	}
	return &listener{Listener: ln, p: p}
}

type listener struct {
	net.Listener
	p *Policy
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		var addr netip.Addr
		remote := conn.RemoteAddr()
		if t, ok := remote.(*net.TCPAddr); ok {
			addr = t.AddrPort().Addr()
		}
		if l.p.admits(addr) {
			return conn, nil
		}
		conn.Close()
		l.p.refused(fmt.Sprint(remote))
	}
}

// refused counts a refusal and WARNs at most once per warnEvery
func (p *Policy) refused(remote string) {
	n := p.denied.Add(1)
	now, next := int64(time.Since(p.epoch)), p.nextWarn.Load()
	if now < next || !p.nextWarn.CompareAndSwap(next, now+int64(warnEvery)) {
		return
	}
	p.logger.Warn("msg", "Connection refused by acl; more within a minute are only counted",
		"component", p.component,
		"instance_id", p.id,
		"remote_addr", remote,
		"acl_denied", n)
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
	return fmt.Sprintf("allow=%s deny=%d", allow, len(p.deny))
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
	return map[string]any{"acl": p.Describe(), "acl_denied": p.denied.Load()}
}
