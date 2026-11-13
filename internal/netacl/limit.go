package netacl

import (
	"maps"
	"net/netip"
	"sync"
	"time"

	"github.com/lixenwraith/logwisp/internal/tokenbucket"
)

const (
	maxClients = 65536       // per table; past it new clients are refused
	netShare   = 16          // a /48 holds at most 1/netShare of a table
	slotIdle   = time.Minute // without a rate: Release drops a client, the sweep only expired holds
)

// nat64 is the well-known NAT64 prefix, whose addresses carry IPv4 clients
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Client is what per-client limits count: the address, or for IPv6 its /64,
// which one host usually holds whole. Link-local too, per zone: a peer picks
// any fe80::/64 address, so per address it would escape its budget. A /48,
// 65,536 /64s that tunnel brokers hand out free, holds a share of a table.
type Client struct {
	key string
	net netip.Prefix // a global IPv6 client's /48; invalid for the rest
}

func (c Client) String() string { return c.key }

// Key is the Client addr counts as; a NAT64 address is the IPv4 one it carries
func Key(addr netip.Addr) Client {
	addr = addr.Unmap()
	if addr.Is6() && nat64.Contains(addr.WithZone("")) {
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte(b[12:]))
	}
	if !addr.Is6() {
		return Client{key: addr.String()}
	}
	key := netip.PrefixFrom(addr, 64).Masked().String()
	if !addr.IsLinkLocalUnicast() {
		return Client{key: key, net: netip.PrefixFrom(addr, 48).Masked()}
	}
	// Only a link-local peer's zone names a link here, an interface name under
	// IFNAMSIZ (16) bytes; another comes in a forwarded hop's text, sized at will
	if zone := addr.Zone(); zone != "" && len(zone) < 16 {
		key += "%" + zone
	}
	return Client{key: key}
}

// Table limits each client key: an attempt spends a token from its bucket, if
// the table has a rate, and takes a slot, if it caps slots; a slot is
// released, or held by an id until done or expired. A full table refuses new
// keys, failing closed, and a sweep drops the idle ones. A /48 holds at most
// 1/netShare of the keys, and of the pool its slots stand for.
type Table struct {
	burst, rate float64
	slots       int
	netSlots    int           // slots a /48 may hold; 0: no cap
	idle        time.Duration // a bucket's refill: a client idle that long loses nothing when dropped

	mu        sync.Mutex
	clients   map[string]*client
	nets      map[netip.Prefix]*share // the /48s clients belong to
	peak      int                     // most clients since the maps were made
	lastSweep time.Time
}

type client struct {
	bucket *tokenbucket.TokenBucket // nil without a rate
	held   map[string]time.Time     // slots held by id, until their expiry; nil until a Hold, which only SCRAM makes
	taken  int                      // slots taken and not yet held or released
	seen   time.Time
	net    *share // its /48's, nil for none
}

// share is what one /48 holds of a table: its clients and their slots
type share struct {
	prefix         netip.Prefix
	clients, slots int
}

// NewTable allows each client burst attempts refilled at rate per second (0:
// no rate) and slots at once (0: no cap); pool is what those slots stand for
// in all, such as a server's handshakes (0: none)
func NewTable(burst, rate float64, slots, pool int) *Table {
	t := &Table{burst: burst, rate: rate, slots: slots, netSlots: pool / netShare, idle: slotIdle,
		clients: make(map[string]*client), nets: make(map[netip.Prefix]*share)}
	if rate > 0 {
		// Capped at 1e9 s (~31 years): past a Duration's range the conversion
		// is the platform's, and amd64's negative idle sweeps every client away
		t.idle = time.Duration(min(burst/rate, 1e9) * float64(time.Second))
	}
	return t
}

// Take admits an attempt by k, false when its tokens or slots, or its /48's
// share, are spent, or the table is full
func (t *Table) Take(k Client) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastSweep) > t.idle/6 {
		t.sweep(now)
	}
	c := t.clients[k.key]
	if c == nil {
		if c = t.add(k); c == nil {
			return false
		}
		if t.rate > 0 {
			c.bucket = tokenbucket.New(t.burst, t.rate)
		}
	}
	c.seen = now
	t.expire(c, now)
	// Taken under this lock: concurrent attempts cannot all pass the check
	if t.slots > 0 && (len(c.held)+c.taken >= t.slots || c.net != nil && t.netSlots > 0 && c.net.slots >= t.netSlots) ||
		c.bucket != nil && !c.bucket.Allow() {
		return false
	}
	if t.slots > 0 {
		c.taken++
		t.used(c, 1)
	}
	return true
}

// add makes k's entry, nil when the table or k's /48 holds its share of keys
func (t *Table) add(k Client) *client {
	if len(t.clients) >= maxClients {
		return nil
	}
	c := &client{}
	if k.net.IsValid() {
		if c.net = t.nets[k.net]; c.net == nil {
			c.net = &share{prefix: k.net}
			t.nets[k.net] = c.net
		} else if c.net.clients >= maxClients/netShare {
			return nil
		}
		c.net.clients++
	}
	t.clients[k.key] = c
	t.peak = max(t.peak, len(t.clients))
	return c
}

// used counts n slots more, or fewer, against c's /48
func (t *Table) used(c *client, n int) {
	if c.net != nil {
		c.net.slots += n
	}
}

// drop removes an idle client, and its /48's entry with its last
func (t *Table) drop(key string, c *client) {
	delete(t.clients, key)
	if s := c.net; s != nil {
		if s.clients--; s.clients == 0 {
			delete(t.nets, s.prefix)
		}
	}
}

// Hold moves a slot Take took to id, until done or expired
func (t *Table) Hold(k Client, id string, until time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[k.key]; c != nil {
		c.taken--
		if c.held == nil {
			c.held = make(map[string]time.Time)
		}
		if _, again := c.held[id]; again {
			t.used(c, -1)
		}
		c.held[id] = until
	}
}

// Release frees a slot Take took that no id holds
func (t *Table) Release(k Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[k.key]; c != nil {
		c.taken--
		t.used(c, -1)
		if c.idle(time.Now(), t.idle) {
			t.drop(k.key, c)
		}
	}
}

// Done frees the slot id holds, reporting whether k held it
func (t *Table) Done(k Client, id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.clients[k.key]
	if c == nil {
		return false
	}
	if _, ok := c.held[id]; !ok {
		return false
	}
	delete(c.held, id)
	t.used(c, -1)
	return true
}

// Refund returns the token of an attempt that turned out not to count
func (t *Table) Refund(k Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[k.key]; c != nil && c.bucket != nil {
		c.bucket.Refund(1)
	}
}

func (t *Table) expire(c *client, now time.Time) {
	for id, expiry := range c.held {
		if now.After(expiry) {
			delete(c.held, id)
			t.used(c, -1)
		}
	}
}

// idle reports a client holding nothing whose bucket, if any, is full again
func (c *client) idle(now time.Time, after time.Duration) bool {
	return c.taken == 0 && len(c.held) == 0 && (c.bucket == nil || now.Sub(c.seen) > after)
}

func (t *Table) sweep(now time.Time) {
	t.lastSweep = now
	for key, c := range t.clients {
		t.expire(c, now) // an abandoned hold has no Done
		if c.idle(now, t.idle) {
			t.drop(key, c)
		}
	}
	// A map keeps the room of its peak: once a flood has gone, a copy frees it
	// (maps.Clone would keep it)
	if len(t.clients) < t.peak/4 {
		clients := make(map[string]*client, len(t.clients))
		maps.Copy(clients, t.clients)
		nets := make(map[netip.Prefix]*share, len(t.nets))
		maps.Copy(nets, t.nets)
		t.clients, t.nets, t.peak = clients, nets, len(clients)
	}
}
