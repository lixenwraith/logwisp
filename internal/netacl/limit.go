package netacl

import (
	"net/netip"
	"sync"
	"time"

	"github.com/lixenwraith/logwisp/internal/tokenbucket"
)

const (
	maxClients = 65536       // per table; past it new clients are refused
	slotIdle   = time.Minute // without a rate: Release drops a client, the sweep only expired holds
)

// Key is what per-client limits count: the address, or for IPv6 its /64,
// which one host usually holds whole. Link-local too, per zone: a peer picks
// any fe80::/64 address, so per address it would escape its budget.
func Key(addr netip.Addr) string {
	addr = addr.Unmap()
	if !addr.Is6() {
		return addr.String()
	}
	key := netip.PrefixFrom(addr, 64).Masked().String()
	if zone := addr.Zone(); zone != "" {
		key += "%" + zone
	}
	return key
}

// Table limits each client key: an attempt spends a token from its bucket, if
// the table has a rate, and takes a slot, if it caps slots; a slot is
// released, or held by an id until done or expired. A full table refuses new
// keys, failing closed, and a sweep drops the idle ones.
type Table struct {
	burst, rate float64
	slots       int
	idle        time.Duration // a bucket's refill: a client idle that long loses nothing when dropped

	mu        sync.Mutex
	clients   map[string]*client
	lastSweep time.Time
}

type client struct {
	bucket *tokenbucket.TokenBucket // nil without a rate
	held   map[string]time.Time     // slots held by id, until their expiry
	taken  int                      // slots taken and not yet held or released
	seen   time.Time
}

// NewTable allows each client burst attempts refilled at rate per second (0:
// no rate) and slots at once (0: no cap)
func NewTable(burst, rate float64, slots int) *Table {
	t := &Table{burst: burst, rate: rate, slots: slots, idle: slotIdle, clients: make(map[string]*client)}
	if rate > 0 {
		t.idle = time.Duration(burst / rate * float64(time.Second))
	}
	return t
}

// Take admits an attempt by key, false when its tokens or slots are spent or
// the table is full
func (t *Table) Take(key string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastSweep) > t.idle/6 {
		t.sweep(now)
	}
	c := t.clients[key]
	if c == nil {
		if len(t.clients) >= maxClients {
			return false
		}
		c = &client{held: make(map[string]time.Time)}
		if t.rate > 0 {
			c.bucket = tokenbucket.New(t.burst, t.rate)
		}
		t.clients[key] = c
	}
	c.seen = now
	c.expire(now)
	// Taken under this lock: concurrent attempts cannot all pass the check
	if t.slots > 0 && len(c.held)+c.taken >= t.slots || c.bucket != nil && !c.bucket.Allow() {
		return false
	}
	if t.slots > 0 {
		c.taken++
	}
	return true
}

// Hold moves a slot Take took to id, until done or expired
func (t *Table) Hold(key, id string, until time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[key]; c != nil {
		c.taken--
		c.held[id] = until
	}
}

// Release frees a slot Take took that no id holds
func (t *Table) Release(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[key]; c != nil {
		c.taken--
		if c.idle(time.Now(), t.idle) {
			delete(t.clients, key)
		}
	}
}

// Done frees the slot id holds
func (t *Table) Done(key, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[key]; c != nil {
		delete(c.held, id)
	}
}

// Refund returns the token of an attempt that turned out not to count
func (t *Table) Refund(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.clients[key]; c != nil && c.bucket != nil {
		c.bucket.Refund(1)
	}
}

func (c *client) expire(now time.Time) {
	for id, expiry := range c.held {
		if now.After(expiry) {
			delete(c.held, id)
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
		c.expire(now) // an abandoned hold has no Done
		if c.idle(now, t.idle) {
			delete(t.clients, key)
		}
	}
}
