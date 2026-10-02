package authz

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lixenwraith/auth"
)

// SessionCookie carries a browser's token in proxy mode
const SessionCookie = "logwisp_session"

const maxRevoked = 65536 // logged-out tokens remembered until they expire

// proxyMode is an http sink behind TLS-terminating reverse proxies: only they
// may connect, X-Forwarded-For names the client, logins are unbound (logwisp
// holds no certificate the browser sees) and sessions may be cookies.
type proxyMode struct {
	trusted   []netip.Prefix
	plaintext bool // no tls on the hop from the proxies
	mu        sync.Mutex
	revoked   map[[32]byte]time.Time
}

func parseProxies(entries []string) (*proxyMode, error) {
	m := &proxyMode{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		prefix, err := netip.ParsePrefix(e)
		if err != nil {
			addr, aerr := netip.ParseAddr(e)
			if aerr != nil {
				return nil, fmt.Errorf("auth: trusted_proxies entry %q is neither an address nor a CIDR", e)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		m.trusted = append(m.trusted, prefix.Masked())
	}
	return m, nil
}

func (m *proxyMode) trusts(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return slices.ContainsFunc(m.trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// exposedHop reports a plaintext hop from a proxy that may be on another host
func (m *proxyMode) exposedHop() bool {
	return m.plaintext && slices.ContainsFunc(m.trusted, func(p netip.Prefix) bool { return !p.Addr().IsLoopback() })
}

// client is the rightmost X-Forwarded-For hop that is not a trusted proxy:
// hops to its left come from the client and prove nothing.
func (m *proxyMode) client(peer string, h http.Header) (string, error) {
	if !m.trusts(peer) {
		return "", fmt.Errorf("%s is not a trusted proxy", peer)
	}
	protos := headerList(h, "X-Forwarded-Proto")
	if len(protos) == 0 || slices.ContainsFunc(protos, func(v string) bool { return !strings.EqualFold(v, "https") }) {
		return "", fmt.Errorf("proxy forwarded X-Forwarded-Proto %q; sessions need https", strings.Join(protos, ","))
	}
	hops := headerList(h, "X-Forwarded-For")
	for i := len(hops) - 1; i >= 0; i-- {
		if m.trusts(hops[i]) {
			continue
		}
		if addr, err := netip.ParseAddr(hops[i]); err == nil {
			return addr.Unmap().String(), nil
		}
		if ap, err := netip.ParseAddrPort(hops[i]); err == nil {
			return ap.Addr().Unmap().String(), nil
		}
		return "", fmt.Errorf("malformed X-Forwarded-For hop %q", hops[i])
	}
	return "", errors.New("proxy sent no client address in X-Forwarded-For")
}

func headerList(h http.Header, key string) []string {
	var out []string
	for _, v := range h.Values(key) {
		for e := range strings.SplitSeq(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

func (m *proxyMode) revoke(token string, until time.Time) bool {
	key := sha256.Sum256([]byte(token))
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[[32]byte]time.Time)
	}
	if len(m.revoked) >= maxRevoked {
		for k, expiry := range m.revoked {
			if now.After(expiry) {
				delete(m.revoked, k)
			}
		}
		if len(m.revoked) >= maxRevoked {
			return false
		}
	}
	m.revoked[key] = until
	return true
}

func (m *proxyMode) isRevoked(token string) bool {
	key := sha256.Sum256([]byte(token))
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[key]
	return ok
}

// BehindProxy reports proxy mode (auth.trusted_proxies on an http sink)
func (p *Policy) BehindProxy() bool {
	return p != nil && p.listener != nil && p.listener.proxy != nil
}

// ClientAddr is the address throttling, sessions and logs name: the socket
// peer, or in proxy mode the forwarded client. A proxy-mode request from an
// untrusted peer, or one the proxy did not receive over https, is refused.
func (p *Policy) ClientAddr(r *http.Request) (string, error) {
	peer := remoteIP(r.RemoteAddr)
	if !p.BehindProxy() {
		return peer, nil
	}
	addr, err := p.listener.proxy.client(peer, r.Header)
	if err != nil {
		p.rejected.Add(1)
		return "", fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return addr, nil
}

// presentedToken is the bearer token or, in proxy mode, the session cookie
func (p *Policy) presentedToken(r *http.Request) (string, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		token, err := auth.ParseBearerToken(h)
		if err != nil {
			return "", errors.New("malformed bearer token")
		}
		return token, nil
	}
	if p.BehindProxy() {
		if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
			return c.Value, nil
		}
	}
	return "", errors.New("no bearer token")
}

// sessionCookie sets no Path: it defaults to the directory of /auth, which is
// the mount point behind any proxy prefix, so stream and status receive it.
func sessionCookie(token string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: SessionCookie, Value: token, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
}

// logout clears the cookie and revokes a valid presented token until it
// expires. It answers on /auth itself: a clearing cookie set from another path
// would default to another Path and miss the login cookie.
func (p *Policy) logout(w http.ResponseWriter, r *http.Request) error {
	l := p.listener
	http.SetCookie(w, sessionCookie("", -1))
	token, err := p.presentedToken(r)
	if err == nil {
		_, _, err = l.tokens.ValidateToken(token)
	}
	if err == nil && !l.proxy.revoke(token, time.Now().Add(l.lifetime)) {
		l.busy.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, authStep{Error: "busy"})
		return errors.New("auth: logout revocation list is full; the token stays valid until it expires")
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
