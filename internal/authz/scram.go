package authz

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/tlsx"
	"logwisp/internal/tokenbucket"

	"github.com/lixenwraith/auth"
	"github.com/lixenwraith/toml"
)

const (
	// ExchangeTimeout bounds a whole SCRAM exchange on either side
	ExchangeTimeout = 10 * time.Second
	// DefaultTokenLifetime is how long a bearer token from /auth stays valid
	DefaultTokenLifetime = 15 * time.Minute
	// Token lifetime bounds: exp has whole seconds, a sub-second expires_in
	// reads as unknown, and 10 s leaves room for renewal ahead of expiry
	MinTokenLifetime = 10 * time.Second
	MaxTokenLifetime = 24 * time.Hour

	maxAuthLine  = 4096 // pre-auth lines and /auth bodies come from unauthenticated peers
	streamBuffer = 64 * 1024

	limitBurst   = 10 // failed or abandoned exchanges per address before throttling
	limitRate    = 1  // per second
	limitPending = 4  // unfinished exchanges per address
	limitPeers   = 65536
	limitIdle    = time.Minute
)

// The dialer's floor on the Argon2 cost a server may ask for. A hostile server
// could otherwise request a cheaply guessable proof; tests lower it.
var minArgonTime, minArgonMemory uint32 = auth.DefaultArgonTime, auth.DefaultArgonMemory

var errPinMismatch = errors.New("server certificate differs from the one the SCRAM login was bound to")

// authStep is every SCRAM message after the hello: TCP lines and HTTP bodies.
// Binding is the client's view of the server certificate, used only to tell
// TLS interception apart from a wrong password in the listener's log.
type authStep struct {
	Error     string                   `json:"error,omitempty"`
	Challenge *auth.ServerFirstMessage `json:"challenge,omitempty"`
	Proof     *auth.ClientFinalRequest `json:"proof,omitempty"`
	Binding   string                   `json:"binding,omitempty"`
	Final     *auth.ServerFinalMessage `json:"final,omitempty"`
	Token     string                   `json:"token,omitempty"`
	ExpiresIn int64                    `json:"expires_in,omitempty"`
	Session   string                   `json:"session,omitempty"` // "cookie": proxy mode, token in a cookie
	Logout    bool                     `json:"logout,omitempty"`
}

// Credentials is a parsed credentials file: the verifiers a listener accepts,
// never passwords, and the key that keeps unknown-user challenges stable.
type Credentials struct {
	DecoyKey []byte
	Users    []*auth.Credential
}

var credentialKeys = map[string]bool{
	"username": true, "salt": true, "argon_time": true, "argon_memory": true,
	"argon_threads": true, "stored_key": true, "server_key": true,
}

// LoadCredentials reads and validates a credentials file
func LoadCredentials(path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: credentials_file: %w", err)
	}
	c, err := ParseCredentials(data)
	if err != nil {
		return nil, fmt.Errorf("auth: credentials_file %s: %w", path, err)
	}
	return c, nil
}

// ParseCredentials validates a whole file: a decoy key, at least one user,
// unique names, one shared KDF profile (mixed profiles would reveal which
// accounts exist) and well-formed verifiers.
func ParseCredentials(data []byte) (*Credentials, error) {
	root, err := toml.NewParser(data).Parse()
	if err != nil {
		return nil, err
	}
	for k := range root {
		if k != "decoy_key" && k != "users" {
			return nil, fmt.Errorf("unknown key %q", k)
		}
	}
	key, _ := root["decoy_key"].(string)
	decoy, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(decoy) < 32 {
		return nil, errors.New("decoy_key must hold at least 32 base64-encoded bytes")
	}
	var users []map[string]any
	switch v := root["users"].(type) {
	case []map[string]any:
		users = v
	case []any:
		for _, e := range v {
			if u, ok := e.(map[string]any); ok {
				users = append(users, u)
			}
		}
	}
	if len(users) == 0 {
		return nil, errors.New("no users")
	}
	c := &Credentials{DecoyKey: decoy}
	seen := make(map[string]bool, len(users))
	for i, u := range users {
		for k := range u {
			if !credentialKeys[k] {
				return nil, fmt.Errorf("users[%d]: unknown key %q", i, k)
			}
		}
		cred, err := auth.ImportCredential(u)
		if err != nil {
			return nil, fmt.Errorf("users[%d]: %w", i, err)
		}
		if seen[cred.Username] {
			return nil, fmt.Errorf("users[%d]: duplicate user %q", i, cred.Username)
		}
		seen[cred.Username] = true
		if f := c.Users; len(f) > 0 && (f[0].ArgonTime != cred.ArgonTime || f[0].ArgonMemory != cred.ArgonMemory ||
			f[0].ArgonThreads != cred.ArgonThreads || len(f[0].Salt) != len(cred.Salt)) {
			return nil, fmt.Errorf("users[%d] %q: Argon2 profile differs from %q's; all users must share one", i, cred.Username, f[0].Username)
		}
		c.Users = append(c.Users, cred)
	}
	return c, nil
}

// Marshal renders the file in its canonical form
func (c *Credentials) Marshal() ([]byte, error) {
	users := make([]map[string]any, len(c.Users))
	for i, u := range c.Users {
		users[i] = u.Export()
	}
	body, err := toml.Marshal(map[string]any{
		"decoy_key": base64.StdEncoding.EncodeToString(c.DecoyKey),
		"users":     users,
	})
	if err != nil {
		return nil, err
	}
	header := "# logwisp SCRAM verifiers, written by `lw auth add-user`. Keep it private.\n"
	return append([]byte(header), body...), nil
}

// ReadPassword reads a password file, trimming one trailing line break so a
// file from an editor and one from `lw auth add-user` agree.
func ReadPassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("auth: password_file: %w", err)
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if pw == "" || len(pw) > auth.MaxPasswordLen {
		return "", fmt.Errorf("auth: password_file %s: password must be 1-%d bytes", path, auth.MaxPasswordLen)
	}
	return pw, nil
}

// --- Listener ---

type scramListener struct {
	creds    *Credentials
	cb       []byte    // SHA-256 of this listener's certificate, the channel binding; nil behind proxies
	tokens   *auth.JWT // HTTP listeners; a per-instance key, so a reload revokes every token
	lifetime time.Duration
	proxy    *proxyMode
	server   atomic.Pointer[auth.ScramServer]
	limit    limiter

	throttled       atomic.Uint64
	busy            atomic.Uint64
	bindingMismatch atomic.Uint64
}

func (p *Policy) compileSCRAM(o *config.AuthOptions, tlsCfg *tls.Config) error {
	if len(o.Allow) > 0 || len(o.AllowPatterns) > 0 {
		return fmt.Errorf("auth: allow and allow_patterns apply only to type %q; the credentials file is the allow list", MethodMTLS)
	}
	if p.role == RoleDialer {
		return p.compileSCRAMDialer(o)
	}
	switch {
	case o.Username != "" || o.PasswordFile != "":
		return errors.New("auth: username and password_file apply only to dialers")
	case o.CredentialsFile == "":
		return fmt.Errorf("auth: type %q requires credentials_file", MethodSCRAM)
	case o.TokenLifetimeMS != 0 && (o.TokenLifetimeMS < MinTokenLifetime.Milliseconds() || o.TokenLifetimeMS > MaxTokenLifetime.Milliseconds()):
		return fmt.Errorf("auth: token_lifetime_ms %d is outside %d (%s) to %d (%s)", o.TokenLifetimeMS,
			MinTokenLifetime.Milliseconds(), MinTokenLifetime, MaxTokenLifetime.Milliseconds(), MaxTokenLifetime)
	case o.TokenLifetimeMS > 0 && p.transport != HTTP:
		return errors.New("auth: token_lifetime_ms applies only to HTTP listeners")
	case len(o.TrustedProxies) > 0 && (p.role != RoleListener || p.transport != HTTP):
		return errors.New("auth: trusted_proxies applies only to the http sink")
	case len(o.TrustedProxies) > 0 && o.Identity != "":
		return errors.New("auth: identity binds a client certificate, which a TLS-terminating proxy does not pass on; drop it or trusted_proxies")
	}
	if o.Identity != "" {
		// Binds the certificate to the user: a peer needs its own of both
		if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
			return fmt.Errorf("auth: identity under type %q binds the client certificate to the user and requires tls.client_auth", MethodSCRAM)
		}
		var err error
		if p.identity, err = identityMode(o.Identity); err != nil {
			return err
		}
	}
	l := &scramListener{}
	var err error
	if len(o.TrustedProxies) > 0 {
		if l.proxy, err = parseProxies(o.TrustedProxies); err != nil {
			return err
		}
		l.proxy.plaintext = tlsCfg == nil
	} else {
		if len(tlsCfg.Certificates) == 0 || len(tlsCfg.Certificates[0].Certificate) == 0 {
			return errors.New("auth: type scram needs the listener certificate for channel binding")
		}
		cb := sha256.Sum256(tlsCfg.Certificates[0].Certificate[0])
		l.cb = cb[:]
	}
	if l.creds, err = LoadCredentials(o.CredentialsFile); err != nil {
		return err
	}
	if p.transport == HTTP {
		l.lifetime = DefaultTokenLifetime
		if o.TokenLifetimeMS > 0 {
			l.lifetime = time.Duration(o.TokenLifetimeMS) * time.Millisecond
		}
		key := make([]byte, 32)
		rand.Read(key)
		if l.tokens, err = auth.NewJWT(key, auth.WithIssuer("logwisp"),
			auth.WithTokenLifetime(l.lifetime), auth.WithLeeway(0)); err != nil {
			return err
		}
	}
	p.listener = l
	p.secrets = append(p.secrets, secretFile{"auth.credentials_file", o.CredentialsFile})
	return nil
}

// Start brings up the SCRAM server. Plugins call it from Start, so a policy
// that is constructed but never started holds no goroutine.
func (p *Policy) Start() error {
	if p == nil || p.listener == nil {
		return nil
	}
	l := p.listener
	s, err := auth.NewScramServerWithDecoyKey(l.creds.DecoyKey)
	if err != nil {
		return err
	}
	for _, c := range l.creds.Users {
		if err := s.AddCredential(c); err != nil {
			s.Stop()
			return fmt.Errorf("auth: user %q: %w", c.Username, err)
		}
	}
	l.server.Store(s)
	return nil
}

// Close stops the SCRAM server; exchanges in flight fail
func (p *Policy) Close() {
	if p == nil || p.listener == nil {
		return
	}
	if s := p.listener.server.Swap(nil); s != nil {
		s.Stop()
	}
}

// begin opens an exchange for a peer: throttling, then the challenge. On
// failure, status is the HTTP answer and public the only detail sent.
func (p *Policy) begin(ip string, first json.RawMessage) (challenge auth.ServerFirstMessage, status int, public string, err error) {
	l := p.listener
	var req auth.ClientFirstRequest
	if err := json.Unmarshal(first, &req); err != nil {
		p.rejected.Add(1)
		return challenge, http.StatusBadRequest, "malformed request", fmt.Errorf("%w: malformed client-first message", ErrRefused)
	}
	if !l.limit.start(ip) {
		l.throttled.Add(1)
		return challenge, http.StatusTooManyRequests, "too many attempts", fmt.Errorf("%w: %s throttled", ErrRefused, ip)
	}
	s := l.server.Load()
	if s == nil {
		l.limit.release(ip)
		l.busy.Add(1)
		return challenge, http.StatusServiceUnavailable, "busy", errors.New("auth: scram server is not running")
	}
	challenge, err = s.ProcessClientFirstMessage(req.Username, req.ClientNonce)
	if err != nil {
		l.limit.release(ip)
	}
	switch {
	case errors.Is(err, auth.ErrSCRAMTooManyHandshakes), errors.Is(err, auth.ErrSCRAMStopped):
		l.busy.Add(1)
		return challenge, http.StatusServiceUnavailable, "busy", err
	case err != nil:
		p.rejected.Add(1)
		return challenge, http.StatusBadRequest, "malformed request", fmt.Errorf("%w: %w", ErrRefused, err)
	}
	l.limit.track(ip, challenge.FullNonce)
	return challenge, 0, "", nil
}

// finish verifies a proof, binding it to this listener's certificate, then
// the client certificate to the user when configured.
func (p *Policy) finish(ip, nonce string, step authStep, cs *tls.ConnectionState) (auth.ServerFinalMessage, error) {
	l := p.listener
	l.limit.done(ip, nonce)
	s := l.server.Load()
	if s == nil {
		l.busy.Add(1)
		return auth.ServerFinalMessage{}, errors.New("auth: scram server is not running")
	}
	var bind auth.ExchangeOption // nil, so unbound, behind proxies
	if l.cb != nil {
		bind = auth.WithChannelBinding(l.cb)
	}
	final, err := s.ProcessClientFinalMessage(nonce, step.Proof.ClientProof, bind)
	if err == nil {
		err = p.bindCertificate(cs, final.Username)
	}
	if err != nil {
		p.rejected.Add(1)
		switch {
		case step.Binding != "" && l.proxy != nil:
			err = fmt.Errorf("%w; the client bound its proof to the proxy's certificate: behind trusted_proxies, log in unbound (lw auth token -unbound)", err)
		case step.Binding == "" && l.cb != nil:
			err = fmt.Errorf("%w; the client sent an unbound proof (-unbound), but this listener binds logins to its certificate", err)
		case step.Binding != "" && step.Binding != base64.StdEncoding.EncodeToString(l.cb):
			l.bindingMismatch.Add(1)
			err = fmt.Errorf("%w; the client saw another server certificate: TLS interception or a terminating proxy", err)
		}
		return auth.ServerFinalMessage{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	p.allowed.Add(1)
	l.limit.succeeded(ip)
	return final, nil
}

func (p *Policy) bindCertificate(cs *tls.ConnectionState, username string) error {
	if p.identity == "" {
		return nil
	}
	if cs == nil {
		return errors.New("no client certificate")
	}
	if got := tlsx.PeerIdentity(*cs, p.identity); got != username {
		return fmt.Errorf("certificate %s %q does not match user %q", p.identity, got, username)
	}
	return nil
}

// exchangeTCP runs the listener side after the hello and returns the final
// line for Accept. An exchange abandoned after its challenge is released from
// the auth table at once rather than holding a slot for its timeout.
func (p *Policy) exchangeTCP(a *Admission, cs *tls.ConnectionState) (Identity, []byte, error) {
	ip := throttleKey(remoteIP(a.conn.RemoteAddr().String()))
	challenge, _, public, err := p.begin(ip, a.Hello.Scram)
	if err != nil {
		writeStep(a.conn, authStep{Error: public})
		return Identity{}, nil, err
	}
	settled := false
	defer func() {
		if !settled {
			p.listener.limit.done(ip, challenge.FullNonce)
			if s := p.listener.server.Load(); s != nil {
				s.ProcessClientFinalMessage(challenge.FullNonce, "")
			}
		}
	}()
	if err := writeStep(a.conn, authStep{Challenge: &challenge}); err != nil {
		return Identity{}, nil, err
	}
	line, err := readLine(a.Reader)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("read proof: %w", err)
	}
	var step authStep
	if err := json.Unmarshal(line, &step); err != nil || step.Proof == nil {
		p.rejected.Add(1)
		writeStep(a.conn, authStep{Error: "malformed proof"})
		return Identity{}, nil, fmt.Errorf("%w: malformed proof", ErrRefused)
	}
	settled = true
	final, err := p.finish(ip, challenge.FullNonce, step, cs)
	if err != nil {
		writeStep(a.conn, authStep{Error: "authentication failed"})
		return Identity{}, nil, err
	}
	out, err := json.Marshal(authStep{Final: &final})
	if err != nil {
		return Identity{}, nil, err
	}
	return Identity{Name: final.Username, Method: MethodSCRAM}, append(out, '\n'), nil
}

// ServeAuth answers POST /auth on an HTTP scram listener: a hello gets a
// challenge, a proof gets the server-final message and a bearer token (in
// proxy mode, a session cookie on request), a logout ends a session. It
// returns the identity of a completed login, or the refusal, for the
// plugin's log; other steps return neither.
func (p *Policy) ServeAuth(w http.ResponseWriter, r *http.Request) (Identity, error) {
	if p == nil || p.listener == nil || p.listener.tokens == nil {
		http.NotFound(w, r)
		return Identity{}, nil
	}
	l := p.listener
	client, err := p.ClientAddr(r)
	if err != nil {
		writeJSON(w, http.StatusForbidden, authStep{Error: "forbidden"})
		return Identity{}, err
	}
	ip := throttleKey(client)
	// A cross-origin page cannot send JSON without a preflight nobody answers
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		p.rejected.Add(1)
		writeJSON(w, http.StatusUnsupportedMediaType, authStep{Error: "malformed request"})
		return Identity{}, errors.New("auth request: Content-Type is not application/json")
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(ExchangeTimeout))
	rc.SetWriteDeadline(time.Now().Add(ExchangeTimeout))
	var req struct {
		chain.Hello
		authStep
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAuthLine)).Decode(&req); err != nil {
		p.rejected.Add(1)
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, authStep{Error: "request too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, authStep{Error: "malformed request"})
		}
		return Identity{}, fmt.Errorf("auth request: %w", err)
	}
	cookie := req.Session == "cookie"
	switch {
	case cookie && l.proxy == nil, req.Session != "" && !cookie, req.Logout && l.proxy == nil:
		p.rejected.Add(1)
		writeJSON(w, http.StatusBadRequest, authStep{Error: "sessions and logout need trusted_proxies"})
		return Identity{}, errors.New("auth request: a browser session outside proxy mode")
	case req.Logout:
		return Identity{}, p.logout(w, r)
	case len(req.Scram) > 0 && req.LogWisp == chain.ProtocolVersion:
		challenge, status, public, err := p.begin(ip, req.Scram)
		if err != nil {
			writeJSON(w, status, authStep{Error: public})
			return Identity{}, err
		}
		writeJSON(w, http.StatusOK, authStep{Challenge: &challenge})
		return Identity{}, nil
	case req.Proof != nil:
		final, err := p.finish(ip, req.Proof.FullNonce, req.authStep, r.TLS)
		if err != nil {
			status := http.StatusUnauthorized
			if !errors.Is(err, ErrRefused) {
				status = http.StatusServiceUnavailable
			}
			writeJSON(w, status, authStep{Error: "authentication failed"})
			return Identity{}, err
		}
		token, err := l.tokens.GenerateToken(final.Username, nil)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, authStep{Error: "token unavailable"})
			return Identity{}, err
		}
		answer := authStep{Final: &final, ExpiresIn: int64(l.lifetime / time.Second)}
		if cookie {
			http.SetCookie(w, sessionCookie(token, int(l.lifetime/time.Second)))
		} else {
			answer.Token = token
		}
		writeJSON(w, http.StatusOK, answer)
		return Identity{Name: final.Username, Method: MethodSCRAM}, nil
	}
	p.rejected.Add(1)
	writeJSON(w, http.StatusBadRequest, authStep{Error: "malformed request"})
	return Identity{}, errors.New("auth request: neither a hello nor a proof")
}

func (p *Policy) authorizeToken(r *http.Request) (Identity, int, error) {
	l := p.listener
	if l.tokens == nil {
		p.rejected.Add(1)
		return Identity{}, http.StatusUnauthorized, fmt.Errorf("%w: no token issuer on this listener", ErrRefused)
	}
	if _, err := p.ClientAddr(r); err != nil {
		return Identity{}, http.StatusForbidden, err
	}
	token, err := p.presentedToken(r)
	if err != nil {
		p.rejected.Add(1)
		return Identity{}, http.StatusUnauthorized, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	user, _, err := l.tokens.ValidateToken(token)
	if err == nil && l.proxy != nil && l.proxy.isRevoked(token) {
		err = errors.New("token ended by logout")
	}
	if err != nil {
		p.rejected.Add(1)
		return Identity{}, http.StatusUnauthorized, fmt.Errorf("%w: bearer %w", ErrRefused, err)
	}
	if err := p.bindCertificate(r.TLS, user); err != nil {
		p.rejected.Add(1)
		return Identity{}, http.StatusForbidden, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return Identity{Name: user, Method: MethodSCRAM}, 0, nil
}

func (l *scramListener) stats(d map[string]any) {
	d["auth_users"] = len(l.creds.Users)
	d["auth_throttled"] = l.throttled.Load()
	d["auth_busy"] = l.busy.Load()
	d["auth_binding_mismatch"] = l.bindingMismatch.Load()
	if l.tokens != nil {
		d["auth_token_lifetime_ms"] = l.lifetime.Milliseconds()
	}
	if l.proxy != nil {
		proxies := make([]string, len(l.proxy.trusted))
		for i, p := range l.proxy.trusted {
			proxies[i] = p.String()
		}
		d["auth_trusted_proxies"] = proxies
	}
}

// --- Dialer ---

type scramDialer struct {
	username string
	password string
	unbound  bool // HTTP logins to a listener behind a TLS-terminating proxy
	token    atomic.Pointer[string]
	renewAt  atomic.Int64           // unix nanoseconds; Prepare logs in again from then
	expires  atomic.Int64           // unix nanoseconds; 0 = lifetime unknown
	pin      atomic.Pointer[[]byte] // HTTP: certificate the token's login was bound to
	failures atomic.Uint64
	lastErr  atomic.Pointer[string]
}

func (p *Policy) compileSCRAMDialer(o *config.AuthOptions) error {
	switch {
	case o.CredentialsFile != "", o.TokenLifetimeMS != 0, len(o.TrustedProxies) > 0:
		return errors.New("auth: credentials_file, token_lifetime_ms and trusted_proxies apply only to listeners")
	case o.Identity != "":
		return fmt.Errorf("auth: identity on a dialer pins the server and applies only to type %q", MethodMTLS)
	case o.Username == "" || o.PasswordFile == "":
		return fmt.Errorf("auth: type %q on a dialer requires username and password_file", MethodSCRAM)
	}
	password, err := ReadPassword(o.PasswordFile)
	if err != nil {
		return err
	}
	d := &scramDialer{username: o.Username, password: password}
	if _, err := d.client().StartAuthentication(); err != nil {
		return fmt.Errorf("auth: username %q: %w", o.Username, err)
	}
	p.dialer = d
	p.secrets = append(p.secrets, secretFile{"auth.password_file", o.PasswordFile})
	return nil
}

// Unbind makes a dialer's HTTP logins unbound, for an http sink behind a
// TLS-terminating proxy whose certificate logwisp never sees
func (p *Policy) Unbind() {
	if p != nil && p.dialer != nil {
		p.dialer.unbound = true
	}
}

func (d *scramDialer) client() *auth.ScramClient {
	return auth.NewScramClient(d.username, d.password, auth.WithMinArgonCost(minArgonTime, minArgonMemory))
}

// exchangeTCP runs the dialer side on conn; nothing is trusted until the
// server's final signature proves it holds this user's verifier.
func (d *scramDialer) exchangeTCP(conn net.Conn, r *bufio.Reader, node string) (err error) {
	defer func() { d.record(err) }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("auth: scram requires TLS")
	}
	c := d.client()
	first, err := c.StartAuthentication()
	if err != nil {
		return err
	}
	scram, err := json.Marshal(first)
	if err != nil {
		return err
	}
	line, err := chain.EncodeHello(chain.Hello{Node: node, Scram: scram})
	if err != nil {
		return err
	}
	if _, err := conn.Write(line); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	step, err := readStep(r)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("%w: no challenge within %v (older logwisp, or not a scram listener)", ErrRefused, ExchangeTimeout)
		}
		return err
	}
	if step.Challenge == nil {
		return errors.New("auth: server sent no challenge")
	}
	cb := certHash(tc.ConnectionState())
	proof, err := c.ProcessServerFirstMessage(*step.Challenge, auth.WithChannelBinding(cb))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if err := writeStep(conn, authStep{Proof: &proof, Binding: base64.StdEncoding.EncodeToString(cb)}); err != nil {
		return err
	}
	if step, err = readStep(r); err != nil {
		return err
	}
	return d.verifyFinal(c, step)
}

func (d *scramDialer) verifyFinal(c *auth.ScramClient, step authStep) error {
	if step.Final == nil {
		return errors.New("auth: server sent no final message")
	}
	if err := c.VerifyServerFinalMessage(*step.Final); err != nil {
		return fmt.Errorf("%w: the server could not prove it holds this user's verifier: %w", ErrRefused, err)
	}
	return nil
}

// Token logs in over HTTP and returns a fresh bearer token: for the CLI, and
// behind Prepare. The certificate of the first answer is pinned before the
// proof is sent, so neither the proof nor the token reaches another server.
func (p *Policy) Token(ctx context.Context, client *http.Client, baseURL string) (token string, err error) {
	if p == nil || p.dialer == nil {
		return "", fmt.Errorf("auth: tokens need type %q on a dialer", MethodSCRAM)
	}
	d := p.dialer
	defer func() { d.record(err) }()
	d.dropToken() // a rotated server certificate must be able to bind anew
	ctx, cancel := context.WithTimeout(ctx, ExchangeTimeout)
	defer cancel()
	url := baseURL + chain.AuthPath

	c := d.client()
	first, err := c.StartAuthentication()
	if err != nil {
		return "", err
	}
	scram, err := json.Marshal(first)
	if err != nil {
		return "", err
	}
	hello, err := json.Marshal(chain.Hello{LogWisp: chain.ProtocolVersion, Scram: scram})
	if err != nil {
		return "", err
	}
	step, resp, err := postStep(ctx, client, url, hello)
	if err != nil {
		return "", err
	}
	if step.Challenge == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", errors.New("auth: no challenge over TLS")
	}
	cb := certHash(*resp.TLS)
	d.pin.Store(&cb) // unbound too: both requests must reach the same server
	var bind auth.ExchangeOption
	var binding string
	if !d.unbound {
		bind, binding = auth.WithChannelBinding(cb), base64.StdEncoding.EncodeToString(cb)
	}
	proof, err := c.ProcessServerFirstMessage(*step.Challenge, bind)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrRefused, err)
	}
	body, err := json.Marshal(authStep{Proof: &proof, Binding: binding})
	if err != nil {
		return "", err
	}
	if step, _, err = postStep(ctx, client, url, body); err != nil {
		return "", err
	}
	if err := d.verifyFinal(c, step); err != nil {
		return "", err
	}
	if step.Token == "" {
		return "", errors.New("auth: server issued no token")
	}
	now, lifetime := time.Now(), time.Duration(step.ExpiresIn)*time.Second
	d.renewAt.Store(renewAt(now, lifetime).UnixNano())
	d.expires.Store(0)
	if lifetime > 0 {
		d.expires.Store(now.Add(lifetime).UnixNano())
	}
	d.token.Store(&step.Token)
	return step.Token, nil
}

// renewAt schedules a fresh login ahead of expiry, so a healthy link never
// pays a refused request each lifetime; 401 stays the fallback for reloads.
func renewAt(now time.Time, lifetime time.Duration) time.Time {
	if lifetime <= 0 {
		return now.Add(100 * 365 * 24 * time.Hour) // lifetime unknown: renew on 401 only
	}
	margin := min(max(5*time.Second, lifetime/10), lifetime/2)
	return now.Add(lifetime - margin)
}

func (d *scramDialer) dropToken() {
	d.token.Store(nil)
	d.pin.Store(nil)
}

func (d *scramDialer) verifyPin(cs tls.ConnectionState) error {
	pin := d.pin.Load()
	if pin == nil {
		return nil
	}
	if len(cs.PeerCertificates) == 0 || !bytes.Equal(certHash(cs), *pin) {
		return errPinMismatch
	}
	return nil
}

func (d *scramDialer) record(err error) {
	msg := ""
	if err != nil {
		d.failures.Add(1)
		msg = err.Error()
	}
	d.lastErr.Store(&msg)
}

func (d *scramDialer) stats(m map[string]any) {
	m["auth_username"] = d.username
	m["auth_failures"] = d.failures.Load()
	if e := d.lastErr.Load(); e != nil {
		m["last_auth_error"] = *e
	}
}

// postStep sends one /auth request; any answer but 200 is a refusal
func postStep(ctx context.Context, client *http.Client, url string, body []byte) (authStep, *http.Response, error) {
	var step authStep
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return step, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return step, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthLine))
	if err != nil {
		return step, resp, err
	}
	decodeErr := json.Unmarshal(data, &step)
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return step, resp, fmt.Errorf("%w: no auth endpoint at %s (older logwisp, or not a scram listener)", ErrRefused, url)
	case resp.StatusCode != http.StatusOK:
		msg := step.Error
		if msg == "" {
			msg = resp.Status
		}
		return step, resp, fmt.Errorf("%w: server: %s", ErrRefused, msg)
	case decodeErr != nil:
		return step, resp, fmt.Errorf("auth: malformed answer: %w", decodeErr)
	}
	return step, resp, nil
}

// AwaitClose blocks until a listener ends a link after its admission. Chain
// sources never write once a link is up, so a line is a refusal (ErrRefused,
// sent to dialers without scram that never read it) and EOF a close.
func AwaitClose(r *bufio.Reader) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	var step authStep
	if json.Unmarshal(line, &step) == nil && step.Error != "" {
		return fmt.Errorf("%w: server: %s", ErrRefused, step.Error)
	}
	return errors.New("unexpected data from server")
}

// --- Wire helpers ---

// readLine refuses a line over maxAuthLine as soon as it arrives: r buffers
// far more, for the stream after the exchange.
func readLine(r *bufio.Reader) ([]byte, error) {
	for {
		b, _ := r.Peek(r.Buffered())
		if i := bytes.IndexByte(b, '\n'); i >= 0 && i < maxAuthLine {
			line := bytes.Clone(bytes.TrimRight(b[:i+1], "\r\n"))
			r.Discard(i + 1)
			return line, nil
		}
		if len(b) >= maxAuthLine {
			return nil, fmt.Errorf("line exceeds %d bytes", maxAuthLine)
		}
		if _, err := r.Peek(len(b) + 1); err != nil {
			return nil, err
		}
	}
}

func readStep(r *bufio.Reader) (authStep, error) {
	var step authStep
	line, err := readLine(r)
	if err != nil {
		return step, err
	}
	if err := json.Unmarshal(line, &step); err != nil {
		return step, fmt.Errorf("auth: malformed answer: %w", err)
	}
	if step.Error != "" {
		return step, fmt.Errorf("%w: server: %s", ErrRefused, step.Error)
	}
	return step, nil
}

func writeStep(w io.Writer, step authStep) error {
	line, err := json.Marshal(step)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

func writeJSON(w http.ResponseWriter, status int, step authStep) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	writeStep(w, step)
}

func certHash(cs tls.ConnectionState) []byte {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	h := sha256.Sum256(cs.PeerCertificates[0].Raw)
	return h[:]
}

func remoteIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// --- Throttling ---

// throttleKey is what the limiter counts: an address, or for IPv6 its /64,
// which one host usually holds whole. Link-local too: a peer picks any
// fe80::/64 address, so per address it would escape its budget.
func throttleKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Is4() {
		return ip
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// limiter bounds SCRAM attempts per remote address: failed or abandoned
// exchanges drain a token bucket (successes are refunded) and at most
// limitPending may be unfinished. A full table fails closed.
type limiter struct {
	mu        sync.Mutex
	peers     map[string]*peerLimit
	lastSweep time.Time
}

type peerLimit struct {
	bucket   *tokenbucket.TokenBucket
	pending  map[string]time.Time // full nonce -> expiry
	reserved int                  // started, challenge not yet issued
	seen     time.Time
}

func (l *limiter) start(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.peers == nil {
		l.peers = make(map[string]*peerLimit)
	}
	if now.Sub(l.lastSweep) > limitIdle/6 {
		l.sweep(now)
	}
	pl := l.peers[ip]
	if pl == nil {
		if len(l.peers) >= limitPeers {
			return false
		}
		pl = &peerLimit{bucket: tokenbucket.New(limitBurst, limitRate), pending: make(map[string]time.Time)}
		l.peers[ip] = pl
	}
	pl.seen = now
	pl.expire(now)
	// Reserved under this lock: concurrent hellos cannot all pass the check
	if len(pl.pending)+pl.reserved >= limitPending || !pl.bucket.Allow() {
		return false
	}
	pl.reserved++
	return true
}

// track turns start's reservation into the exchange's nonce
func (l *limiter) track(ip, nonce string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pl := l.peers[ip]; pl != nil {
		pl.reserved--
		pl.pending[nonce] = time.Now().Add(auth.ScramHandshakeTimeout)
	}
}

// release frees start's reservation when no challenge was issued
func (l *limiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pl := l.peers[ip]; pl != nil {
		pl.reserved--
	}
}

func (l *limiter) done(ip, nonce string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pl := l.peers[ip]; pl != nil {
		delete(pl.pending, nonce)
	}
}

func (l *limiter) succeeded(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pl := l.peers[ip]; pl != nil {
		pl.bucket.Refund(1)
	}
}

func (pl *peerLimit) expire(now time.Time) {
	for nonce, expiry := range pl.pending {
		if now.After(expiry) {
			delete(pl.pending, nonce)
		}
	}
}

// sweep drops addresses idle long enough for their bucket to be full again
func (l *limiter) sweep(now time.Time) {
	l.lastSweep = now
	for ip, pl := range l.peers {
		pl.expire(now) // an abandoned HTTP challenge has no done
		if now.Sub(pl.seen) > limitIdle && len(pl.pending) == 0 && pl.reserved == 0 {
			delete(l.peers, ip)
		}
	}
}
