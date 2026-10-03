// Package authz is the single seam between declarative auth config and the
// network plugins. Listeners admit peers through Admit (TCP) or
// AuthorizeRequest (HTTP); dialers prove themselves through Greet or Prepare.
// New returns nil when auth is disabled and every method tolerates a nil
// receiver, so call sites read the same whether or not a policy is set.
package authz

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync/atomic"
	"time"

	"logwisp/internal/chain"
	"logwisp/internal/config"
	"logwisp/internal/tlsx"

	"github.com/lixenwraith/log"
)

// Authentication methods
const (
	MethodNone  = "none"
	MethodMTLS  = "mtls"
	MethodSCRAM = "scram"
)

// Node label binding modes. See ResolveNode and TrustsEntryNode for the
// difference between assert and force.
const (
	BindingNone   = "none"
	BindingAssert = "assert"
	BindingForce  = "force"
)

// Role selects the validation and behavior appropriate to the call site
type Role int

const (
	// RoleListener authenticates peers of a plugin with no node concept: the
	// tcp and http sinks
	RoleListener Role = iota
	// RoleChainListener also binds the node label a peer declares: the
	// tcp_chain and http_chain sources
	RoleChainListener
	// RoleDialer proves itself to, or pins, the server: the tcp_chain and
	// http_chain sinks
	RoleDialer
)

// Transport tells HTTP plugins, which carry bearer tokens, from TCP ones
type Transport int

const (
	TCP Transport = iota
	HTTP
)

// ErrRefused marks a decision of the policy, on either side: a peer refused
// by this listener, or this dialer refused by its server. Anything else is a
// transport or protocol failure.
var ErrRefused = errors.New("auth: refused")

// Policy is the compiled form of config.AuthOptions
type Policy struct {
	role      Role
	transport Transport
	method    string
	identity  string // mtls: identity field; scram: certificate-to-user binding, "" = none
	allow     map[string]struct{}
	patterns  []*regexp.Regexp
	binding   string
	secrets   []secretFile // reported at startup when every local user can read them

	listener *scramListener // scram listener state
	dialer   *scramDialer   // scram dialer state

	// Statistics
	allowed  atomic.Uint64
	rejected atomic.Uint64
}

type secretFile struct{ key, path string }

// Identity is the outcome of a successful authorization. The zero value is
// what a disabled policy yields.
type Identity struct {
	Name   string // certificate field (mtls) or username (scram)
	Method string
}

// Apply stamps an authenticated identity onto session metadata. A zero
// Identity (auth disabled) leaves the map untouched.
func (id Identity) Apply(meta map[string]any) {
	if id.Name == "" {
		return
	}
	meta["auth_method"] = id.Method
	meta["auth_identity"] = id.Name
}

// New compiles an auth policy, returning (nil, nil) when auth is disabled.
// tlsCfg is what tlsx built from the sibling `tls` block: a policy the
// transport cannot enforce is rejected here rather than silently accepted.
func New(o *config.AuthOptions, tlsCfg *tls.Config, role Role, transport Transport) (*Policy, error) {
	if o == nil {
		return nil, nil
	}
	switch o.Type {
	case "", MethodNone:
		// Tuning keys are ignored with the block, but one that names peers or
		// credentials means auth was intended and the type was forgotten
		if key := intentKey(o); key != "" {
			return nil, fmt.Errorf("auth: %s is set but auth.type is %q", key, MethodNone)
		}
		return nil, nil
	case MethodMTLS, MethodSCRAM:
	default:
		return nil, fmt.Errorf("auth: type %q (valid: %q, %q, %q)", o.Type, MethodNone, MethodMTLS, MethodSCRAM)
	}
	if tlsCfg == nil && (o.Type != MethodSCRAM || len(o.TrustedProxies) == 0) {
		return nil, fmt.Errorf("auth: type %q requires tls.enabled", o.Type)
	}
	if role == RoleDialer && tlsCfg != nil && tlsCfg.InsecureSkipVerify {
		// An unverified server makes identities claims and exposes credentials
		return nil, fmt.Errorf("auth: type %q cannot be used with tls.insecure_skip_verify", o.Type)
	}

	binding, err := nodeBinding(o.NodeBinding, role)
	if err != nil {
		return nil, err
	}
	p := &Policy{role: role, transport: transport, method: o.Type, binding: binding}
	if o.Type == MethodMTLS {
		err = p.compileMTLS(o, tlsCfg)
	} else {
		err = p.compileSCRAM(o, tlsCfg)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// intentKey names the first key that only makes sense with authentication on
func intentKey(o *config.AuthOptions) string {
	switch {
	case len(o.Allow) > 0:
		return "allow"
	case len(o.AllowPatterns) > 0:
		return "allow_patterns"
	}
	return scramKey(o)
}

func nodeBinding(binding string, role Role) (string, error) {
	if role != RoleChainListener {
		if binding != "" && binding != BindingNone {
			return "", fmt.Errorf("auth: node_binding %q applies only to chain sources", binding)
		}
		return BindingNone, nil
	}
	switch binding {
	case "":
		// The only setting under which a misconfigured or hostile edge cannot
		// mislabel its entries
		return BindingForce, nil
	case BindingNone, BindingAssert, BindingForce:
		return binding, nil
	}
	return "", fmt.Errorf("auth: node_binding %q (valid: %q, %q, %q)", binding, BindingNone, BindingAssert, BindingForce)
}

func identityMode(mode string) (string, error) {
	switch mode {
	case "":
		return tlsx.IdentityCN, nil
	case tlsx.IdentityCN, tlsx.IdentitySANDNS, tlsx.IdentitySANURI, tlsx.IdentitySANEmail:
		return mode, nil
	}
	return "", fmt.Errorf("auth: identity %q (valid: %q, %q, %q, %q)",
		mode, tlsx.IdentityCN, tlsx.IdentitySANDNS, tlsx.IdentitySANURI, tlsx.IdentitySANEmail)
}

func (p *Policy) compileMTLS(o *config.AuthOptions, tlsCfg *tls.Config) error {
	if key := scramKey(o); key != "" {
		return fmt.Errorf("auth: %s applies only to type %q", key, MethodSCRAM)
	}
	if p.role != RoleDialer && tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		return fmt.Errorf("auth: type %q requires tls.client_auth", MethodMTLS)
	}
	var err error
	if p.identity, err = identityMode(o.Identity); err != nil {
		return err
	}
	p.allow = make(map[string]struct{}, len(o.Allow))
	for _, a := range o.Allow {
		if a = strings.TrimSpace(a); a != "" {
			p.allow[a] = struct{}{}
		}
	}
	for i, pat := range o.AllowPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("auth: allow_patterns[%d] %q: %w", i, pat, err)
		}
		p.patterns = append(p.patterns, re)
	}
	return nil
}

func scramKey(o *config.AuthOptions) string {
	switch {
	case o.CredentialsFile != "":
		return "credentials_file"
	case o.TokenLifetimeMS != 0:
		return "token_lifetime_ms"
	case o.Username != "":
		return "username"
	case o.PasswordFile != "":
		return "password_file"
	case len(o.TrustedProxies) > 0:
		return "trusted_proxies"
	}
	return ""
}

// Authorize checks the mtls certificate identity of a completed handshake. It
// refuses under scram, so a listener that skipped its exchange fails closed.
// A nil policy authorizes everything and yields the zero Identity.
func (p *Policy) Authorize(cs *tls.ConnectionState) (Identity, error) {
	if p == nil {
		return Identity{}, nil
	}
	if p.method != MethodMTLS {
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("%w: type %q admits peers only through its exchange", ErrRefused, p.method)
	}
	if cs == nil {
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("%w: peer is not on a TLS connection", ErrRefused)
	}
	name := tlsx.PeerIdentity(*cs, p.identity)
	if name == "" {
		// An unusable identity field is a rejection, not an empty match
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("%w: peer certificate carries no %s identity", ErrRefused, p.identity)
	}
	if !p.permits(name) {
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("%w: identity %q is not allowed", ErrRefused, name)
	}
	p.allowed.Add(1)
	return Identity{Name: name, Method: MethodMTLS}, nil
}

// VerifyConnection is assignable to tls.Config.VerifyConnection on a dialer.
// It runs after the standard chain and hostname checks on every connection,
// resumed ones included: mtls pins the server identity, scram pins the
// certificate its last exchange was bound to.
func (p *Policy) VerifyConnection(cs tls.ConnectionState) error {
	if p == nil {
		return nil
	}
	if p.dialer != nil {
		return p.dialer.verifyPin(cs)
	}
	_, err := p.Authorize(&cs)
	return err
}

// Admission is a TCP peer that passed authentication and awaits the plugin's
// own checks. Under scram nothing is sent until Accept or Reject, so a later
// check such as node binding still decides what the peer is told.
type Admission struct {
	Identity Identity
	Hello    chain.Hello   // zero when no hello was read
	Reader   *bufio.Reader // the stream continues here, after the auth lines
	conn     net.Conn
	final    []byte // scram: the server-final line Accept sends
	deadline bool
}

// Admit authenticates a TCP peer before it is served: the certificate under
// mtls (before anything is read), the hello's SCRAM exchange under scram.
// wantHello reads the chain hello without scram too. The whole exchange runs
// under one read/write deadline of timeout; Accept clears it.
func (p *Policy) Admit(conn net.Conn, cs *tls.ConnectionState, wantHello bool, timeout time.Duration) (*Admission, error) {
	a := &Admission{conn: conn, Reader: bufio.NewReaderSize(conn, streamBuffer)}
	scram := p != nil && p.listener != nil
	if !scram {
		id, err := p.Authorize(cs)
		if err != nil {
			return nil, err
		}
		a.Identity = id
	}
	if !wantHello && !scram {
		return a, nil
	}
	conn.SetDeadline(time.Now().Add(timeout))
	a.deadline = true
	line, err := readLine(a.Reader)
	if err != nil {
		return nil, fmt.Errorf("read hello: %w", err)
	}
	if a.Hello, err = chain.DecodeHello(line); err != nil {
		if scram {
			p.rejected.Add(1)
			writeStep(conn, authStep{Error: "malformed hello"})
		}
		return nil, err
	}
	switch {
	case scram:
		if len(a.Hello.Scram) == 0 {
			p.rejected.Add(1)
			writeStep(conn, authStep{Error: "authentication required"})
			return nil, fmt.Errorf("%w: peer offered no credentials", ErrRefused)
		}
		a.Identity, a.final, err = p.exchangeTCP(a, cs)
		if err != nil {
			return nil, err
		}
	case len(a.Hello.Scram) > 0:
		// Without this answer a SCRAM dialer would wait out its deadline
		writeStep(conn, authStep{Error: "authentication not enabled"})
		return nil, fmt.Errorf("%w: peer offered credentials, auth.type is not %q", ErrRefused, MethodSCRAM)
	}
	return a, nil
}

// Accept tells a scram peer it is admitted and lifts the exchange deadline
func (a *Admission) Accept() error {
	if a.final != nil {
		if _, err := a.conn.Write(a.final); err != nil {
			return err
		}
	}
	if a.deadline {
		return a.conn.SetDeadline(time.Time{})
	}
	return nil
}

// Reject tells a scram peer why it is turned away after authenticating
func (a *Admission) Reject(reason string) {
	if a.final != nil {
		writeStep(a.conn, authStep{Error: reason})
	}
}

// AuthorizeRequest admits one HTTP request to a protected endpoint: the
// client certificate under mtls, the bearer token under scram. status is the
// answer for a refusal (401 or 403); see Refuse.
func (p *Policy) AuthorizeRequest(r *http.Request) (Identity, int, error) {
	switch {
	case p == nil:
		return Identity{}, 0, nil
	case p.listener == nil:
		id, err := p.Authorize(r.TLS)
		if err != nil {
			return Identity{}, http.StatusForbidden, err
		}
		return id, 0, nil
	}
	return p.authorizeToken(r)
}

// Refuse answers a request AuthorizeRequest turned away, with no detail
func Refuse(w http.ResponseWriter, status int) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="logwisp"`)
	}
	http.Error(w, strings.ToLower(http.StatusText(status)), status)
}

// Greet opens a dialer's connection: it writes the hello and, under scram,
// runs the whole exchange under ExchangeTimeout, cut short by ctx. The
// returned reader holds whatever the server sent after the exchange.
func (p *Policy) Greet(ctx context.Context, conn net.Conn, node string) (*bufio.Reader, error) {
	r := bufio.NewReaderSize(conn, streamBuffer)
	conn.SetDeadline(time.Now().Add(ExchangeTimeout))
	defer context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })()
	if p == nil || p.dialer == nil {
		line, err := chain.EncodeHello(chain.Hello{Node: node})
		if err == nil {
			_, err = conn.Write(line)
		}
		if err != nil {
			return nil, fmt.Errorf("hello: %w", err)
		}
	} else if err := p.dialer.exchangeTCP(conn, r, node); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return r, conn.SetDeadline(time.Time{})
}

// Prepare readies a request for a protected HTTP endpoint: under scram it
// authenticates when no token is held, then sets the bearer header. baseURL
// is scheme://host:port; client must carry VerifyConnection. No-op otherwise.
func (p *Policy) Prepare(ctx context.Context, client *http.Client, baseURL string, req *http.Request) error {
	if p == nil || p.dialer == nil {
		return nil
	}
	d := p.dialer
	token := d.token.Load()
	if token == nil || time.Now().UnixNano() >= d.renewAt.Load() {
		pin, expires := d.pin.Load(), d.expires.Load()
		t, err := p.Token(ctx, client, baseURL)
		// A renewal refused while the old token holds (a throttled login behind
		// a shared address) keeps sending on it and retries in a few seconds
		if left := time.Duration(expires - time.Now().UnixNano()); err != nil && token != nil && left > 0 {
			d.pin.Store(pin)
			d.token.Store(token)
			d.renewAt.Store(time.Now().Add(min(5*time.Second, left/2)).UnixNano())
		} else if err != nil {
			return err
		} else {
			token = &t
		}
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	return nil
}

// Invalidate drops the scram token after the server refused it (status 401)
// or a connection presented a certificate other than the bound one (err),
// and reports whether a retry can succeed by authenticating again.
func (p *Policy) Invalidate(status int, err error) bool {
	if p == nil || p.dialer == nil {
		return false
	}
	if status != http.StatusUnauthorized && !errors.Is(err, errPinMismatch) {
		return false
	}
	p.dialer.dropToken()
	return true
}

// permits reports whether an identity satisfies the allow list. An empty list
// admits any identity the CA vouches for; that is the documented default, and
// constructors log it at startup rather than leaving it silent.
// Identities are not secrets, so ordinary comparison is fine.
func (p *Policy) permits(name string) bool {
	if len(p.allow) == 0 && len(p.patterns) == 0 {
		return true
	}
	if _, ok := p.allow[name]; ok {
		return true
	}
	for _, re := range p.patterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// ResolveNode returns the node label for a connection. With no policy, or
// node_binding "none", trust_node governs as before: the declared label stands
// only when trusted and non-empty, otherwise fallback (the remote address) is
// used. Otherwise the label is bound to the authenticated identity.
func (p *Policy) ResolveNode(declared, fallback string, trustNode bool, id Identity) (string, error) {
	if p == nil || p.binding == BindingNone {
		if declared == "" || !trustNode {
			return fallback, nil
		}
		return declared, nil
	}
	if id.Name == "" {
		return "", fmt.Errorf("auth: node_binding %q requires an authenticated identity", p.binding)
	}
	if p.binding == BindingForce {
		return id.Name, nil
	}
	// BindingAssert: a mismatch is loud rather than silently corrected
	if declared == "" {
		return "", fmt.Errorf("auth: node_binding %q: peer %q declared no node label", BindingAssert, id.Name)
	}
	if declared != id.Name {
		return "", fmt.Errorf("auth: node_binding %q: declared node %q does not match identity %q",
			BindingAssert, declared, id.Name)
	}
	return declared, nil
}

// TrustsEntryNode reports whether node labels carried by individual entries
// survive the policy. force relabels every entry, so an ingest boundary that
// does not trust its peer gets exact attribution; assert pins only the
// connection's own label, so a relay forwarding other nodes' entries proves
// who it is while preserving their origin.
func (p *Policy) TrustsEntryNode(trustNode bool) bool {
	if p == nil {
		return trustNode
	}
	if p.binding == BindingForce {
		return false
	}
	return trustNode
}

// BindsNode reports whether the policy overrides trust_node
func (p *Policy) BindsNode() bool {
	return p != nil && p.binding != BindingNone
}

// NodeBinding returns the effective binding mode
func (p *Policy) NodeBinding() string {
	if p == nil {
		return BindingNone
	}
	return p.binding
}

// Enabled reports whether a policy is in force
func (p *Policy) Enabled() bool { return p != nil }

// Unrestricted reports whether an mtls policy admits any identity the CA
// vouches for. Under scram the credentials file is the allow list.
func (p *Policy) Unrestricted() bool {
	return p != nil && p.method == MethodMTLS && len(p.allow) == 0 && len(p.patterns) == 0
}

// LogStartup reports, once per plugin construction, what the policy admits,
// how it labels nodes, allow patterns that admit more than they appear to,
// and secret files every local user can read. trustNode: chain sources only.
func (p *Policy) LogStartup(l *log.Logger, component, id string, trustNode bool) {
	if p == nil {
		return
	}
	for _, re := range p.patterns {
		if !anchored(re.String()) {
			l.Warn("msg", "auth.allow_patterns entry is not anchored and matches any identity containing it",
				"component", component,
				"instance_id", id,
				"pattern", re.String(),
				"hint", "anchor every alternative, e.g. ^(edge-01|edge-02)$")
		}
	}
	for _, f := range p.secrets {
		if w := tlsx.SecretFileWarning(f.key, f.path); w != "" {
			l.Warn("msg", w, "component", component, "instance_id", id)
		}
	}
	if p.role == RoleDialer {
		return
	}
	if p.BehindProxy() && p.listener.proxy.exposedHop() {
		l.Warn("msg", "Trusted proxies may be on other hosts and the hop from them is plaintext: anyone on that path can relay logins and read sessions",
			"component", component,
			"instance_id", id,
			"hint", "keep the proxies on loopback, or enable tls on this listener")
	}
	if p.Unrestricted() {
		l.Warn("msg", "Auth policy admits any identity the configured CA vouches for",
			"component", component,
			"instance_id", id,
			"hint", "set auth.allow or auth.allow_patterns to authorize named peers")
	}
	if p.BindsNode() {
		msg := "Connection node label bound to peer identity; trust_node still governs per-entry labels"
		if p.binding == BindingForce {
			msg = "Node labels bound to peer identity; trust_node is ignored"
		}
		l.Info("msg", msg,
			"component", component,
			"instance_id", id,
			"node_binding", p.binding,
			"trust_node", trustNode)
	}
}

// anchored reports whether every match of pattern spans the whole identity:
// each alternative must start with ^ and end with $. "^a|b$" is the classic
// miss, admitting "a..." and "...b".
func anchored(pattern string) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	re = re.Simplify()
	return anchoredAt(re, syntax.OpBeginText) && anchoredAt(re, syntax.OpEndText)
}

// anchoredAt follows the matching edge of re (first or last element of a
// concatenation, every branch of an alternation) down to the anchor op.
func anchoredAt(re *syntax.Regexp, anchor syntax.Op) bool {
	switch re.Op {
	case anchor:
		return true
	case syntax.OpCapture:
		return anchoredAt(re.Sub[0], anchor)
	case syntax.OpConcat:
		if anchor == syntax.OpBeginText {
			return anchoredAt(re.Sub[0], anchor)
		}
		return anchoredAt(re.Sub[len(re.Sub)-1], anchor)
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !anchoredAt(sub, anchor) {
				return false
			}
		}
		return true
	}
	return false
}

// Describe renders the policy for a startup log line
func (p *Policy) Describe() string {
	switch {
	case p == nil:
		return MethodNone
	case p.dialer != nil:
		return fmt.Sprintf("%s user=%s", MethodSCRAM, p.dialer.username)
	case p.listener != nil:
		cert := "independent"
		if p.identity != "" {
			cert = p.identity + "=username"
		}
		if p.BehindProxy() {
			return fmt.Sprintf("%s users=%d unbound behind %d trusted proxy range(s)", MethodSCRAM, len(p.listener.creds.Users), len(p.listener.proxy.trusted))
		}
		return fmt.Sprintf("%s users=%d certificate=%s node_binding=%s", MethodSCRAM, len(p.listener.creds.Users), cert, p.binding)
	}
	scope := fmt.Sprintf("%d exact, %d pattern(s)", len(p.allow), len(p.patterns))
	if p.Unrestricted() {
		scope = "any identity issued by the configured CA"
	}
	return fmt.Sprintf("%s identity=%s allow=[%s] node_binding=%s", MethodMTLS, p.identity, scope, p.binding)
}

// Rejected returns the number of authorization failures
func (p *Policy) Rejected() uint64 {
	if p == nil {
		return 0
	}
	return p.rejected.Load()
}

// Stats reports policy state for a plugin's stats details map. Merge it in
// with maps.Copy so rejections surface in the status reporter and in the
// http sink's status endpoint. allowed counts admissions (certificate checks,
// SCRAM logins); rejected counts every refusal.
func (p *Policy) Stats() map[string]any {
	if p == nil {
		return map[string]any{"auth": MethodNone}
	}
	d := map[string]any{
		"auth":          p.method,
		"auth_allowed":  p.allowed.Load(),
		"auth_rejected": p.rejected.Load(),
	}
	switch {
	case p.dialer != nil:
		p.dialer.stats(d)
	case p.listener != nil:
		p.listener.stats(d)
		if p.identity != "" {
			d["auth_identity"] = p.identity
		}
	default:
		d["auth_identity"] = p.identity
		d["auth_unrestricted"] = p.Unrestricted()
	}
	if p.role == RoleChainListener {
		d["node_binding"] = p.binding
	}
	return d
}
