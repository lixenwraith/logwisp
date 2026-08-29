// Package authz turns a verified certificate into an authorization decision.
// It is the single seam between declarative auth config and the network
// plugins: each one compiles a Policy at construction and calls Authorize per
// connection (TCP) or per request (HTTP).
//
// New returns (nil, nil) when auth is disabled, mirroring tlsx.Server and
// tlsx.Client, and every method tolerates a nil receiver — so call sites read
// the same whether or not a policy is configured.
package authz

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"logwisp/internal/config"
	"logwisp/internal/tlsx"
)

// Authentication methods
const (
	MethodNone = "none"
	MethodMTLS = "mtls"
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
	// RoleListener authorizes client certificates on a plugin with no node
	// concept: the tcp and http sinks
	RoleListener Role = iota
	// RoleChainListener authorizes client certificates and binds the node
	// label a peer declares: the tcp_chain and http_chain sources
	RoleChainListener
	// RoleDialer pins the server's identity beyond hostname verification:
	// the tcp_chain and http_chain sinks
	RoleDialer
)

// Policy is the compiled form of config.AuthOptions
type Policy struct {
	role     Role
	identity string
	allow    map[string]struct{}
	patterns []*regexp.Regexp
	binding  string

	// Statistics
	allowed  atomic.Uint64
	rejected atomic.Uint64
}

// Identity is the outcome of a successful authorization. The zero value is
// what a disabled policy yields.
type Identity struct {
	Name   string // the selected certificate field
	Method string // MethodMTLS
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
// tlsOpts is the sibling `tls` block: an auth policy the transport cannot
// enforce is rejected here rather than silently accepted, which is the
// failure mode worth designing out.
func New(o *config.AuthOptions, tlsOpts *config.TLSOptions, role Role) (*Policy, error) {
	if o == nil {
		return nil, nil
	}
	switch o.Type {
	case "", MethodNone:
		return nil, nil
	case MethodMTLS:
	default:
		return nil, fmt.Errorf("auth: type %q (valid: %q, %q)", o.Type, MethodNone, MethodMTLS)
	}

	if tlsOpts == nil || !tlsOpts.Enabled {
		return nil, fmt.Errorf("auth: type %q requires tls.enabled", MethodMTLS)
	}
	if role == RoleDialer {
		// Identity from an unverified chain is a claim, not a fact
		if tlsOpts.InsecureSkipVerify {
			return nil, fmt.Errorf("auth: type %q cannot pin an identity with tls.insecure_skip_verify", MethodMTLS)
		}
	} else if !tlsOpts.ClientAuth {
		return nil, fmt.Errorf("auth: type %q requires tls.client_auth", MethodMTLS)
	}

	identity := o.Identity
	if identity == "" {
		identity = tlsx.IdentityCN
	}
	switch identity {
	case tlsx.IdentityCN, tlsx.IdentitySANDNS, tlsx.IdentitySANURI, tlsx.IdentitySANEmail:
	default:
		return nil, fmt.Errorf("auth: identity %q (valid: %q, %q, %q, %q)",
			identity, tlsx.IdentityCN, tlsx.IdentitySANDNS, tlsx.IdentitySANURI, tlsx.IdentitySANEmail)
	}

	binding := o.NodeBinding
	if role == RoleChainListener {
		if binding == "" {
			// The only setting under which a misconfigured or hostile edge
			// cannot mislabel its entries
			binding = BindingForce
		}
	} else if binding != "" && binding != BindingNone {
		return nil, fmt.Errorf("auth: node_binding %q applies only to chain sources", binding)
	} else {
		binding = BindingNone
	}
	switch binding {
	case BindingNone, BindingAssert, BindingForce:
	default:
		return nil, fmt.Errorf("auth: node_binding %q (valid: %q, %q, %q)",
			binding, BindingNone, BindingAssert, BindingForce)
	}

	p := &Policy{
		role:     role,
		identity: identity,
		binding:  binding,
		allow:    make(map[string]struct{}, len(o.Allow)),
	}
	for _, a := range o.Allow {
		if a = strings.TrimSpace(a); a != "" {
			p.allow[a] = struct{}{}
		}
	}
	for i, pat := range o.AllowPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("auth: allow_patterns[%d] %q: %w", i, pat, err)
		}
		p.patterns = append(p.patterns, re)
	}
	return p, nil
}

// Authorize extracts and checks the peer identity from a completed handshake.
// A nil policy authorizes everything and yields the zero Identity, so callers
// need no branch on whether auth is configured.
func (p *Policy) Authorize(cs *tls.ConnectionState) (Identity, error) {
	if p == nil {
		return Identity{}, nil
	}
	if cs == nil {
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("auth: peer is not on a TLS connection")
	}
	name := tlsx.PeerIdentity(*cs, p.identity)
	if name == "" {
		// An unusable identity field is a rejection, not an empty match
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("auth: peer certificate carries no %s identity", p.identity)
	}
	if !p.permits(name) {
		p.rejected.Add(1)
		return Identity{}, fmt.Errorf("auth: identity %q is not allowed", name)
	}
	p.allowed.Add(1)
	return Identity{Name: name, Method: MethodMTLS}, nil
}

// VerifyConnection is assignable to tls.Config.VerifyConnection on a dialer,
// so a server whose identity the policy rejects fails the handshake itself
// rather than after the first write. It runs after the standard chain and
// hostname checks, so the identity it reads is already verified.
func (p *Policy) VerifyConnection(cs tls.ConnectionState) error {
	_, err := p.Authorize(&cs)
	return err
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

// Unrestricted reports whether the policy admits any identity the CA vouches
// for. Constructors log this at startup: it is a deliberate default, and a
// silent one would be a footgun.
func (p *Policy) Unrestricted() bool {
	return p != nil && len(p.allow) == 0 && len(p.patterns) == 0
}

// Describe renders the policy for a startup log line
func (p *Policy) Describe() string {
	if p == nil {
		return MethodNone
	}
	scope := fmt.Sprintf("%d exact, %d pattern(s)", len(p.allow), len(p.patterns))
	if p.Unrestricted() {
		scope = "any identity issued by the configured CA"
	}
	return fmt.Sprintf("%s identity=%s allow=[%s] node_binding=%s",
		MethodMTLS, p.identity, scope, p.binding)
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
// http sink's status endpoint.
func (p *Policy) Stats() map[string]any {
	if p == nil {
		return map[string]any{"auth": MethodNone}
	}
	d := map[string]any{
		"auth":              MethodMTLS,
		"auth_identity":     p.identity,
		"auth_unrestricted": p.Unrestricted(),
		"auth_allowed":      p.allowed.Load(),
		"auth_rejected":     p.rejected.Load(),
	}
	if p.role == RoleChainListener {
		d["node_binding"] = p.binding
	}
	return d
}
