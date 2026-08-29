package authz

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"logwisp/internal/config"
	"logwisp/internal/tlsx"
)

// peerState fakes a completed handshake. Only the leaf's identity fields are
// read: the chain is verified by crypto/tls before a policy ever sees it.
func peerState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
}

func leafCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func mtlsListenerTLS() *config.TLSOptions {
	return &config.TLSOptions{Enabled: true, ClientAuth: true}
}

func TestPeerIdentityModes(t *testing.T) {
	uri, err := url.Parse("spiffe://example.org/edge-01")
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	leaf := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "edge-01"},
		DNSNames:       []string{"edge-01.internal", "alt.internal"},
		URIs:           []*url.URL{uri},
		EmailAddresses: []string{"ops@example.org"},
	}
	cs := peerState(leaf)

	cases := map[string]string{
		tlsx.IdentityCN:       "edge-01",
		tlsx.IdentitySANDNS:   "edge-01.internal",
		tlsx.IdentitySANURI:   "spiffe://example.org/edge-01",
		tlsx.IdentitySANEmail: "ops@example.org",
		"":                    "edge-01", // empty mode defaults to CN
		"nonsense":            "",
	}
	for mode, want := range cases {
		if got := tlsx.PeerIdentity(*cs, mode); got != want {
			t.Errorf("PeerIdentity(%q) = %q, want %q", mode, got, want)
		}
	}

	// A mode the certificate does not carry yields no identity
	bare := peerState(leafCN("edge-01"))
	if got := tlsx.PeerIdentity(*bare, tlsx.IdentitySANDNS); got != "" {
		t.Errorf("PeerIdentity(san_dns) on bare cert = %q, want empty", got)
	}
	// No peer certificate at all
	if got := tlsx.PeerIdentity(tls.ConnectionState{}, tlsx.IdentityCN); got != "" {
		t.Errorf("PeerIdentity with no peer certs = %q, want empty", got)
	}
}

func TestNewDisabled(t *testing.T) {
	for _, o := range []*config.AuthOptions{nil, {}, {Type: MethodNone}} {
		p, err := New(o, nil, RoleListener)
		if err != nil {
			t.Fatalf("New(%+v) error: %v", o, err)
		}
		if p != nil {
			t.Fatalf("New(%+v) = %v, want nil policy", o, p)
		}
	}
}

// A nil policy must behave as if auth were never configured
func TestNilPolicyIsTransparent(t *testing.T) {
	var p *Policy
	id, err := p.Authorize(nil)
	if err != nil || id.Name != "" {
		t.Fatalf("nil Authorize = (%+v, %v), want (zero, nil)", id, err)
	}
	if p.Enabled() || p.BindsNode() || p.Unrestricted() {
		t.Fatal("nil policy reports itself active")
	}
	if p.NodeBinding() != BindingNone {
		t.Fatalf("nil NodeBinding = %q", p.NodeBinding())
	}
	if !p.TrustsEntryNode(true) || p.TrustsEntryNode(false) {
		t.Fatal("nil policy must defer to trust_node")
	}
	// trust_node semantics are unchanged without a policy
	node, err := p.ResolveNode("edge-01", "10.0.0.5", true, Identity{})
	if err != nil || node != "edge-01" {
		t.Fatalf("nil ResolveNode(trust) = (%q, %v), want edge-01", node, err)
	}
	node, err = p.ResolveNode("edge-01", "10.0.0.5", false, Identity{})
	if err != nil || node != "10.0.0.5" {
		t.Fatalf("nil ResolveNode(no trust) = (%q, %v), want 10.0.0.5", node, err)
	}
	node, err = p.ResolveNode("", "10.0.0.5", true, Identity{})
	if err != nil || node != "10.0.0.5" {
		t.Fatalf("nil ResolveNode(no label) = (%q, %v), want 10.0.0.5", node, err)
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		auth *config.AuthOptions
		tls  *config.TLSOptions
		role Role
	}{
		{"unknown type", &config.AuthOptions{Type: "kerberos"}, mtlsListenerTLS(), RoleListener},
		{"no tls", &config.AuthOptions{Type: MethodMTLS}, nil, RoleListener},
		{"tls disabled", &config.AuthOptions{Type: MethodMTLS}, &config.TLSOptions{}, RoleListener},
		{"no client_auth", &config.AuthOptions{Type: MethodMTLS}, &config.TLSOptions{Enabled: true}, RoleListener},
		{"unknown identity", &config.AuthOptions{Type: MethodMTLS, Identity: "serial"}, mtlsListenerTLS(), RoleListener},
		{"bad pattern", &config.AuthOptions{Type: MethodMTLS, AllowPatterns: []string{"^edge-("}}, mtlsListenerTLS(), RoleListener},
		{"unknown binding", &config.AuthOptions{Type: MethodMTLS, NodeBinding: "maybe"}, mtlsListenerTLS(), RoleChainListener},
		{"binding on plain listener", &config.AuthOptions{Type: MethodMTLS, NodeBinding: BindingForce}, mtlsListenerTLS(), RoleListener},
		{"binding on dialer", &config.AuthOptions{Type: MethodMTLS, NodeBinding: BindingForce}, &config.TLSOptions{Enabled: true}, RoleDialer},
		{"dialer skips verify", &config.AuthOptions{Type: MethodMTLS}, &config.TLSOptions{Enabled: true, InsecureSkipVerify: true}, RoleDialer},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.auth, tc.tls, tc.role); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}

	// A dialer needs TLS but not client_auth: it pins the server's identity
	if _, err := New(&config.AuthOptions{Type: MethodMTLS}, &config.TLSOptions{Enabled: true}, RoleDialer); err != nil {
		t.Fatalf("dialer policy rejected: %v", err)
	}
}

func TestAuthorizeMatching(t *testing.T) {
	p, err := New(&config.AuthOptions{
		Type:          MethodMTLS,
		Allow:         []string{"edge-01", " edge-02 "},
		AllowPatterns: []string{`^relay-\d{2}$`},
	}, mtlsListenerTLS(), RoleListener)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Unrestricted() {
		t.Fatal("policy with an allow list reports unrestricted")
	}

	allowed := []string{"edge-01", "edge-02", "relay-07"}
	for _, cn := range allowed {
		id, err := p.Authorize(peerState(leafCN(cn)))
		if err != nil {
			t.Errorf("Authorize(%q): %v", cn, err)
			continue
		}
		if id.Name != cn || id.Method != MethodMTLS {
			t.Errorf("Authorize(%q) = %+v", cn, id)
		}
	}

	denied := []string{"edge-99", "relay-007", "prefix-relay-07", "", "EDGE-01"}
	for _, cn := range denied {
		if _, err := p.Authorize(peerState(leafCN(cn))); err == nil {
			t.Errorf("Authorize(%q) allowed, want rejection", cn)
		}
	}

	if got, want := p.Rejected(), uint64(len(denied)); got != want {
		t.Errorf("Rejected = %d, want %d", got, want)
	}
	stats := p.Stats()
	if stats["auth_allowed"].(uint64) != uint64(len(allowed)) {
		t.Errorf("auth_allowed = %v, want %d", stats["auth_allowed"], len(allowed))
	}
	if _, ok := stats["node_binding"]; ok {
		t.Error("plain listener stats report node_binding")
	}
}

// Empty allow and allow_patterns admits any CA-vouched identity, but still
// records it and still refuses a certificate with no usable identity field
func TestAuthorizeUnrestricted(t *testing.T) {
	p, err := New(&config.AuthOptions{Type: MethodMTLS}, mtlsListenerTLS(), RoleListener)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !p.Unrestricted() {
		t.Fatal("empty allow list should be unrestricted")
	}
	id, err := p.Authorize(peerState(leafCN("anyone")))
	if err != nil || id.Name != "anyone" {
		t.Fatalf("Authorize = (%+v, %v)", id, err)
	}
	if _, err := p.Authorize(peerState(leafCN(""))); err == nil {
		t.Error("certificate with no CN was authorized")
	}
	if _, err := p.Authorize(&tls.ConnectionState{}); err == nil {
		t.Error("connection with no peer certificate was authorized")
	}
	if _, err := p.Authorize(nil); err == nil {
		t.Error("non-TLS connection was authorized")
	}
}

func TestResolveNodeBindings(t *testing.T) {
	newChain := func(binding string) *Policy {
		p, err := New(&config.AuthOptions{Type: MethodMTLS, NodeBinding: binding}, mtlsListenerTLS(), RoleChainListener)
		if err != nil {
			t.Fatalf("New(%q): %v", binding, err)
		}
		return p
	}
	id := Identity{Name: "edge-01", Method: MethodMTLS}

	// Default under mtls is force
	if got := newChain("").NodeBinding(); got != BindingForce {
		t.Errorf("default node_binding = %q, want %q", got, BindingForce)
	}

	// force ignores the declared label, however it was spoofed
	force := newChain(BindingForce)
	for _, declared := range []string{"edge-99", "", "edge-01"} {
		node, err := force.ResolveNode(declared, "10.0.0.5", true, id)
		if err != nil || node != "edge-01" {
			t.Errorf("force ResolveNode(%q) = (%q, %v), want edge-01", declared, node, err)
		}
	}
	if force.TrustsEntryNode(true) {
		t.Error("force must not trust per-entry node labels")
	}

	// assert rejects a mismatch and an omission, and leaves per-entry labels
	// alone so a relay can forward other nodes' entries
	assert := newChain(BindingAssert)
	node, err := assert.ResolveNode("edge-01", "10.0.0.5", true, id)
	if err != nil || node != "edge-01" {
		t.Errorf("assert ResolveNode(match) = (%q, %v)", node, err)
	}
	if _, err := assert.ResolveNode("edge-99", "10.0.0.5", true, id); err == nil {
		t.Error("assert accepted a mismatched node label")
	}
	if _, err := assert.ResolveNode("", "10.0.0.5", true, id); err == nil {
		t.Error("assert accepted a missing node label")
	}
	if !assert.TrustsEntryNode(true) || assert.TrustsEntryNode(false) {
		t.Error("assert must leave per-entry node labels to trust_node")
	}

	// none leaves trust_node governing entirely
	none := newChain(BindingNone)
	if none.BindsNode() {
		t.Error("node_binding none should not bind")
	}
	node, err = none.ResolveNode("edge-99", "10.0.0.5", true, id)
	if err != nil || node != "edge-99" {
		t.Errorf("none ResolveNode = (%q, %v), want edge-99", node, err)
	}
	node, err = none.ResolveNode("edge-99", "10.0.0.5", false, id)
	if err != nil || node != "10.0.0.5" {
		t.Errorf("none ResolveNode(no trust) = (%q, %v), want 10.0.0.5", node, err)
	}

	// Binding without an authenticated identity is a refusal, not a fallback
	if _, err := force.ResolveNode("edge-01", "10.0.0.5", true, Identity{}); err == nil {
		t.Error("force resolved a node without an identity")
	}
}

func TestIdentityApply(t *testing.T) {
	meta := map[string]any{"type": "tcp_chain"}
	Identity{}.Apply(meta)
	if len(meta) != 1 {
		t.Fatalf("zero identity stamped metadata: %v", meta)
	}
	Identity{Name: "edge-01", Method: MethodMTLS}.Apply(meta)
	if meta["auth_identity"] != "edge-01" || meta["auth_method"] != MethodMTLS {
		t.Fatalf("metadata = %v", meta)
	}
}

func TestVerifyConnectionPinsServer(t *testing.T) {
	p, err := New(&config.AuthOptions{Type: MethodMTLS, Allow: []string{"relay.internal"}},
		&config.TLSOptions{Enabled: true}, RoleDialer)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.VerifyConnection(*peerState(leafCN("relay.internal"))); err != nil {
		t.Errorf("pinned server rejected: %v", err)
	}
	if err := p.VerifyConnection(*peerState(leafCN("impostor.internal"))); err == nil {
		t.Error("unpinned server accepted")
	}
}
