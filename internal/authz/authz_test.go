package authz

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/tlsx"
)

// peerState fakes a completed handshake. Only the leaf's identity fields are
// read: the chain is verified by crypto/tls before a policy ever sees it.
func peerState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
}

func leafCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func mtlsListenerTLS() *tls.Config {
	return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}
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
		p, err := New(o, nil, nil, config.Listener, TCP)
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

// Each row is valid but for its own rule, and the error names that rule
func TestNewValidation(t *testing.T) {
	f := newFixture(t)
	pw := f.write(t, "pw", "edge-01-secret\n")
	scram := func(o config.AuthOptions) *config.AuthOptions { o.Type = MethodSCRAM; return &o }
	listener := func(o config.AuthOptions) *config.AuthOptions { o.CredentialsFile = f.creds; return scram(o) }
	proxies := []string{"127.0.0.1", "10.0.0.0/8"}
	dialer := func(o config.AuthOptions) *config.AuthOptions {
		o.Username, o.PasswordFile = "edge-01", pw
		return scram(o)
	}
	tests := []struct {
		name      string
		auth      *config.AuthOptions
		tls       *tls.Config
		role      config.Side
		transport Transport
		want      string
	}{
		{"unknown type", &config.AuthOptions{Type: "kerberos"}, mtlsListenerTLS(), config.Listener, TCP, `got "kerberos"`},
		{"allow list without a type", &config.AuthOptions{Allow: []string{"edge-01"}}, mtlsListenerTLS(), config.Listener, TCP, "allow is set"},
		{"credentials without a type", &config.AuthOptions{CredentialsFile: f.creds}, mtlsListenerTLS(), config.Listener, TCP, "credentials_file is set"},
		{"no tls", &config.AuthOptions{Type: MethodMTLS}, nil, config.Listener, TCP, "requires tls.enabled"},
		{"no client_auth", &config.AuthOptions{Type: MethodMTLS}, &tls.Config{}, config.Listener, TCP, "requires tls.client_auth"},
		{"unknown identity", &config.AuthOptions{Type: MethodMTLS, Identity: "serial"}, mtlsListenerTLS(), config.Listener, TCP, `got "serial"`},
		{"bad pattern", &config.AuthOptions{Type: MethodMTLS, AllowPatterns: []string{"^edge-("}}, mtlsListenerTLS(), config.Listener, TCP, "allow_patterns[0]"},
		{"unknown binding", &config.AuthOptions{Type: MethodMTLS, NodeBinding: "maybe"}, mtlsListenerTLS(), config.ChainListener, TCP, `got "maybe"`},
		{"binding on plain listener", &config.AuthOptions{Type: MethodMTLS, NodeBinding: BindingForce}, mtlsListenerTLS(), config.Listener, TCP, "only to chain sources"},
		{"binding on dialer", &config.AuthOptions{Type: MethodMTLS, NodeBinding: BindingForce}, &tls.Config{}, config.Dialer, TCP, "only to chain sources"},
		{"dialer skips verify", &config.AuthOptions{Type: MethodMTLS}, &tls.Config{InsecureSkipVerify: true}, config.Dialer, TCP, "insecure_skip_verify"},
		{"mtls with a password", &config.AuthOptions{Type: MethodMTLS, PasswordFile: pw}, &tls.Config{}, config.Dialer, TCP, "password_file applies only"},
		{"scram without tls", listener(config.AuthOptions{}), nil, config.Listener, TCP, "requires tls.enabled"},
		{"scram without users", scram(config.AuthOptions{}), f.serverTLS, config.Listener, TCP, "requires credentials_file, or username and password_file"},
		{"scram with an allow list", listener(config.AuthOptions{Allow: []string{"edge-01"}}), f.serverTLS, config.Listener, TCP, "the users are the allow list"},
		{"credentials and a user", listener(config.AuthOptions{Username: "edge-01"}), f.serverTLS, config.Listener, TCP, "not both"},
		{"user without password_file", scram(config.AuthOptions{Username: "edge-01"}), f.serverTLS, config.Listener, TCP, "go together"},
		{"scram certificate binding without client_auth", listener(config.AuthOptions{Identity: "cn"}), f.serverTLS, config.Listener, TCP, "requires tls.client_auth"},
		{"token lifetime on tcp", listener(config.AuthOptions{TokenLifetimeMS: 60000}), f.serverTLS, config.Listener, TCP, "only to HTTP listeners"},
		{"token lifetime too short", listener(config.AuthOptions{TokenLifetimeMS: 900}), f.serverTLS, config.Listener, HTTP, "must be from 10000 to 86400000"},
		{"token lifetime too long", listener(config.AuthOptions{TokenLifetimeMS: 1e13}), f.serverTLS, config.Listener, HTTP, "must be from 10000 to 86400000"},
		{"scram listener without a certificate", listener(config.AuthOptions{}), &tls.Config{}, config.Listener, TCP, "listener certificate"},
		{"scram dialer without a password", scram(config.AuthOptions{Username: "edge-01"}), &tls.Config{}, config.Dialer, TCP, "requires username and password_file"},
		{"scram dialer with credentials", dialer(config.AuthOptions{CredentialsFile: f.creds}), &tls.Config{}, config.Dialer, TCP, "only to listeners"},
		{"scram dialer skips verify", dialer(config.AuthOptions{}), &tls.Config{InsecureSkipVerify: true}, config.Dialer, TCP, "insecure_skip_verify"},
		{"trusted proxies without a type", &config.AuthOptions{TrustedProxies: proxies}, nil, config.Listener, HTTP, "trusted_proxies is set"},
		{"trusted proxies under mtls", &config.AuthOptions{Type: MethodMTLS, TrustedProxies: proxies}, mtlsListenerTLS(), config.Listener, HTTP, "trusted_proxies applies only"},
		{"trusted proxies on a chain source", listener(config.AuthOptions{TrustedProxies: proxies}), nil, config.ChainListener, HTTP, "only to the http sink"},
		{"trusted proxies on tcp", listener(config.AuthOptions{TrustedProxies: proxies}), nil, config.Listener, TCP, "only to the http sink"},
		{"trusted proxies with certificate binding", listener(config.AuthOptions{TrustedProxies: proxies, Identity: "cn"}), f.serverTLS, config.Listener, HTTP, "TLS-terminating proxy"},
		{"malformed trusted proxy", listener(config.AuthOptions{TrustedProxies: []string{"localhost"}}), nil, config.Listener, HTTP, "neither an address"},
		{"trusted proxies on a dialer", dialer(config.AuthOptions{TrustedProxies: proxies}), &tls.Config{}, config.Dialer, HTTP, "only to listeners"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.auth, tc.tls, nil, tc.role, tc.transport); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one naming %q", err, tc.want)
			}
		})
	}

	// The rows' bases are valid: a dialer needs TLS but not client_auth, as it
	// pins the server's identity; tls.pin_sha256 verifies in place of the chain
	pinned := &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }}
	for _, o := range []*config.AuthOptions{{Type: MethodMTLS}, dialer(config.AuthOptions{})} {
		for _, c := range []*tls.Config{{}, pinned} {
			if _, err := New(o, c, nil, config.Dialer, TCP); err != nil {
				t.Fatalf("dialer policy %s rejected: %v", o.Type, err)
			}
		}
	}
	for _, o := range []*config.AuthOptions{listener(config.AuthOptions{TokenLifetimeMS: 60000}), scram(config.AuthOptions{Username: "edge-01", PasswordFile: pw})} {
		if _, err := New(o, f.serverTLS, nil, config.Listener, HTTP); err != nil {
			t.Fatalf("scram listener rejected: %v", err)
		}
	}
	// Behind proxies TLS ends at the proxy, so the hop may be plaintext
	if _, err := New(listener(config.AuthOptions{TrustedProxies: proxies}), nil, nil, config.Listener, HTTP); err != nil {
		t.Fatalf("proxy-mode listener rejected: %v", err)
	}
}

func TestAuthorizeMatching(t *testing.T) {
	p, err := New(&config.AuthOptions{
		Type:          MethodMTLS,
		Allow:         []string{"edge-01", " edge-02 "},
		AllowPatterns: []string{`^relay-\d{2}$`},
	}, mtlsListenerTLS(), nil, config.Listener, TCP)
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
	p, err := New(&config.AuthOptions{Type: MethodMTLS}, mtlsListenerTLS(), nil, config.Listener, TCP)
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
		p, err := New(&config.AuthOptions{Type: MethodMTLS, NodeBinding: binding}, mtlsListenerTLS(), nil, config.ChainListener, TCP)
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
		&tls.Config{}, nil, config.Dialer, TCP)
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

// Only patterns whose every alternative is pinned at both ends stay silent at
// startup; "^a|b$" reads as anchored but admits "a..." and "...b".
func TestAllowPatternAnchoring(t *testing.T) {
	for pattern, want := range map[string]bool{
		`^edge-\d{2}$`:        true,
		`^(edge-01|edge-02)$`: true,
		`^edge-a$|^edge-bc$`:  true, // the parser factors this into ^edge-(?:a$|bc$)
		`\Aedge\z`:            true,
		`edge-\d{2}`:          false,
		`^a|b$`:               false,
		`^ab$|^ac`:            false,
		`^a$|`:                false,
	} {
		if got := anchored(pattern); got != want {
			t.Errorf("anchored(%q) = %v, want %v", pattern, got, want)
		}
	}
}
