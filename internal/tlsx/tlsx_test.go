package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/testutil"
)

// A dialer verifies an IPv6 target by its address: the zone names a local
// interface, which no certificate carries.
func TestClientServerNameDropsTheZone(t *testing.T) {
	for host, want := range map[string]string{"fe80::1%eth0": "fe80::1", "::1": "::1", "relay.example": "relay.example"} {
		cfg, err := Client(&config.TLSOptions{Enabled: true}, host)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServerName != want {
			t.Errorf("Client(%q).ServerName = %q, want %q", host, cfg.ServerName, want)
		}
	}
}

// Startup names a certificate outside its validity window or within 30 days
// of leaving it; a healthy one stays silent.
func TestExpiryWarning(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cert := func(from, until time.Duration) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: "relay"}, NotBefore: now.Add(from), NotAfter: now.Add(until)}
	}
	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"valid", cert(-day, 90*day), ""},
		{"expiring", cert(-day, 10*day), "expires on 2026-10-11"},
		{"expired", cert(-90*day, -day), "expired on 2026-09-30"},
		{"not yet valid", cert(day, 90*day), "not valid until"},
	} {
		got := expiryWarning(tc.cert, now)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("%s: warning = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A self-signed listener is verified by the pin of the process key, which a
// reload's reissued certificate keeps; any other pin, or none, fails.
func TestSelfSignedListenerIsVerifiedByItsPin(t *testing.T) {
	o := &config.TLSOptions{Enabled: true, SelfSigned: true, Hosts: []string{"agg.example"}}
	first, err := Server(o, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := Server(o, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	leaf := reloaded.Certificates[0].Leaf
	pin := PinSHA256(leaf)
	if PinSHA256(first.Certificates[0].Leaf) != pin || !slices.Contains(leaf.DNSNames, "agg.example") ||
		!slices.Contains(leaf.DNSNames, "localhost") || slices.ContainsFunc(leaf.IPAddresses, net.IP.IsUnspecified) {
		t.Fatalf("pin %s, names %v %v", pin, leaf.DNSNames, leaf.IPAddresses)
	}
	other := "sha256//" + strings.Repeat("A", 43) + "="
	for pins, want := range map[string]string{other + "; " + pin: "", other: "matches no tls.pin_sha256", "": "certificate"} {
		client, err := Client(&config.TLSOptions{Enabled: true, PinSHA256: pins}, "agg.example")
		if err != nil {
			t.Fatal(err)
		}
		err = testutil.Handshake(t, reloaded, client)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("pins %q: %v, want %q", pins, err, want)
		}
	}
}

// Go skips the pin check on a resumed session, so a pinned dialer never
// resumes one, even given a session cache
func TestPinnedDialerNeverResumes(t *testing.T) {
	server, err := Server(&config.TLSOptions{Enabled: true, SelfSigned: true}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	client, err := Client(&config.TLSOptions{Enabled: true, PinSHA256: PinSHA256(server.Certificates[0].Leaf)}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	client.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			tconn := tls.Server(conn, server)
			tconn.Write([]byte{1}) // after the handshake and its session ticket
			tconn.Close()
		}
	}()
	for i := range 2 {
		conn, err := tls.Dial("tcp4", ln.Addr().String(), client)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 1)) // stores a ticket, if one came
		resumed := conn.ConnectionState().DidResume
		conn.Close()
		if err != nil || resumed {
			t.Fatalf("connection %d: resumed %v, %v", i+1, resumed, err)
		}
	}
}

// An issuer-signed listener chains to the CA file, for its host, and expires
// with its issuer; a certificate that is no CA cannot issue.
func TestIssuedListenerCertificateChainsToTheIssuer(t *testing.T) {
	dir := t.TempDir()
	ca, key, err := NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	caFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	testutil.WriteFile(t, caFile, string(EncodeCert(ca)))
	testutil.WriteFile(t, keyFile, string(keyPEM))
	server, err := Server(&config.TLSOptions{Enabled: true, IssuerCertFile: caFile, IssuerKeyFile: keyFile}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if leaf := server.Certificates[0].Leaf; !leaf.NotAfter.Equal(ca.NotAfter) {
		t.Fatalf("leaf expires %s, issuer %s", leaf.NotAfter, ca.NotAfter)
	}
	client, err := Client(&config.TLSOptions{Enabled: true, CAFile: caFile}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := testutil.Handshake(t, server, client); err != nil {
		t.Fatalf("issued chain: %v", err)
	}
	leafFile := filepath.Join(dir, "leaf.crt")
	testutil.WriteFile(t, leafFile, string(EncodeCert(server.Certificates[0].Leaf)))
	if _, err := Server(&config.TLSOptions{Enabled: true, IssuerCertFile: leafFile, IssuerKeyFile: keyFile}, ""); err == nil {
		t.Fatal("a leaf issued certificates")
	}
}

// Each role takes one source of trust and one certificate source; keys of the
// other role fail instead of doing nothing.
func TestTLSOptionConflicts(t *testing.T) {
	pin := "sha256//" + strings.Repeat("A", 43) + "="
	for _, c := range []struct {
		o      config.TLSOptions
		server bool
		want   string
	}{
		{config.TLSOptions{SelfSigned: true, CertFile: "c", KeyFile: "k"}, true, "set one of"},
		{config.TLSOptions{SelfSigned: true, IssuerCertFile: "c"}, true, "set one of"},
		{config.TLSOptions{IssuerCertFile: "c"}, true, "must be set together"},
		{config.TLSOptions{CertFile: "c"}, true, "must be set together"},
		{config.TLSOptions{Hosts: []string{"a"}, CertFile: "c", KeyFile: "k"}, true, "hosts applies to"},
		{config.TLSOptions{SelfSigned: true, PinSHA256: pin}, true, "apply to dialers"},
		{config.TLSOptions{SelfSigned: true, CAFile: "ca"}, true, "apply to dialers"},
		{config.TLSOptions{}, true, "listeners need"},
		{config.TLSOptions{SelfSigned: true}, false, "apply to listeners"},
		{config.TLSOptions{ClientAuth: true, ClientCAFile: "ca"}, false, "apply to listeners"},
		{config.TLSOptions{PinSHA256: pin, CAFile: "ca"}, false, "set one"},
		{config.TLSOptions{PinSHA256: pin, InsecureSkipVerify: true}, false, "set one"},
		{config.TLSOptions{PinSHA256: "sha256//short"}, false, "want sha256//BASE64"},
	} {
		c.o.Enabled = true
		var err error
		if c.server {
			_, err = Server(&c.o, "")
		} else {
			_, err = Client(&c.o, "host")
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.o, err, c.want)
		}
	}
}
