package tlsx

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"logwisp/internal/config"
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
