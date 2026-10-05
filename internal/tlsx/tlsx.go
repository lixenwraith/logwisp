// Package tlsx builds crypto/tls configurations from config.TLSOptions.
// It is the single seam between declarative TLS config and the stdlib;
// each network plugin calls exactly one constructor.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/log"
)

const (
	// HandshakeTimeout bounds TLS handshakes on both accept and dial paths
	HandshakeTimeout = 10 * time.Second
	// expiryWindow is how far ahead startup announces certificate expiry
	expiryWindow = 30 * 24 * time.Hour
)

// Server builds the *tls.Config for listener plugins (tcp/http sinks,
// tcp_chain/http_chain sources) from cert_file and key_file, or issues one on
// the process key: self-signed or from the issuer files, for host, hosts and
// this machine's names. Returns (nil, nil) when disabled.
func Server(o *config.TLSOptions, host string) (*tls.Config, error) {
	if o == nil || !o.Enabled {
		return nil, nil
	}
	files, issuer := o.CertFile != "" || o.KeyFile != "", o.IssuerCertFile != "" || o.IssuerKeyFile != ""
	switch {
	case o.PinSHA256 != "":
		return nil, fmt.Errorf("tls: pin_sha256 applies to dialers")
	case files && (issuer || o.SelfSigned) || issuer && o.SelfSigned:
		return nil, fmt.Errorf("tls: set one of cert_file and key_file, self_signed, or issuer_cert_file and issuer_key_file")
	case len(o.Hosts) > 0 && !issuer && !o.SelfSigned:
		return nil, fmt.Errorf("tls: hosts applies to self_signed and issuer certificates")
	case files && (o.CertFile == "" || o.KeyFile == ""):
		return nil, fmt.Errorf("tls: cert_file and key_file must be set together")
	case issuer && (o.IssuerCertFile == "" || o.IssuerKeyFile == ""):
		return nil, fmt.Errorf("tls: issuer_cert_file and issuer_key_file must be set together")
	case !files && !issuer && !o.SelfSigned:
		return nil, fmt.Errorf("tls: listeners need cert_file and key_file, self_signed, or issuer_cert_file and issuer_key_file")
	}
	var cert tls.Certificate
	var err error
	if files {
		cert, err = tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	} else {
		cert, err = generated(o.IssuerCertFile, o.IssuerKeyFile, host, o.Hosts)
	}
	if err != nil {
		return nil, fmt.Errorf("tls: load keypair: %w", err)
	}
	mv, err := minVersion(o.MinVersion)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   mv,
	}
	if o.ClientAuth {
		if o.ClientCAFile == "" {
			return nil, fmt.Errorf("tls: client_auth requires client_ca_file")
		}
		pool, err := loadPool(o.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// Client builds the *tls.Config for dialer plugins (tcp_chain/http_chain
// sinks). host seeds ServerName when no override is set; Go verifies IP SANs
// when host is an address, without its zone, which names a local interface
// and no certificate carries. pin_sha256 replaces chain and name checks.
// Returns (nil, nil) when disabled.
func Client(o *config.TLSOptions, host string) (*tls.Config, error) {
	if o == nil || !o.Enabled {
		return nil, nil
	}
	switch {
	case o.SelfSigned || o.IssuerCertFile != "" || o.IssuerKeyFile != "" || len(o.Hosts) > 0:
		return nil, fmt.Errorf("tls: self_signed, issuer_cert_file, issuer_key_file and hosts apply to listeners")
	case o.PinSHA256 != "" && (o.CAFile != "" || o.InsecureSkipVerify):
		return nil, fmt.Errorf("tls: pin_sha256 replaces ca_file and insecure_skip_verify: set one")
	}
	mv, err := minVersion(o.MinVersion)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:         mv,
		ServerName:         o.ServerName,
		InsecureSkipVerify: o.InsecureSkipVerify,
	}
	if cfg.ServerName == "" {
		cfg.ServerName, _, _ = strings.Cut(host, "%")
	}
	if o.PinSHA256 != "" {
		if cfg.VerifyPeerCertificate, err = verifyPins(o.PinSHA256); err != nil {
			return nil, err
		}
		// The pin check replaces Go's; Go skips it on a resumed session, so a
		// pinned dialer never resumes, and a pin dropped by a reload holds
		cfg.InsecureSkipVerify, cfg.SessionTicketsDisabled = true, true
	}
	if o.CAFile != "" {
		pool, err := loadPool(o.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if (o.CertFile == "") != (o.KeyFile == "") {
		return nil, fmt.Errorf("tls: cert_file and key_file must be set together")
	}
	if o.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// Identity modes for PeerIdentity, mirroring the auth.identity config values.
// Validity is enforced at policy construction in internal/authz.
const (
	IdentityCN       = "cn"
	IdentitySANDNS   = "san_dns"
	IdentitySANURI   = "san_uri"
	IdentitySANEmail = "san_email"
)

// PeerCN returns the subject CN of the verified peer leaf, "" if none
func PeerCN(cs tls.ConnectionState) string {
	return PeerIdentity(cs, IdentityCN)
}

// PeerIdentity returns the field named by mode from the verified peer leaf,
// "" when the certificate does not carry it or mode is unknown. The chain,
// signature, and validity window are already checked by the handshake, so
// this is pure field selection.
func PeerIdentity(cs tls.ConnectionState, mode string) string {
	if len(cs.PeerCertificates) == 0 {
		return ""
	}
	leaf := cs.PeerCertificates[0]
	switch mode {
	case "", IdentityCN:
		return leaf.Subject.CommonName
	case IdentitySANDNS:
		if len(leaf.DNSNames) > 0 {
			return leaf.DNSNames[0]
		}
	case IdentitySANURI:
		if len(leaf.URIs) > 0 {
			return leaf.URIs[0].String()
		}
	case IdentitySANEmail:
		if len(leaf.EmailAddresses) > 0 {
			return leaf.EmailAddresses[0]
		}
	}
	return ""
}

// LogWarnings reports TLS settings that work but are likely mistakes, once per
// plugin construction, so each reload re-announces expiring certificates.
func LogWarnings(l *log.Logger, component, id string, o *config.TLSOptions, listener bool) {
	if o == nil || !o.Enabled {
		return
	}
	if key, err := processKey(); listener && o.SelfSigned && err == nil {
		// Without a CA, a dialer verifies this listener by its pin only
		l.Warn("msg", "Serving a self-signed certificate; it changes when lw restarts",
			"component", component,
			"instance_id", id,
			"pin_sha256", pinOfKey(key),
			"hint", "dialers set tls.pin_sha256; for a stable identity use issuer_cert_file or cert_file")
	}
	var warnings []string
	if !listener && o.InsecureSkipVerify {
		warnings = append(warnings, "tls.insecure_skip_verify disables server verification: any peer can impersonate the server")
	}
	type file struct{ key, path string }
	files := []file{{"cert_file", o.CertFile}, {"ca_file", o.CAFile}}
	if listener {
		files = []file{{"cert_file", o.CertFile}, {"client_ca_file", o.ClientCAFile}, {"issuer_cert_file", o.IssuerCertFile}}
	}
	now := time.Now()
	for _, f := range files {
		for _, c := range readCerts(f.path) {
			if w := expiryWarning(c, now); w != "" {
				warnings = append(warnings, fmt.Sprintf("tls.%s %s: %s", f.key, f.path, w))
			}
		}
	}
	for _, key := range []file{{"tls.key_file", o.KeyFile}, {"tls.issuer_key_file", o.IssuerKeyFile}} {
		if w := SecretFileWarning(key.key, key.path); w != "" {
			warnings = append(warnings, w)
		}
	}
	for _, w := range warnings {
		l.Warn("msg", w, "component", component, "instance_id", id)
	}
}

// expiryWarning describes a certificate outside, or about to leave, its
// validity window; a handshake failure is otherwise the first sign.
func expiryWarning(c *x509.Certificate, now time.Time) string {
	name := c.Subject.CommonName
	switch {
	case now.After(c.NotAfter):
		return fmt.Sprintf("certificate %q expired on %s", name, c.NotAfter.UTC().Format(time.DateOnly))
	case now.Before(c.NotBefore):
		return fmt.Sprintf("certificate %q is not valid until %s", name, c.NotBefore.UTC().Format(time.DateTime))
	case c.NotAfter.Sub(now) < expiryWindow:
		return fmt.Sprintf("certificate %q expires on %s", name, c.NotAfter.UTC().Format(time.DateOnly))
	}
	return ""
}

// readCerts parses every certificate in a PEM file. Constructors already
// loaded it successfully, so an unreadable file yields nothing here.
func readCerts(path string) []*x509.Certificate {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var certs []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	return certs
}

// warnedSecrets keeps reloads from repeating a permission warning per path
var warnedSecrets sync.Map

// SecretFileWarning describes a secret file every local user can read, once
// per path per process. Group access is left alone: container secret mounts
// commonly grant it on purpose.
func SecretFileWarning(key, path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o004 == 0 {
		return ""
	}
	if _, seen := warnedSecrets.LoadOrStore(path, struct{}{}); seen {
		return ""
	}
	return fmt.Sprintf("%s %s is readable by all users (mode %04o)", key, path, fi.Mode().Perm())
}

// HTTPErrorLog adapts the structured logger for http.Server.ErrorLog so TLS
// handshake failures don't bypass log routing straight to stderr (which would
// violate the console sanitization policy).
func HTTPErrorLog(l *log.Logger, component string) *stdlog.Logger {
	return stdlog.New(errLogWriter{l: l, component: component}, "", 0)
}

type errLogWriter struct {
	l         *log.Logger
	component string
}

func (w errLogWriter) Write(p []byte) (int, error) {
	w.l.Warn("msg", strings.TrimSpace(string(p)), "component", w.component)
	return len(p), nil
}

func loadPool(file string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("tls: no certificates found in %s", file)
	}
	return pool, nil
}

func minVersion(s string) (uint16, error) {
	switch s {
	case "", "1.3":
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("tls: min_version %q (valid: \"1.2\", \"1.3\")", s)
	}
}
