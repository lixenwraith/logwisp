// Package tlsx builds crypto/tls configurations from config.TLSOptions.
// It is the single seam between declarative TLS config and the stdlib;
// each network plugin calls exactly one constructor.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"time"

	"logwisp/internal/config"

	"github.com/lixenwraith/log"
)

// HandshakeTimeout bounds TLS handshakes on both accept and dial paths
const HandshakeTimeout = 10 * time.Second

// Server builds the *tls.Config for listener plugins
// (tcp/http sinks, tcp_chain/http_chain sources). Returns (nil, nil) when disabled.
func Server(o *config.TLSOptions) (*tls.Config, error) {
	if o == nil || !o.Enabled {
		return nil, nil
	}
	if o.CertFile == "" || o.KeyFile == "" {
		return nil, fmt.Errorf("tls: cert_file and key_file are required for listeners")
	}
	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
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
// when host is an address. Returns (nil, nil) when disabled.
func Client(o *config.TLSOptions, host string) (*tls.Config, error) {
	if o == nil || !o.Enabled {
		return nil, nil
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
		cfg.ServerName = host
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
