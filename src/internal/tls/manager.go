// FILE: logwisp/src/internal/tls/manager.go
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// Manager handles TLS configuration for servers
type Manager struct {
	config    *config.TLSConfig
	tlsConfig *tls.Config
	logger    *log.Logger
}

// NewManager creates a TLS configuration from TLS config
func NewManager(cfg *config.TLSConfig, logger *log.Logger) (*Manager, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	m := &Manager{
		config: cfg,
		logger: logger,
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert/key: %w", err)
	}

	// Create base TLS config
	m.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   parseTLSVersion(cfg.MinVersion, tls.VersionTLS12),
		MaxVersion:   parseTLSVersion(cfg.MaxVersion, tls.VersionTLS13),
	}

	// Configure cipher suites if specified
	if cfg.CipherSuites != "" {
		m.tlsConfig.CipherSuites = parseCipherSuites(cfg.CipherSuites)
	} else {
		// Use secure defaults
		m.tlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	}

	// Configure client authentication (mTLS)
	if cfg.ClientAuth {
		if cfg.VerifyClientCert {
			m.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			m.tlsConfig.ClientAuth = tls.RequireAnyClientCert
		}

		// Load client CA if specified
		if cfg.ClientCAFile != "" {
			caCert, err := os.ReadFile(cfg.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read client CA: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse client CA certificate")
			}
			m.tlsConfig.ClientCAs = caCertPool
		}
	}

	// Set secure defaults
	m.tlsConfig.SessionTicketsDisabled = false
	m.tlsConfig.Renegotiation = tls.RenegotiateNever

	logger.Info("msg", "TLS manager initialized",
		"component", "tls",
		"min_version", cfg.MinVersion,
		"max_version", cfg.MaxVersion,
		"client_auth", cfg.ClientAuth,
		"cipher_count", len(m.tlsConfig.CipherSuites))

	return m, nil
}

// GetConfig returns the TLS configuration
func (m *Manager) GetConfig() *tls.Config {
	if m == nil {
		return nil
	}
	// Return a clone to prevent modification
	return m.tlsConfig.Clone()
}

// GetHTTPConfig returns TLS config suitable for HTTP servers
func (m *Manager) GetHTTPConfig() *tls.Config {
	if m == nil {
		return nil
	}

	cfg := m.tlsConfig.Clone()
	// Enable HTTP/2
	cfg.NextProtos = []string{"h2", "http/1.1"}
	return cfg
}

// GetTCPConfig returns TLS config for raw TCP connections
func (m *Manager) GetTCPConfig() *tls.Config {
	if m == nil {
		return nil
	}

	cfg := m.tlsConfig.Clone()
	// No ALPN for raw TCP
	cfg.NextProtos = nil
	return cfg
}

// ValidateClientCert validates a client certificate for mTLS
func (m *Manager) ValidateClientCert(rawCerts [][]byte) error {
	if m == nil || !m.config.ClientAuth {
		return nil
	}

	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	// Verify against CA if configured
	if m.tlsConfig.ClientCAs != nil {
		opts := x509.VerifyOptions{
			Roots:         m.tlsConfig.ClientCAs,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		// Add any intermediate certs
		for i := 1; i < len(rawCerts); i++ {
			intermediate, err := x509.ParseCertificate(rawCerts[i])
			if err != nil {
				continue
			}
			opts.Intermediates.AddCert(intermediate)
		}

		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("client certificate verification failed: %w", err)
		}
	}

	m.logger.Debug("msg", "Client certificate validated",
		"component", "tls",
		"subject", cert.Subject.String(),
		"serial", cert.SerialNumber.String())

	return nil
}

func parseTLSVersion(version string, defaultVersion uint16) uint16 {
	switch strings.ToUpper(version) {
	case "TLS1.0", "TLS10":
		return tls.VersionTLS10
	case "TLS1.1", "TLS11":
		return tls.VersionTLS11
	case "TLS1.2", "TLS12":
		return tls.VersionTLS12
	case "TLS1.3", "TLS13":
		return tls.VersionTLS13
	default:
		return defaultVersion
	}
}

func parseCipherSuites(suites string) []uint16 {
	var result []uint16

	// Map of cipher suite names to IDs
	suiteMap := map[string]uint16{
		// TLS 1.2 ECDHE suites (preferred)
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

		// RSA suites (less preferred)
		"TLS_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}

	for _, suite := range strings.Split(suites, ",") {
		suite = strings.TrimSpace(suite)
		if id, ok := suiteMap[suite]; ok {
			result = append(result, id)
		}
	}

	return result
}

// GetStats returns TLS statistics
func (m *Manager) GetStats() map[string]any {
	if m == nil {
		return map[string]any{"enabled": false}
	}

	return map[string]any{
		"enabled":       true,
		"min_version":   tlsVersionString(m.tlsConfig.MinVersion),
		"max_version":   tlsVersionString(m.tlsConfig.MaxVersion),
		"client_auth":   m.config.ClientAuth,
		"cipher_suites": len(m.tlsConfig.CipherSuites),
	}
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}