// FILE: src/internal/tls/client.go
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// ClientManager handles TLS configuration for client components.
type ClientManager struct {
	config    *config.TLSClientConfig
	tlsConfig *tls.Config
	logger    *log.Logger
}

// NewClientManager creates a TLS manager for clients (HTTP Client Sink).
func NewClientManager(cfg *config.TLSClientConfig, logger *log.Logger) (*ClientManager, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	m := &ClientManager{
		config: cfg,
		logger: logger,
		tlsConfig: &tls.Config{
			MinVersion: parseTLSVersion(cfg.MinVersion, tls.VersionTLS12),
			MaxVersion: parseTLSVersion(cfg.MaxVersion, tls.VersionTLS13),
		},
	}

	// Cipher suite configuration
	if cfg.CipherSuites != "" {
		m.tlsConfig.CipherSuites = parseCipherSuites(cfg.CipherSuites)
	}

	// Load client certificate for mTLS, if provided.
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key: %w", err)
		}
		m.tlsConfig.Certificates = []tls.Certificate{clientCert}
	} else if cfg.ClientCertFile != "" || cfg.ClientKeyFile != "" {
		return nil, fmt.Errorf("both client_cert_file and client_key_file must be provided for mTLS")
	}

	// Load server CA for verification.
	if cfg.ServerCAFile != "" {
		caCert, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read server CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse server CA certificate")
		}
		m.tlsConfig.RootCAs = caCertPool
	}

	m.tlsConfig.InsecureSkipVerify = cfg.InsecureSkipVerify
	m.tlsConfig.ServerName = cfg.ServerName

	logger.Info("msg", "TLS Client Manager initialized", "component", "tls")
	return m, nil
}

// GetConfig returns the client's TLS configuration.
func (m *ClientManager) GetConfig() *tls.Config {
	if m == nil {
		return nil
	}
	return m.tlsConfig.Clone()
}

// GetStats returns statistics about the current client TLS configuration.
func (m *ClientManager) GetStats() map[string]any {
	if m == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled":              true,
		"min_version":          tlsVersionString(m.tlsConfig.MinVersion),
		"max_version":          tlsVersionString(m.tlsConfig.MaxVersion),
		"has_client_cert":      m.config.ClientCertFile != "",
		"has_server_ca":        m.config.ServerCAFile != "",
		"insecure_skip_verify": m.config.InsecureSkipVerify,
	}
}