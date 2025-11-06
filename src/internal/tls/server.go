// FILE: src/internal/tls/server.go
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"logwisp/src/internal/config"

	"github.com/lixenwraith/log"
)

// ServerManager handles TLS configuration for server components.
type ServerManager struct {
	config    *config.TLSServerConfig
	tlsConfig *tls.Config
	logger    *log.Logger
}

// NewServerManager creates a TLS manager for servers (HTTP Source/Sink).
func NewServerManager(cfg *config.TLSServerConfig, logger *log.Logger) (*ServerManager, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	m := &ServerManager{
		config: cfg,
		logger: logger,
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}

	// Enforce TLS 1.2 / TLS 1.3
	m.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   parseTLSVersion(cfg.MinVersion, tls.VersionTLS12),
		MaxVersion:   parseTLSVersion(cfg.MaxVersion, tls.VersionTLS13),
	}

	if cfg.CipherSuites != "" {
		m.tlsConfig.CipherSuites = parseCipherSuites(cfg.CipherSuites)
	} else {
		// Use secure defaults
		m.tlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
	}

	// Configure client authentication (mTLS)
	if cfg.ClientAuth {
		if cfg.ClientCAFile == "" {
			return nil, fmt.Errorf("client_auth is enabled but client_ca_file is not specified")
		}
		caCert, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}
		m.tlsConfig.ClientCAs = caCertPool
	}

	logger.Info("msg", "TLS Server Manager initialized", "component", "tls")
	return m, nil
}

// GetHTTPConfig returns a TLS configuration suitable for HTTP servers.
func (m *ServerManager) GetHTTPConfig() *tls.Config {
	if m == nil {
		return nil
	}
	cfg := m.tlsConfig.Clone()
	cfg.NextProtos = []string{"h2", "http/1.1"}
	return cfg
}

// GetStats returns statistics about the current server TLS configuration.
func (m *ServerManager) GetStats() map[string]any {
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