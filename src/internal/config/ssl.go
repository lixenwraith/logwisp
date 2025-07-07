// FILE: src/internal/config/ssl.go
package config

type SSLConfig struct {
	Enabled  bool   `toml:"enabled"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`

	// Client certificate authentication
	ClientAuth       bool   `toml:"client_auth"`
	ClientCAFile     string `toml:"client_ca_file"`
	VerifyClientCert bool   `toml:"verify_client_cert"`

	// TLS version constraints
	MinVersion string `toml:"min_version"` // "TLS1.2", "TLS1.3"
	MaxVersion string `toml:"max_version"`

	// Cipher suites (comma-separated list)
	CipherSuites string `toml:"cipher_suites"`
}