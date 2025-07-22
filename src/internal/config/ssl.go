// FILE: logwisp/src/internal/config/ssl.go
package config

import "fmt"

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

func validateSSLOptions(serverType, pipelineName string, sinkIndex int, ssl map[string]any) error {
	if enabled, ok := ssl["enabled"].(bool); ok && enabled {
		certFile, certOk := ssl["cert_file"].(string)
		keyFile, keyOk := ssl["key_file"].(string)

		if !certOk || certFile == "" || !keyOk || keyFile == "" {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: SSL enabled but cert/key files not specified",
				pipelineName, sinkIndex, serverType)
		}

		if clientAuth, ok := ssl["client_auth"].(bool); ok && clientAuth {
			if caFile, ok := ssl["client_ca_file"].(string); !ok || caFile == "" {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: client auth enabled but CA file not specified",
					pipelineName, sinkIndex, serverType)
			}
		}

		// Validate TLS versions
		validVersions := map[string]bool{"TLS1.0": true, "TLS1.1": true, "TLS1.2": true, "TLS1.3": true}
		if minVer, ok := ssl["min_version"].(string); ok && minVer != "" {
			if !validVersions[minVer] {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: invalid min TLS version: %s",
					pipelineName, sinkIndex, serverType, minVer)
			}
		}
		if maxVer, ok := ssl["max_version"].(string); ok && maxVer != "" {
			if !validVersions[maxVer] {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: invalid max TLS version: %s",
					pipelineName, sinkIndex, serverType, maxVer)
			}
		}
	}
	return nil
}