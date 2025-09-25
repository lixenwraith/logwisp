// FILE: logwisp/src/internal/config/tls.go
package config

import (
	"fmt"
	"os"
)

type TLSConfig struct {
	Enabled  bool   `toml:"enabled"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`

	// Client certificate authentication
	ClientAuth       bool   `toml:"client_auth"`
	ClientCAFile     string `toml:"client_ca_file"`
	VerifyClientCert bool   `toml:"verify_client_cert"`

	// Option to skip verification for clients
	InsecureSkipVerify bool `toml:"insecure_skip_verify"`

	// CA file for client to trust specific server certificates
	CAFile string `toml:"ca_file"`

	// TLS version constraints
	MinVersion string `toml:"min_version"` // "TLS1.2", "TLS1.3"
	MaxVersion string `toml:"max_version"`

	// Cipher suites (comma-separated list)
	CipherSuites string `toml:"cipher_suites"`
}

func validateTLSOptions(serverType, pipelineName string, sinkIndex int, tls map[string]any) error {
	if enabled, ok := tls["enabled"].(bool); ok && enabled {
		certFile, certOk := tls["cert_file"].(string)
		keyFile, keyOk := tls["key_file"].(string)

		if !certOk || certFile == "" || !keyOk || keyFile == "" {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: TLS enabled but cert/key files not specified",
				pipelineName, sinkIndex, serverType)
		}

		// Validate that certificate files exist and are readable
		if _, err := os.Stat(certFile); err != nil {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: cert_file is not accessible: %w",
				pipelineName, sinkIndex, serverType, err)
		}
		if _, err := os.Stat(keyFile); err != nil {
			return fmt.Errorf("pipeline '%s' sink[%d] %s: key_file is not accessible: %w",
				pipelineName, sinkIndex, serverType, err)
		}

		if clientAuth, ok := tls["client_auth"].(bool); ok && clientAuth {
			caFile, caOk := tls["client_ca_file"].(string)
			if !caOk || caFile == "" {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: client auth enabled but CA file not specified",
					pipelineName, sinkIndex, serverType)
			}
			// Validate that the client CA file exists and is readable
			if _, err := os.Stat(caFile); err != nil {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: client_ca_file is not accessible: %w",
					pipelineName, sinkIndex, serverType, err)
			}
		}

		// Validate TLS versions
		validVersions := map[string]bool{"TLS1.0": true, "TLS1.1": true, "TLS1.2": true, "TLS1.3": true}
		if minVer, ok := tls["min_version"].(string); ok && minVer != "" {
			if !validVersions[minVer] {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: invalid min TLS version: %s",
					pipelineName, sinkIndex, serverType, minVer)
			}
		}
		if maxVer, ok := tls["max_version"].(string); ok && maxVer != "" {
			if !validVersions[maxVer] {
				return fmt.Errorf("pipeline '%s' sink[%d] %s: invalid max TLS version: %s",
					pipelineName, sinkIndex, serverType, maxVer)
			}
		}
	}
	return nil
}