// FILE: logwisp/src/internal/tls/parse.go
package tls

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// parseTLSVersion converts a string representation (e.g., "TLS1.2") into a Go crypto/tls constant.
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

// parseCipherSuites converts a comma-separated string of cipher suite names into a slice of Go constants.
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

		// RSA suites
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

// tlsVersionString converts a Go crypto/tls version constant back into a string representation.
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