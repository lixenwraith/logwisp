package main

import (
	"slices"
	"testing"
)

// A plugin's details map is spread into its status line: auth and TLS
// rejection counters live there and would otherwise never be reported.
func TestStatusLineCarriesPluginDetails(t *testing.T) {
	fields := statsFields("Pipeline sources", "in", map[string]any{
		"id":      "in",
		"details": map[string]any{"auth_rejected": uint64(3), "tls_handshake_errors": uint64(1)},
	})
	for _, key := range []string{"auth_rejected", "tls_handshake_errors"} {
		if !slices.Contains(fields, any(key)) {
			t.Errorf("status fields lack %s: %v", key, fields)
		}
	}
}
