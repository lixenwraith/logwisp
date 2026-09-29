// Package testutil provides standard-library fixtures shared by logwisp tests.
// Application packages must not import it.
package testutil

import (
	"os"
	"strings"
	"testing"
)

// ClearEnvPrefix isolates overrides while preserving the caller's environment.
// Like testing.Setenv, it must not be used by parallel tests.
func ClearEnvPrefix(t testing.TB, prefix string) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, prefix) {
			t.Setenv(key, value) // Register restoration before unsetting it.
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset fixture variable %s: %v", key, err)
			}
		}
	}
}

func WriteFile(t testing.TB, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write fixture %q: %v", path, err)
	}
}
