package config

import (
	"testing"

	"github.com/lixenwraith/logwisp/internal/testutil"
)

func isolateConfig(t *testing.T) {
	t.Helper()
	testutil.ClearEnvPrefix(t, "LOGWISP_")
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Chdir(dir)
}
