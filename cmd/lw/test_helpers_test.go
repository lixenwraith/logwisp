package main

import (
	"testing"

	"logwisp/internal/config"
	"logwisp/internal/testutil"

	"github.com/lixenwraith/log"
)

func testLogger(t *testing.T) {
	t.Helper()
	previous := logger
	logger = log.NewLogger()
	t.Cleanup(func() { logger = previous })
}

func loadTestConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	testutil.ClearEnvPrefix(t, "LOGWISP_")
	m, err := config.Load([]string{"-c", path, "--quiet", "--status_reporter=false"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	cfg, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
