package main

import (
	"bytes"
	"testing"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/testutil"

	"github.com/lixenwraith/log"
)

func testLogger(t *testing.T) {
	t.Helper()
	previous := logger
	logger = log.NewLogger()
	t.Cleanup(func() { logger = previous })
}

func loadTestConfig(t *testing.T, path string, args ...string) *config.Config {
	t.Helper()
	testutil.ClearEnvPrefix(t, "LOGWISP_")
	inv, err := parseCommandLine(append([]string{"-c", path, "--quiet", "--status_reporter=false"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	m, err := config.Load(inv.load)
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

// runCommand runs `lw NAME ARGS...` and returns its exit status and output
func runCommand(t *testing.T, name string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	inv, err := parseCommandLine(append([]string{name}, args...))
	if err != nil || inv.command == nil {
		t.Fatalf("lw %s: not a command: %v", name, err)
	}
	var out, errOut bytes.Buffer
	code = inv.command.run(inv.args, &out, &errOut)
	return code, out.String(), errOut.String()
}
