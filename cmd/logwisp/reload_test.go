package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"logwisp/internal/config"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

func testLogger(t *testing.T) {
	t.Helper()
	logger = log.NewLogger()
	t.Cleanup(func() { logger = nil })
}

func TestWatchErrorsDoNotTriggerReloadAndChangesAreCoalesced(t *testing.T) {
	testLogger(t)
	for _, event := range []string{lconfig.EventFileDeleted, lconfig.EventPermissionsChanged, lconfig.EventReloadTimeout, lconfig.EventReloadError + ":invalid TOML"} {
		if collectConfigChanges(event, nil) {
			t.Fatalf("error event triggered service restart: %s", event)
		}
	}
	changes := make(chan string, 3)
	changes <- "pipelines"
	changes <- "status_reporter"
	changes <- lconfig.EventReloadError + ":partial edit"
	close(changes)
	if !collectConfigChanges("logging.level", changes) || len(changes) != 0 {
		t.Fatal("pending path changes were not folded into a single reload")
	}
	if collectConfigChanges("", changes) {
		t.Fatal("closed channel triggered a reload")
	}
}

func loadTestConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "LOGWISP_") {
			t.Setenv(key, value)
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
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

func TestShippedConfigurationBuildsWithCheckedPluginDecoder(t *testing.T) {
	testLogger(t)
	path, err := filepath.Abs(filepath.Join("..", "..", "config", "logwisp.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadTestConfig(t, path)
	if len(cfg.Pipelines) != 1 || cfg.Pipelines[0].Name != "default" {
		t.Fatalf("sample array-of-tables decoded incorrectly: %+v", cfg.Pipelines)
	}
	svc, err := bootstrapService(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown()
	pl, err := svc.GetPipeline("default")
	if err != nil || len(pl.Sources) != 1 || len(pl.Sinks) != 1 {
		t.Fatalf("sample plugins failed to build: %v", err)
	}
	svc.Shutdown() // A later reload failure or process exit can close it again.
}

func TestInvalidReloadLeavesStatusReporterRunning(t *testing.T) {
	testLogger(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[logging]\nlevel = \"info\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"empty-pipelines", "duplicate-names", "fractional-plugin-integer", "plugin-overflow"} {
		t.Run(mode, func(t *testing.T) {
			cfg := loadTestConfig(t, path)
			switch mode {
			case "empty-pipelines":
				cfg.Pipelines = nil
			case "duplicate-names":
				cfg.Pipelines = append(cfg.Pipelines, cfg.Pipelines[0])
			case "fractional-plugin-integer":
				cfg.Pipelines[0].PluginSinks[0].Config["buffer_size"] = 1.5
			case "plugin-overflow":
				cfg.Pipelines[0].PluginSinks[0].Config["buffer_size"] = ^uint64(0)
			}
			cancelled := false
			svc, next, _, err := handleReload(context.Background(), cfg, nil, func() { cancelled = true })
			if err == nil || svc != nil || next != nil || cancelled {
				t.Fatalf("invalid reload affected running state: svc=%v cfg=%v cancelled=%v error=%v", svc, next, cancelled, err)
			}
		})
	}
}
