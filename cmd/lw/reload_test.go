package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/testutil"

	lconfig "github.com/lixenwraith/config"
)

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
	testutil.WriteFile(t, path, "[logging]\nlevel = \"info\"\n")
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

// Every registered plugin decodes through the checked decoder, so a typo in
// any plugin's config, security tables included, refuses to start.
func TestEveryPluginRejectsUnknownKeys(t *testing.T) {
	testLogger(t)
	manager := session.NewManager(time.Hour)
	t.Cleanup(manager.Stop)
	proxy := session.NewProxy(manager, "typo")
	bad := map[string]any{"no_such_key": true}
	check := func(kind, name string, err error) {
		if err == nil || !strings.Contains(err.Error(), "no_such_key") {
			t.Errorf("%s %q accepted an unknown key: %v", kind, name, err)
		}
	}
	for _, name := range plugin.ListSources() {
		factory, _ := plugin.GetSource(name)
		_, err := factory("typo", bad, logger, proxy)
		check("source", name, err)
	}
	for _, name := range plugin.ListSinks() {
		factory, _ := plugin.GetSink(name)
		_, err := factory("typo", bad, logger, proxy)
		check("sink", name, err)
	}
}

// A misspelled spec key reaches the plugin as the nested key it names, so the
// sink refuses to build instead of starting without the TLS it was asked for.
func TestMisspelledSpecKeyFailsPluginConstruction(t *testing.T) {
	testLogger(t)
	path := filepath.Join(t.TempDir(), "empty.toml")
	testutil.WriteFile(t, path, "")
	cfg := loadTestConfig(t, path, "--source", "null", "--sink", "http,host=127.0.0.1,port=15861,tls.enabeld=true")
	svc, err := bootstrapService(context.Background(), cfg)
	if err == nil {
		svc.Shutdown()
	}
	if err == nil || !strings.Contains(err.Error(), `unknown key "tls.enabeld"`) {
		t.Fatalf("misspelled spec key accepted: %v", err)
	}
}

// lw --check builds every plugin, so a bad option fails it, but starts none:
// the port a valid sink names stays free and its log directory uncreated.
func TestCheckBuildsWithoutStarting(t *testing.T) {
	testLogger(t)
	dir := t.TempDir()
	path, out := filepath.Join(dir, "empty.toml"), filepath.Join(dir, "out")
	testutil.WriteFile(t, path, "")
	if code := checkConfig(loadTestConfig(t, path, "--source", "null", "--sink", "http,host=127.0.0.1,port=15862",
		"--sink", "file,name=check,directory="+out)); code != 0 {
		t.Fatalf("valid configuration: exit %d", code)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:15862")
	if err != nil {
		t.Fatalf("check bound the sink's port: %v", err)
	}
	ln.Close()
	if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("check created the file sink's directory: %v", err)
	}
	if code := checkConfig(loadTestConfig(t, path, "--source", "null", "--sink", "http,port=15862,tls.enabled=true")); code != 1 {
		t.Fatalf("listener TLS without a certificate: exit %d, want 1", code)
	}
}
