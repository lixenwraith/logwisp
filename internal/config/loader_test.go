package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/testutil"
)

// -c wins over the environment, which wins over discovery; only the
// discovered default is not explicit, so only it may be missing.
func TestResolveConfigPath(t *testing.T) {
	isolateConfig(t)
	if path, explicit := resolveConfigPath(""); path != "logwisp.toml" || explicit {
		t.Fatalf("discovered default: %q %v", path, explicit)
	}
	t.Setenv("LOGWISP_CONFIG_DIR", "configs")
	t.Setenv("LOGWISP_CONFIG_FILE", "env.toml")
	if path, explicit := resolveConfigPath(""); path != filepath.Join("configs", "env.toml") || !explicit {
		t.Fatalf("environment path: %q %v", path, explicit)
	}
	if path, explicit := resolveConfigPath("chosen.toml"); path != "chosen.toml" || !explicit {
		t.Fatalf("-c path: %q %v", path, explicit)
	}
}

func TestLoadPrecedenceAndDetachedSnapshots(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "selected.toml", "config_file = \"ignored.toml\"\n[logging]\nlevel = \"error\"\n")
	t.Setenv("LOGGING_LEVEL", "invalid-bare-variable")
	t.Setenv("LOGWISP_LOGGING_LEVEL", "debug")
	m, err := Load(Args{File: "selected.toml", Overrides: []string{"--logging.level=warn", "--quiet"}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if unknown := m.config.UnknownCLIKeys(); len(unknown) != 0 {
		t.Fatalf("path flags reached schema parser: %v", unknown)
	}
	first, err := m.Snapshot()
	if err != nil || first.Logging.Level != "warn" || first.ConfigFile != "selected.toml" {
		t.Fatalf("snapshot: %+v %v", first, err)
	}
	first.Logging.Level = "mutated"
	first.Pipelines[0].PluginSources[0].Config["buffer_size"] = 1
	second, err := m.Snapshot()
	if _, aliased := second.Pipelines[0].PluginSources[0].Config["buffer_size"]; err != nil || second.Logging.Level != "warn" || aliased {
		t.Fatalf("snapshot aliases another result: %+v %v", second, err)
	}
	env, err := Load(Args{File: "selected.toml"})
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	fromEnv, err := env.Snapshot()
	if err != nil || fromEnv.Logging.Level != "debug" {
		t.Fatalf("prefixed environment ignored: %+v %v", fromEnv, err)
	}
}

func TestMissingFilesDoNotHideInvalidOverrides(t *testing.T) {
	isolateConfig(t)
	m, err := Load(Args{})
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	if _, err := Load(Args{File: "missing.toml"}); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("missing explicit path: %v", err)
	}
	if _, err := Load(Args{Overrides: []string{"--logging.file.max_size_mb=1.5"}}); err == nil || errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("invalid CLI hidden by missing default: %v", err)
	}
	t.Setenv("LOGWISP_STATUS_REPORTER", "invalid")
	if _, err := Load(Args{}); err == nil || errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("invalid environment hidden by missing default: %v", err)
	}
}

func TestReloadReadsDiskValidatesAndPreservesOldSnapshots(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "reload.toml", "status_reporter = true\n")
	m, err := Load(Args{File: "reload.toml"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	old, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, "reload.toml", "status_reporter = false\n")
	next, err := m.Reload()
	if err != nil || next.StatusReporter || !old.StatusReporter || next.ConfigFile != old.ConfigFile {
		t.Fatalf("disk reload/snapshot ownership: %+v %v", next, err)
	}
	// Builder validators do not run on LoadFile; Snapshot must run them again.
	testutil.WriteFile(t, "reload.toml", "pipelines = []\n")
	if _, err := m.Reload(); err == nil || !strings.Contains(err.Error(), "no pipelines") {
		t.Fatalf("semantically invalid reload accepted: %v", err)
	}
	if len(next.Pipelines) == 0 || !old.StatusReporter {
		t.Fatal("invalid edit changed a published snapshot")
	}
	testutil.WriteFile(t, "reload.toml", "[logging.file]\nmax_size_mb = 1.5\n")
	if _, err := m.Reload(); err == nil {
		t.Fatal("fractional integer accepted")
	}
	testutil.WriteFile(t, "reload.toml", "# remove the status override\n")
	recovered, err := m.Reload()
	if err != nil || !recovered.StatusReporter {
		t.Fatalf("override removal/recovery: %+v %v", recovered, err)
	}
	// Only a missing discovered default is tolerated; a named file must exist.
	if err := os.Remove("reload.toml"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reload(); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("reload without the named file: %v", err)
	}
}

func TestWatchStartsOnSubscriptionAndCloses(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "watched.toml", "auto_reload = true\n")
	m, err := Load(Args{File: "watched.toml"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.config.IsWatching() {
		t.Fatal("watching started before service startup")
	}
	changes := m.Watch()
	if !m.config.IsWatching() {
		t.Fatal("subscription did not start watching")
	}
	m.Close()
	select {
	case _, ok := <-changes:
		if ok {
			t.Fatal("watch channel still open")
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not close")
	}
}

func TestNestedPluginOptionsKeepDefaultsAndNumericTypes(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "plugins.toml", `
[[pipelines]]
name = "nested"
[[pipelines.plugin_sources]]
id = "in"
type = "null"
[[pipelines.plugin_sinks]]
id = "out"
type = "tcp"
[pipelines.plugin_sinks.config]
port = 9000
write_timeout_ms = 9007199254740993
[pipelines.plugin_sinks.config.tls]
enabled = false
server_name = "relay.example"
[pipelines.plugin_sinks.config.auth]
type = "none"
allow = ["one", "two"]
`)
	m, err := Load(Args{File: "plugins.toml"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	opts := TCPSinkOptions{Host: "127.0.0.1", BufferSize: 1000}
	if err := Scan(cfg.Pipelines[0].PluginSinks[0].Config, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.Host != "127.0.0.1" || opts.BufferSize != 1000 || opts.Port != 9000 || opts.WriteTimeoutMS != 9007199254740993 ||
		opts.TLS == nil || opts.TLS.ServerName != "relay.example" || opts.Auth == nil || !reflect.DeepEqual(opts.Auth.Allow, []string{"one", "two"}) {
		t.Fatalf("plugin defaults, nested tables or integer precision lost: %+v", opts)
	}
}

// A misspelled key, even inside a nested tls or auth table, fails plugin
// construction instead of leaving the protection it named switched off.
func TestPluginConfigRejectsUnknownKeys(t *testing.T) {
	isolateConfig(t)
	for key, table := range map[string]string{
		"bogus":       "bogus = true",
		"tls.enabeld": "[pipelines.plugin_sinks.config.tls]\nenabeld = true",
		"auth.tpye":   "[pipelines.plugin_sinks.config.auth]\ntpye = \"mtls\"",
	} {
		testutil.WriteFile(t, "plugins.toml", `
[[pipelines]]
name = "typo"
[[pipelines.plugin_sources]]
id = "in"
type = "null"
[[pipelines.plugin_sinks]]
id = "out"
type = "tcp"
[pipelines.plugin_sinks.config]
port = 9000
`+table+"\n")
		m, err := Load(Args{File: "plugins.toml"})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := m.Snapshot()
		m.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = Scan(cfg.Pipelines[0].PluginSinks[0].Config, &TCPSinkOptions{})
		if err == nil || !strings.Contains(err.Error(), `"`+key+`"`) {
			t.Errorf("unknown key %s: err = %v", key, err)
		}
	}
}

// A misspelled table path above a plugin's config drops that whole table, so
// the file itself is checked too; only config_file is tolerated, as documented.
func TestConfigFileRejectsUnknownKeys(t *testing.T) {
	isolateConfig(t)
	for key, body := range map[string]string{
		"pipelines[0].plugin_sinks[0].confg": "[pipelines.plugin_sinks.confg.tls]\nenabled = true",
		"logging.levle":                      "[logging]\nlevle = \"debug\"",
	} {
		testutil.WriteFile(t, "typo.toml", `config_file = "ignored.toml"
[[pipelines]]
name = "typo"
[[pipelines.plugin_sources]]
id = "in"
type = "null"
[[pipelines.plugin_sinks]]
id = "out"
type = "tcp"
[pipelines.plugin_sinks.config]
port = 9000
`+body+"\n")
		m, err := Load(Args{File: "typo.toml"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = m.Snapshot()
		m.Close()
		if err == nil || !strings.Contains(err.Error(), `"`+key+`"`) {
			t.Errorf("unknown key %s: err = %v", key, err)
		}
	}
}

// A file makes lw a service, logging at info with the status reporter; without
// one it is a command-line tool that reports warnings and errors only.
func TestNoConfigFileMeansQuietLogging(t *testing.T) {
	isolateConfig(t)
	for _, c := range []struct {
		file, level string
		reporter    bool
	}{{"", "warn", false}, {"[logging]\noutput = \"stderr\"\n", "info", true}} {
		if c.file != "" {
			testutil.WriteFile(t, "logwisp.toml", c.file)
		}
		m, err := Load(Args{})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := m.Snapshot()
		m.Close()
		if err != nil || cfg.Logging.Level != c.level || cfg.StatusReporter != c.reporter || cfg.Logging.Output != "stderr" {
			t.Fatalf("file %q: %+v %+v %v", c.file, cfg, cfg.Logging, err)
		}
	}
	t.Setenv("LOGWISP_LOGGING_LEVEL", "debug")
	os.Remove("logwisp.toml")
	m, err := Load(Args{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if cfg, err := m.Snapshot(); err != nil || cfg.Logging.Level != "debug" {
		t.Fatalf("environment over the file-less default: %+v %v", cfg, err)
	}
}

// A string in the file is one list entry: split at its comma, an exclude
// pattern such as password=\S{8,64} would become two that match nothing
func TestFileStringIsOneListEntry(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "logwisp.toml", "[[pipelines]]\nname = \"p\"\n"+
		"[[pipelines.plugin_sources]]\nid = \"in\"\ntype = \"null\"\n[[pipelines.plugin_sinks]]\nid = \"out\"\ntype = \"null\"\n"+
		"[[pipelines.flow.filters]]\ntype = \"exclude\"\npatterns = \"password=\\\\S{8,64}\"\n")
	m, err := Load(Args{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil || !reflect.DeepEqual(cfg.Pipelines[0].Flow.Filters[0].Patterns, []string{`password=\S{8,64}`}) {
		t.Fatalf("patterns: %v %v", cfg.Pipelines[0].Flow.Filters, err)
	}
}

// The top-level color is the default of every console sink, which may set
// its own; other sinks do not take the key.
func TestTopLevelColorIsEachConsoleSinksDefault(t *testing.T) {
	isolateConfig(t)
	m, err := Load(Args{Specs: specs("sink", "console", "sink", "console,color=never", "sink", "null"), Overrides: []string{"--color=always"}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var colors []any
	for _, s := range cfg.Pipelines[0].PluginSinks {
		colors = append(colors, s.Config["color"])
	}
	if !reflect.DeepEqual(colors, []any{"always", "never", nil}) {
		t.Fatalf("console sink colors: %v", colors)
	}
}
