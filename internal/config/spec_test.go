package config

import (
	"reflect"
	"testing"

	"logwisp/internal/testutil"
)

func loadPipelines(t *testing.T, args ...string) []PipelineConfig {
	t.Helper()
	m, err := Load(args)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Pipelines
}

func TestPipelineSpecGrammar(t *testing.T) {
	isolateConfig(t)
	got := loadPipelines(t,
		"--source", `file,directory=/var/log/a\,b,pattern=*.log`,
		`--source=file,id=app,directory=x\=y`,
		"--source", `file,directory=c:\\logs\\`,
		"--sink", "http,port=8080,auth.type=scram,auth.credentials_file=users.toml,tls.cert_file=c",
		"--filter", "include,patterns=ERROR,patterns=WARN",
		"--filter", `exclude,patterns=\d{1\,3}`,
		"--format", `txt,timestamp_format=Jan 2\, 2006`,
		"--pipeline", "b", "--source", "null", "--sink", "null", "--sink", "null", "--heartbeat", "interval_ms=1000",
		"--", "--source", "random")
	want := []PipelineConfig{{
		Name: "cli",
		Flow: &FlowConfig{
			Filters: []FilterConfig{
				{Type: "include", Patterns: []string{"ERROR", "WARN"}},
				{Type: "exclude", Patterns: []string{`\d{1,3}`}},
			},
			Format: &FormatConfig{Type: "txt", TimestampFormat: "Jan 2, 2006"},
		},
		PluginSources: []PluginSourceConfig{
			{ID: "file", Type: "file", Config: map[string]any{"directory": "/var/log/a,b", "pattern": "*.log"}},
			{ID: "app", Type: "file", Config: map[string]any{"directory": "x=y"}},
			{ID: "file_2", Type: "file", Config: map[string]any{"directory": `c:\logs\`}},
		},
		PluginSinks: []PluginSinkConfig{{ID: "http", Type: "http", Config: map[string]any{
			"port": "8080",
			"auth": map[string]any{"type": "scram", "credentials_file": "users.toml"},
			"tls":  map[string]any{"cert_file": "c"},
		}}},
	}, {
		Name:          "b",
		Flow:          &FlowConfig{Heartbeat: &HeartbeatConfig{Enabled: true, IntervalMS: 1000}},
		PluginSources: []PluginSourceConfig{{ID: "null", Type: "null", Config: map[string]any{}}},
		PluginSinks: []PluginSinkConfig{
			{ID: "null", Type: "null", Config: map[string]any{}},
			{ID: "null_2", Type: "null", Config: map[string]any{}},
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pipelines:\n got %+v\nwant %+v", got, want)
	}
	for want, args := range map[string][]string{
		`--sink http,port: missing "="`:                                  {"--sink", "http,port"},
		`--source directory=/x: missing TYPE`:                            {"--source", "directory=/x"},
		`--source file,type=x: TYPE already sets "type"`:                 {"--source", "file,type=x"},
		`--sink http,tls.cert_file=c: "tls" is both a value and a table`: {"--sink", "http,tls=1,tls.cert_file=c"},
		`--sink requires a value`:                                        {"--sink="},
		`--format txt: pipeline "cli" already has one`:                   {"--format", "json", "--format", "txt"},
		`--rate-limit rate=1,polcy=drop: unknown key "polcy"`:            {"--rate-limit", "rate=1,polcy=drop"},
	} {
		if _, err := Load(args); err == nil || err.Error() != want {
			t.Errorf("%q: err = %v, want %s", args, err, want)
		}
	}
}

// One pipeline from LOGWISP_*: numbered variables follow the bare one in
// numeric order, only repeatable kinds are numbered, and empty means unset.
func TestEnvironmentPipeline(t *testing.T) {
	isolateConfig(t)
	for name, value := range map[string]string{
		"LOGWISP_PIPELINE":      "edge",
		"LOGWISP_SOURCE":        "random",
		"LOGWISP_SOURCE_10":     "null,id=ten",
		"LOGWISP_SOURCE_2":      "null,id=two",
		"LOGWISP_SINK_1":        "console",
		"LOGWISP_FILTER":        "",
		"LOGWISP_FORMAT_1":      "raw",
		"LOGWISP_RATE_LIMIT":    "rate=10",
		"LOGWISP_LOGGING_LEVEL": "debug",
	} {
		t.Setenv(name, value)
	}
	m, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Pipelines
	if len(p) != 1 || p[0].Name != "edge" || len(p[0].PluginSources) != 3 || p[0].PluginSources[1].ID != "two" ||
		p[0].PluginSources[2].ID != "ten" || len(p[0].PluginSinks) != 1 || p[0].Flow.Filters != nil || p[0].Flow.Format != nil ||
		*p[0].Flow.RateLimit != (RateLimitConfig{Rate: 10, Policy: "drop"}) || cfg.Logging.Level != "debug" {
		t.Fatalf("environment pipeline: %+v %+v", p, cfg.Logging)
	}
}

func TestCommandLinePipelinesIgnoreEnvironment(t *testing.T) {
	isolateConfig(t)
	t.Setenv("LOGWISP_SOURCE", "random")
	t.Setenv("LOGWISP_SINK", "console")
	got := loadPipelines(t, "--source", "null", "--sink", "null")
	if len(got) != 1 || len(got[0].PluginSources) != 1 || got[0].PluginSources[0].Type != "null" ||
		len(got[0].PluginSinks) != 1 || got[0].PluginSinks[0].Type != "null" {
		t.Fatalf("environment specs mixed into command-line pipelines: %+v", got)
	}
}

// The file's pipelines are dropped unvalidated; its other keys still apply.
func TestSpecPipelinesReplaceFilePipelines(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "file.toml", "[logging]\nlevel = \"warn\"\n[[pipelines]]\nname = \"file\"\n")
	m, err := Load([]string{"-c", "file.toml", "--source", "null", "--sink", "null", "--status_reporter=false"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if unknown := m.config.UnknownCLIKeys(); len(unknown) != 0 {
		t.Fatalf("spec flags reached the schema parser: %v", unknown)
	}
	cfg, err := m.Snapshot()
	if err != nil || len(cfg.Pipelines) != 1 || cfg.Pipelines[0].Name != "cli" || cfg.Logging.Level != "warn" || cfg.StatusReporter {
		t.Fatalf("snapshot: %+v %v", cfg, err)
	}
}

// Without a file a reload still rebuilds; once the discovered default
// appears it is read, and its pipelines still yield to the specs.
func TestReloadKeepsSpecPipelines(t *testing.T) {
	isolateConfig(t)
	m, err := Load([]string{"--source", "random,special=true", "--sink", "null"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	first, err := m.Reload()
	if err != nil || !first.StatusReporter {
		t.Fatalf("reload without a file: %+v %v", first, err)
	}
	first.Pipelines[0].PluginSources[0].Config["special"] = "mutated"
	testutil.WriteFile(t, "logwisp.toml", "status_reporter = false\n[[pipelines]]\nname = \"file\"\n")
	next, err := m.Reload()
	if err != nil || next.StatusReporter || len(next.Pipelines) != 1 || next.Pipelines[0].Name != "cli" ||
		next.Pipelines[0].PluginSources[0].Config["special"] != "true" {
		t.Fatalf("reload: %+v %v", next, err)
	}
}
