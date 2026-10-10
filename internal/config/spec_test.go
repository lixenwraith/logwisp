package config

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/lixenwraith/logwisp/internal/testutil"
)

// specs pairs flags with values: specs("sink", "null") is --sink null
func specs(pairs ...string) []Spec {
	var out []Spec
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, Spec{pairs[i], pairs[i+1]})
	}
	return out
}

func loadPipelines(t *testing.T, pairs ...string) []PipelineConfig {
	t.Helper()
	m, err := Load(Args{Specs: specs(pairs...)})
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
		"source", `file:directory=/var/log/a\,b,pattern=*.log`,
		"source", `file:id=app,directory=x\=y`,
		"source", `file:directory=c:\\logs\\`,
		"sink", "http:port=8080,auth.type=scram,auth.credentials_file=users.toml,tls.enabled=true,tls.cert_file=c,tls.key_file=k",
		"filter", "include:patterns=ERROR,patterns=WARN",
		"filter", `exclude:patterns=\d{1\,3}`,
		"format", `txt:timestamp_format=Jan 2\, 2006`,
		"pipeline", "b", "source", "null", "sink", "null", "sink", "null", "heartbeat", "interval_ms=1000")
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
			"port": int64(8080),
			"auth": map[string]any{"type": "scram", "credentials_file": "users.toml"},
			"tls":  map[string]any{"enabled": true, "cert_file": "c", "key_file": "k"},
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
	for want, pairs := range map[string][]string{
		`--sink http:port: missing "="`:                                         {"sink", "http:port"},
		`--source file,directory=/x: TYPE ends at ':', as in file:directory=/x`: {"source", "file,directory=/x"},
		`--source directory=/x: missing TYPE`:                                   {"source", "directory=/x"},
		`--source file:type=x: TYPE already sets "type"`:                        {"source", "file:type=x"},
		`--sink http:tls.cert_file=c: "tls" is both a value and a table`:        {"sink", "http:tls=1,tls.cert_file=c"},
		`--sink requires a value`:                                               {"sink", ""},
		`--format txt: pipeline "cli" already has one`:                          {"format", "json", "format", "txt"},
		`--rate-limit entries_per_second=1,polcy=drop: unknown key "polcy"`:     {"rate-limit", "entries_per_second=1,polcy=drop"},
	} {
		if _, err := Load(Args{Specs: specs(pairs...)}); err == nil || err.Error() != want {
			t.Errorf("%q: err = %v, want %s", pairs, err, want)
		}
	}
}

// A spec value is one list entry, commas included: a regex quantifier or a DN
// must not split into several, wider entries.
func TestSpecValueIsOneListEntry(t *testing.T) {
	isolateConfig(t)
	sink := loadPipelines(t, "source", "null", "sink",
		`tcp:port=9000,tls.enabled=true,tls.self_signed=true,tls.client_auth=true,tls.client_ca_file=ca,`+
			`auth.type=mtls,auth.allow_patterns=^edge-\d{1\,3}$,auth.allow=CN=a\,O=b,auth.allow=CN=c`)[0].PluginSinks[0]
	var opts TCPSinkOptions
	if err := Scan(sink.Config, &opts); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts.Auth.AllowPatterns, []string{`^edge-\d{1,3}$`}) ||
		!reflect.DeepEqual(opts.Auth.Allow, []string{"CN=a,O=b", "CN=c"}) {
		t.Fatalf("allow_patterns %q, allow %q", opts.Auth.AllowPatterns, opts.Auth.Allow)
	}
}

// One pipeline from LOGWISP_*: numbered variables follow the bare one in
// numeric order, only repeatable kinds are numbered, and empty means unset.
func TestEnvironmentPipeline(t *testing.T) {
	isolateConfig(t)
	for name, value := range map[string]string{
		"LOGWISP_PIPELINE":      "edge",
		"LOGWISP_SOURCE":        "random",
		"LOGWISP_SOURCE_10":     "null:id=ten",
		"LOGWISP_SOURCE_2":      "null:id=two",
		"LOGWISP_SINK_1":        "console",
		"LOGWISP_FILTER":        "",
		"LOGWISP_FORMAT_1":      "raw",
		"LOGWISP_RATE_LIMIT":    "entries_per_second=10",
		"LOGWISP_LOGGING_LEVEL": "debug",
	} {
		t.Setenv(name, value)
	}
	m, err := Load(Args{})
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
		*p[0].Flow.RateLimit != (RateLimitConfig{EntriesPerSecond: 10, Policy: "drop"}) || cfg.Logging.Level != "debug" {
		t.Fatalf("environment pipeline: %+v %+v", p, cfg.Logging)
	}
}

func TestCommandLinePipelinesIgnoreEnvironment(t *testing.T) {
	isolateConfig(t)
	t.Setenv("LOGWISP_SOURCE", "random")
	t.Setenv("LOGWISP_SINK", "console")
	got := loadPipelines(t, "source", "null", "sink", "null")
	if len(got) != 1 || len(got[0].PluginSources) != 1 || got[0].PluginSources[0].Type != "null" ||
		len(got[0].PluginSinks) != 1 || got[0].PluginSinks[0].Type != "null" {
		t.Fatalf("environment specs mixed into command-line pipelines: %+v", got)
	}
}

// The file's pipelines are dropped unvalidated; its other keys still apply.
func TestSpecPipelinesReplaceFilePipelines(t *testing.T) {
	isolateConfig(t)
	testutil.WriteFile(t, "file.toml", "[logging]\nlevel = \"warn\"\n[[pipelines]]\nname = \"file\"\n")
	m, err := Load(Args{File: "file.toml", Specs: specs("source", "null", "sink", "null"), Overrides: []string{"--status_reporter=false"}})
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

// A spec pipeline without a source reads stdin and one without a sink writes
// stdout, as a filter does; two pipelines cannot both read stdin.
func TestSpecPipelinesDefaultToStdio(t *testing.T) {
	isolateConfig(t)
	got := loadPipelines(t, "filter", "include:patterns=ERROR")
	if p := got[0]; len(p.PluginSources) != 1 || p.PluginSources[0].Type != "console" || p.PluginSources[0].ID != "stdin" ||
		len(p.PluginSinks) != 1 || p.PluginSinks[0].Type != "console" || p.PluginSinks[0].ID != "stdout" {
		t.Fatalf("pipeline: %+v", p)
	}
	_, err := Load(Args{Specs: specs("pipeline", "a", "sink", "null", "pipeline", "b", "sink", "null")})
	if err == nil || !strings.Contains(err.Error(), `one console source may run, and pipeline "a" has it`) {
		t.Fatalf("second stdin reader: %v", err)
	}
}

// Without a file a reload still rebuilds; once the discovered default
// appears it is read, and its pipelines still yield to the specs. Its later
// removal fails the reload instead of keeping the removed file's values.
func TestReloadKeepsSpecPipelines(t *testing.T) {
	isolateConfig(t)
	m, err := Load(Args{Specs: specs("source", "random:special=true", "sink", "null")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	first, err := m.Reload()
	if err != nil || first.StatusReporter {
		t.Fatalf("reload without a file: %+v %v", first, err)
	}
	first.Pipelines[0].PluginSources[0].Config["special"] = "mutated"
	testutil.WriteFile(t, "logwisp.toml", "status_reporter = true\n[[pipelines]]\nname = \"file\"\n")
	next, err := m.Reload()
	if err != nil || !next.StatusReporter || len(next.Pipelines) != 1 || next.Pipelines[0].Name != "cli" ||
		next.Pipelines[0].PluginSources[0].Config["special"] != true {
		t.Fatalf("reload: %+v %v", next, err)
	}
	if err := os.Remove("logwisp.toml"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reload(); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("reload after the file was removed: %v", err)
	}
}

// Written specs build the pipelines a file would: each flow stage with its
// defaults, so the rate limit keeps its file policy and the heartbeat its off
func TestWrittenSpecsBuildWhatAFileWould(t *testing.T) {
	p := PipelineConfig{Name: "p", Flow: &FlowConfig{Format: &FormatConfig{}, RateLimit: &RateLimitConfig{EntriesPerSecond: 5}, Heartbeat: &HeartbeatConfig{}},
		PluginSources: []PluginSourceConfig{{ID: "in", Type: "null", Config: map[string]any{}}},
		PluginSinks:   []PluginSinkConfig{{ID: "out", Type: "null", Config: map[string]any{}}}}
	got, err := SpecPipelines(PipelineSpecs([]PipelineConfig{p}), nil)
	p.Flow = &FlowConfig{Format: &FormatConfig{Type: "raw"}, RateLimit: &RateLimitConfig{EntriesPerSecond: 5, Policy: "pass"},
		Heartbeat: &HeartbeatConfig{IntervalMS: 1000, Format: "txt"}}
	if err != nil || !reflect.DeepEqual(got, []PipelineConfig{p}) {
		t.Fatalf("got %+v %v\nwant %+v", got, err, p)
	}
}
