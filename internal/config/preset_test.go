package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A preset starts its pipeline and names it unless --pipeline did; later
// sinks add to its own, a later format replaces its own.
func TestPresetStartsAndNamesItsPipeline(t *testing.T) {
	isolateConfig(t)
	got := loadPipelines(t, "preset", "tail,path=/var/log/app.log", "sink", "null", "format", "json",
		"pipeline", "mine", "preset", "pipe")
	want := []PipelineConfig{{
		Name:          "tail",
		Flow:          &FlowConfig{Format: &FormatConfig{Type: "json"}},
		PluginSources: []PluginSourceConfig{{ID: "file", Type: "file", Config: map[string]any{"directory": "/var/log", "pattern": "app.log", "from": "end"}}},
		PluginSinks: []PluginSinkConfig{
			{ID: "stdout", Type: "console", Config: map[string]any{"color": "auto"}},
			{ID: "null", Type: "null", Config: map[string]any{}},
		},
	}, {
		Name:          "mine",
		Flow:          &FlowConfig{Format: &FormatConfig{Type: "raw"}},
		PluginSources: []PluginSourceConfig{{ID: "stdin", Type: "console", Config: map[string]any{}}},
		PluginSinks:   []PluginSinkConfig{{ID: "stdout", Type: "console", Config: map[string]any{"color": "auto"}}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pipelines:\n got %+v\nwant %+v", got, want)
	}
	if _, err := Load(Args{Specs: specs("sink", "null", "preset", "pipe")}); err == nil || !strings.Contains(err.Error(), "must start its pipeline") {
		t.Fatalf("preset after a sink: %v", err)
	}
}

// Keys are checked against the preset's own, required ones enforced, and
// the edge and aggregator refuse to run without authentication.
func TestPresetKeysAreChecked(t *testing.T) {
	isolateConfig(t)
	for spec, want := range map[string]string{
		"nope":                         `no preset "nope" (valid: pipe, tail, serve, edge, aggregator)`,
		"tail,path=x,colour=1":         `preset tail has no key "colour" (valid: path, from, format)`,
		"tail":                         "preset tail needs path",
		"tail,path=x,format.type=json": "preset keys do not nest",
		"tail,path=x,path=y":           `key "path" takes one value`,
		"serve,listen=8080":            `listen "8080": want HOST:PORT`,
		"serve,tls=self,cert=c":        "cert does not apply to tls=self",
		"serve,tls=files,cert=c":       "tls=files needs key",
		"serve,viewer=yes":             `viewer "yes"`,
		"serve,proxy=127.0.0.1":        "proxy needs users",
		"serve,viewer=true":            "viewer=true needs proxy",
		"edge,to=agg:9000":             "it never sends unauthenticated",
		"edge,to=agg:9000,user=u":      "user and password_file go together",
		"edge,to=agg:9000,user=u,password_file=p,transport=udp": `transport "udp"`,
		"aggregator,users=u,tls=off":                            "the aggregator always serves TLS",
		"aggregator":                                            "it never receives unauthenticated",
	} {
		_, err := Load(Args{Specs: specs("preset", spec)})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %s", spec, err, want)
		}
	}
}

// A preset path is what isDir answers, a directory named with brackets too;
// without isDir, off the target host, it is a directory when it ends in '/',
// a pattern when it holds a glob, and otherwise ErrPathKind asks
func TestPresetPathKind(t *testing.T) {
	yes := func(string) (bool, error) { return true, nil }
	for _, c := range []struct {
		path  string
		isDir IsDir
		want  string
	}{{"/srv/app/", nil, "/srv/app/ *"}, {"/srv/app/*.log", nil, "/srv/app *.log"}, {"/srv/app[1]", yes, "/srv/app[1] *"}, {"/srv/app", nil, ""}} {
		p, err := ExpandPreset("tail", map[string]string{"path": c.path}, c.isDir)
		if c.want == "" {
			if !errors.Is(err, ErrPathKind) {
				t.Errorf("%s: %v, want ErrPathKind", c.path, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if m := p.PluginSources[0].Config; m["directory"].(string)+" "+m["pattern"].(string) != c.want {
			t.Errorf("%s: %v, want %s", c.path, m, c.want)
		}
	}
}
