package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A preset starts its pipeline and names it unless --pipeline did; later
// sinks add to its own, a later format replaces its own.
func TestPresetStartsAndNamesItsPipeline(t *testing.T) {
	isolateConfig(t)
	got := loadPipelines(t, "preset", "tail:path=/var/log/app.log", "sink", "null", "format", "json",
		"pipeline", "mine", "preset", "pipe")
	want := []PipelineConfig{{
		Name:          "tail",
		Flow:          &FlowConfig{Format: &FormatConfig{Type: "json"}},
		PluginSources: []PluginSourceConfig{{ID: "file", Type: "file", Config: map[string]any{"directory": "/var/log", "pattern": "app.log", "from": "end"}}},
		PluginSinks: []PluginSinkConfig{
			{ID: "console", Type: "console", Config: map[string]any{"color": "auto"}},
			{ID: "null", Type: "null", Config: map[string]any{}},
		},
	}, {
		Name:          "mine",
		Flow:          &FlowConfig{Format: &FormatConfig{Type: "raw"}},
		PluginSources: []PluginSourceConfig{{ID: "console", Type: "console", Config: map[string]any{}}},
		PluginSinks:   []PluginSinkConfig{{ID: "console", Type: "console", Config: map[string]any{"color": "auto"}}},
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
		"nope":                             `no preset "nope" (valid: pipe, tail, serve, edge, aggregator)`,
		"tail:path=x,colour=1":             `preset tail has no key "colour" (valid: path, from, format)`,
		"tail":                             "preset tail needs path",
		"tail:path=x,format.type=json":     "preset keys do not nest",
		"tail:path=x,path=y":               `key "path" takes one value`,
		"serve:listen=8080":                `listen "8080": want HOST:PORT`,
		"serve:tls=self,cert=c":            "cert does not apply to tls=self",
		"serve:tls=files,cert=c":           "tls=files needs key",
		"serve:viewer=yes":                 `viewer "yes"`,
		"serve:proxy=127.0.0.1":            "proxy needs user or users",
		"serve:viewer=true":                "viewer=true needs proxy",
		"serve:user=u":                     "user and users need tls (self, issuer or files), or proxy",
		"serve:tls=self,user=u,users=f":    "user or users, not both",
		"edge:to=agg:9000":                 "it never sends unauthenticated",
		"edge:to=agg:9000,password_file=p": "password_file needs user",
		"edge:to=agg:9000,user=u,password_file=p,transport=udp": `transport "udp"`,
		"aggregator:users=u,tls=off":                            `tls "off" (valid: `,
		"aggregator:user=u,users=f":                             "user or users, not both",
		"aggregator":                                            "it never receives unauthenticated",
	} {
		_, err := Load(Args{Specs: specs("preset", spec)})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %s", spec, err, want)
		}
	}
}

// A preset key that sets an option takes its choices and hint, a switch true
// or false; a listener's tls offers off only where it may serve plain text
func TestPresetKeysTakeTheirOptionsChoices(t *testing.T) {
	param := func(preset, key string) PresetParam {
		ps := Presets()
		p := ps[slices.IndexFunc(ps, func(p Preset) bool { return p.Name == preset })]
		return p.Params[slices.IndexFunc(p.Params, func(k PresetParam) bool { return k.Name == key })]
	}
	for _, c := range []struct {
		preset, key string
		table       reflect.Type
		option      string
	}{
		{"tail", "from", reflect.TypeFor[FileSourceOptions](), "from"},
		{"pipe", "format", reflect.TypeFor[FormatConfig](), "type"},
		{"serve", "proxy", reflect.TypeFor[AuthOptions](), "trusted_proxies"},
		{"aggregator", "users", reflect.TypeFor[AuthOptions](), "credentials_file"},
	} {
		opts := options(c.table)
		o := opts[slices.IndexFunc(opts, func(o option) bool { return o.Name == c.option })]
		if p := param(c.preset, c.key); !slices.Equal(p.Enum, o.Enum) || p.Hint != o.Hint || len(o.Enum) == 0 && o.Hint == "" {
			t.Errorf("%s %s: enum %v hint %q, want %s's %v %q", c.preset, c.key, p.Enum, p.Hint, c.option, o.Enum, o.Hint)
		}
	}
	var modes []string
	for _, m := range tlsModes {
		modes = append(modes, m.name)
	}
	for _, c := range []struct {
		preset, key string
		enum        []string
	}{
		{"serve", "viewer", []string{"true", "false"}},
		{"edge", "transport", transports()},
		{"serve", "tls", modes},
		{"aggregator", "tls", slices.DeleteFunc(slices.Clone(modes), func(m string) bool { return m == "off" })},
	} {
		if p := param(c.preset, c.key); !slices.Equal(p.Enum, c.enum) {
			t.Errorf("%s %s: enum %v, want %v", c.preset, c.key, p.Enum, c.enum)
		}
	}
}

// A preset user without password_file is asked for on the terminal
func TestPresetUserWithoutPasswordFileAsks(t *testing.T) {
	p, err := ExpandPreset("edge", map[string]string{"to": "agg:9000", "user": "u"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth := p.PluginSinks[0].Config["auth"].(map[string]any); auth["password_file"] != "/dev/tty" {
		t.Fatalf("auth = %v, want password_file /dev/tty", auth)
	}
}

// A preset path ending in '/' is a directory, there yet or not; any other is
// what isDir answers, a directory named with brackets too: this host's,
// reading ~ as home, or off it the user's answer, a single file too; without
// one it is a pattern when it holds a glob, and otherwise ErrPathKind asks
func TestPresetPathKind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	yes := func(string) (bool, error) { return true, nil }
	file := Answers(map[string]bool{"/srv/app.log": false})
	for _, c := range []struct {
		path  string
		isDir IsDir
		want  string
	}{{"/srv/app/", nil, "/srv/app/ *"}, {"/srv/app/*.log", nil, "/srv/app *.log"}, {"/srv/app[1]", yes, "/srv/app[1] *"}, {"/srv/app", nil, ""},
		{"/srv/app.log", file, "/srv app.log"}, {"/srv/app", file, ""}, {"/srv/app/", file, "/srv/app/ *"},
		{"~/logs", HostIsDir, "~/logs *"}, {home + "/later/", HostIsDir, home + "/later/ *"}} {
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
