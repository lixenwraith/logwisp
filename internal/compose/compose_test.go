package compose

import (
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lixenwraith/logwisp/internal/config"
)

// The engine builds as WebAssembly for the website: it links no TLS, HTTP,
// process, signal or terminal code, nor lw's log, auth or terminal modules
func TestEngineLinksNoHostCode(t *testing.T) {
	// A packager's -buildmode (makepkg's pie) is the host's; wasm has only the
	// default
	flags := slices.DeleteFunc(strings.Fields(os.Getenv("GOFLAGS")), func(f string) bool {
		return strings.HasPrefix(f, "-buildmode")
	})
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "GOFLAGS="+strings.Join(flags, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		module, mine := strings.CutPrefix(dep, "github.com/lixenwraith/")
		if slices.Contains([]string{"crypto/tls", "net/http", "os/exec", "os/signal", "golang.org/x/term"}, dep) ||
			mine && slices.Contains([]string{"log", "auth", "terminal"}, strings.Split(module, "/")[0]) {
			t.Errorf("links %s", dep)
		}
	}
}

// A pasted command line, its line ends LF or CRLF, and the website's JSON each
// start the composition that wrote them: escaped and quoted values, nested
// keys, lists, moved filters, stages whose flags' defaults differ from a
// file's, a value starting with '-', JSON's numbers for integers
func TestWrittenFormsStartTheSameComposition(t *testing.T) {
	c := &Composition{}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.AddPipeline("edge"))
	src, err := c.Add(0, "source", "file")
	must(err)
	must(c.Set(0, src, "directory", "/var/log/my app"))
	must(c.Set(0, src, "pattern", "it's *.log"))
	sink, err := c.Add(0, "sink", "tcp_chain")
	must(err)
	for key, value := range map[string]string{"host": "agg.example", "port": "9000", "tls.enabled": "true",
		"tls.pin_sha256": "sha256//" + strings.Repeat("A", 43) + "=", "auth.type": "scram",
		"auth.username": `edge,01=a\b\`, "auth.password_file": "/etc/lw/edge.pass"} {
		must(c.Set(0, sink, key, value))
	}
	exclude, err := c.Add(0, "filters", "exclude")
	must(err)
	must(c.Set(0, exclude, "patterns", `password=\S{8,64}`, `"quoted"`))
	_, err = c.Add(0, "filters", "include")
	must(err)
	must(c.MoveFilter(0, 1, 0))
	must(c.Set(0, Node{Role: "rate_limit"}, "rate", "100"))
	must(c.Set(0, Node{Role: "heartbeat"}, "interval_ms", "5000"))
	must(c.Set(0, Node{Role: "heartbeat"}, "enabled", "true"))
	must(c.AddPipeline("-b"))
	for _, role := range []string{"source", "sink"} {
		_, err = c.Add(1, role, "null")
		must(err)
	}
	must(c.Set(1, Node{Role: "heartbeat"}, "interval_ms", "2000"))
	line, err := c.CommandLine()
	must(err)
	for _, pasted := range []string{line, strings.ReplaceAll(line, "\n", "\r\n")} {
		got, err := FromCommandLine(pasted, nil)
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatalf("%q\n got %+v %v\nwant %+v", pasted, got, err, c)
		}
	}
	data, err := c.JSON()
	must(err)
	if got, err := FromJSON(data); err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("%s\n got %+v %v\nwant %+v", data, got, err, c)
	}
}

// A null in the website's JSON is a value left unset, which every form then
// leaves out, in a table or a list
func TestANullInJSONIsUnset(t *testing.T) {
	with, err := FromJSON([]byte(`[{"name":"p","flow":{"rate_limit":null,"filters":[{"patterns":["a",null]}]},
		"plugin_sources":[{"type":"file","config":{"directory":"/x/","pattern":null}}],
		"plugin_sinks":[{"type":"console","config":{"color":null}}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	without, err := FromJSON([]byte(`[{"name":"p","flow":{"filters":[{"patterns":["a"]}]},
		"plugin_sources":[{"type":"file","config":{"directory":"/x/"}}],"plugin_sinks":[{"type":"console"}]}]`))
	if err != nil || !reflect.DeepEqual(with, without) {
		t.Fatalf("%v\n got %+v\nwant %+v", err, with, without)
	}
}

// The website's JSON refuses a misspelled key as a file does, at any depth
func TestAMisspelledJSONKeyIsRefused(t *testing.T) {
	for _, data := range []string{`[{"name":"p","plugin_source":[]}]`, `[{"name":"p","flow":{"rate_limt":{}}}]`} {
		if _, err := FromJSON([]byte(data)); err == nil || !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: %v", data, err)
		}
	}
}

// The command line and environment carry no control character, which a
// terminal acts on before the shell reads the paste; the file carries it
func TestShellFormsRefuseControlCharacters(t *testing.T) {
	c, err := FromPreset("tail", map[string]string{"path": "/srv/a\x15b/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, line := c.CommandLine()
	_, env := c.Environment()
	if _, err := c.File(); err != nil || line == nil || env == nil {
		t.Fatalf("command line %v, environment %v, file %v", line, env, err)
	}
}

// Set refuses a value of the wrong kind and leaves the key as it was; Unset
// returns a key to its default, dropping a table it leaves empty
func TestSetKeepsAKeyItCannotTake(t *testing.T) {
	c := &Composition{}
	if err := c.AddPipeline("p"); err != nil {
		t.Fatal(err)
	}
	n, _ := c.Add(0, "sink", "tcp")
	beat := Node{Role: "heartbeat"}
	for _, err := range []error{c.Set(0, n, "port", "8080"), c.Set(0, n, "tls.enabled", "true"),
		c.Unset(0, n, "tls.enabled"), c.Set(0, beat, "interval_ms", "5000"), c.Unset(0, beat, "interval_ms")} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Set(0, n, "port", "http"); err == nil || !strings.HasPrefix(err.Error(), "port: ") {
		t.Fatalf("port http: %v", err)
	}
	if m, beat := c.Pipelines[0].PluginSinks[0].Config, c.Pipelines[0].Flow.Heartbeat; !reflect.DeepEqual(m, map[string]any{"port": int64(8080)}) ||
		beat.IntervalMS != 1000 {
		t.Fatalf("options %v, heartbeat %+v", m, beat)
	}
}

// Options are a copy: changing them changes no pipeline; a stage that is off
// has none
func TestOptionsAreACopy(t *testing.T) {
	c := &Composition{}
	if err := c.AddPipeline("p"); err != nil {
		t.Fatal(err)
	}
	n, _ := c.Add(0, "sink", "tcp")
	if err := c.Set(0, n, "port", "9000"); err != nil {
		t.Fatal(err)
	}
	opts, on, err := c.Options(0, n)
	opts["port"] = int64(1)
	if _, rate, _ := c.Options(0, Node{Role: "rate_limit"}); err != nil || !on || rate || c.Pipelines[0].PluginSinks[0].Config["port"] != int64(9000) {
		t.Fatalf("%v %v %v %v", opts, on, rate, err)
	}
}

// A file may leave a source's or sink's id out: the engine names it as a
// spec would, around the ids the file gave, so the shell forms load back
func TestUnnamedPartsTakeFreeIDs(t *testing.T) {
	c, err := FromConfig(&config.Config{Pipelines: []config.PipelineConfig{{Name: "p",
		PluginSources: []config.PluginSourceConfig{{Type: "null"}, {ID: "null", Type: "null"}},
		PluginSinks:   []config.PluginSinkConfig{{Type: "null"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := c.Pipelines[0]
	if ids := []string{p.PluginSources[0].ID, p.PluginSources[1].ID, p.PluginSinks[0].ID}; !slices.Equal(ids, []string{"null_2", "null", "null"}) {
		t.Fatalf("ids %q", ids)
	}
	line, err := c.CommandLine()
	if err == nil {
		_, err = FromCommandLine(line, nil)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, line)
	}
}
