package config

import (
	"cmp"
	"fmt"
	"strings"
	"testing"

	schema "github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/toml"
)

// The sample lists every key of the settings, the flow stages and each
// catalogued plugin, tls, auth and acl included, with the schema's default;
// a line marked example shows another value
func TestSampleListsEveryKeyWithItsDefault(t *testing.T) {
	all, shown := uncommented(t, true), uncommented(t, false)
	for _, k := range schema.SettingKeys() {
		i := strings.LastIndex(k.Name, ".") + 1
		at := k.Name[:i]
		k.Name = k.Name[i:]
		checkKeys(t, at, []schema.Key{k}, table(all, at), table(shown, at))
	}
	pipeline, pipelineShown := first(all["pipelines"]), first(shown["pipelines"])
	for _, stage := range schema.FlowStages() {
		checkKeys(t, "flow."+stage.Key+".", stage.Keys, first(table(pipeline, "flow")[stage.Key]), first(table(pipelineShown, "flow")[stage.Key]))
	}
	for _, p := range schema.Plugins() {
		list := "plugin_" + p.Role + "s"
		block := ofType(pipeline[list], p.Type)
		if block == nil {
			t.Errorf("%s %s: no block in the sample", p.Type, p.Role)
			continue
		}
		checkKeys(t, p.Type+" "+p.Role+": ", p.Keys(), table(block, "config"), table(ofType(pipelineShown[list], p.Type), "config"))
	}
}

// uncommented is the sample with its commented keys and tables made active
// (prose stays under "##"); without examples it drops the lines marked so
func uncommented(t *testing.T, examples bool) map[string]any {
	t.Helper()
	var b strings.Builder
	for line := range strings.Lines(string(Sample)) {
		line = strings.TrimPrefix(line, "# ")
		if _, comment, _ := strings.Cut(line, " # "); examples || !strings.Contains(comment, "example") {
			b.WriteString(line)
		}
	}
	root, err := toml.NewParser([]byte(b.String())).Parse()
	if err != nil {
		t.Fatalf("the sample uncommented: %v", err)
	}
	return root
}

// zeros is how the sample writes a kind's zero, the default of a key without one
var zeros = map[string]string{"integer": "0", "number": "0", "bool": "false", "list": "[]"}

// checkKeys finds each key in all, the sample, and compares the value shown,
// without examples, with the default
func checkKeys(t *testing.T, path string, keys []schema.Key, all, shown map[string]any) {
	t.Helper()
	for _, k := range keys {
		_, ok := all[k.Name]
		switch want := cmp.Or(k.Default, zeros[k.Kind]); {
		case !ok:
			t.Errorf("%s%s: not in the sample", path, k.Name)
		case k.Kind == "table":
			checkKeys(t, path+k.Name+".", k.Keys, table(all, k.Name), table(shown, k.Name))
		default:
			if v, ok := shown[k.Name]; ok && fmt.Sprint(v) != want {
				t.Errorf("%s%s = %v, the default is %q", path, k.Name, v, want)
			}
		}
	}
}

// table descends a dotted path of tables
func table(m map[string]any, path string) map[string]any {
	for key := range strings.SplitSeq(path, ".") {
		if key != "" {
			m, _ = m[key].(map[string]any)
		}
	}
	return m
}

// first is a table, or the first of an array of tables
func first(v any) map[string]any {
	if list, ok := v.([]map[string]any); ok && len(list) > 0 {
		return list[0]
	}
	m, _ := v.(map[string]any)
	return m
}

// ofType is the block of an array of plugin tables with the type given
func ofType(v any, typ string) map[string]any {
	list, _ := v.([]map[string]any)
	for _, m := range list {
		if m["type"] == typ {
			return m
		}
	}
	return nil
}
