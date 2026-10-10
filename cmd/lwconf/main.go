//go:build js && wasm

// Command lwconf is the configuration engine as WebAssembly, for the website.
// It sets globalThis.lwconf, whose calls take strings and return a JSON object:
// {"value": ...}, or {"error": "..."} for a call refused. Pipelines travel in
// compose's JSON form; off the host a preset's directory path ends in '/'.
package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"syscall/js"

	"github.com/lixenwraith/logwisp/internal/compose"
)

// calls are lwconf's, by name, with the string arguments each takes
var calls = map[string]struct {
	args []string
	call func(args []string) (any, error)
}{
	"schema": {nil, func([]string) (any, error) { return compose.NewSchema(), nil }},
	"preset": {[]string{"name", "values"}, func(a []string) (any, error) {
		var values map[string]string
		if err := json.Unmarshal([]byte(a[1]), &values); err != nil {
			return nil, fmt.Errorf("values: %w", err)
		}
		return pipelines(compose.FromPreset(a[0], values, nil))
	}},
	"parse": {[]string{"line"}, func(a []string) (any, error) {
		return pipelines(compose.FromCommandLine(a[0], nil))
	}},
	"validate": {[]string{"pipelines"}, func(a []string) (any, error) {
		c, err := compose.FromJSON([]byte(a[0]))
		if err == nil {
			err = c.Validate()
		}
		return pipelines(c, err)
	}},
	"emit": {[]string{"pipelines", "form"}, func(a []string) (any, error) {
		c, err := compose.FromJSON([]byte(a[0]))
		if err != nil {
			return nil, err
		}
		forms := compose.Forms()
		if i := slices.IndexFunc(forms, func(f compose.Form) bool { return f.Name == a[1] }); i >= 0 {
			return forms[i].Write(c)
		}
		return nil, fmt.Errorf("no form %q", a[1])
	}},
}

// pipelines is a composition's value: its pipelines settled, ids given
func pipelines(c *compose.Composition, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	data, err := c.JSON()
	return json.RawMessage(data), err
}

func main() {
	api := map[string]any{}
	for name := range calls {
		api[name] = js.FuncOf(func(_ js.Value, args []js.Value) any { return answer(name, args) })
	}
	js.Global().Set("lwconf", js.ValueOf(api))
	select {} // the page calls in until it closes
}

// answer is a call's JSON for the page: its value, or why it was refused
func answer(name string, args []js.Value) string {
	c := calls[name]
	value, err := any(nil), fmt.Errorf("usage: lwconf.%s(%s), each a string", name, strings.Join(c.args, ", "))
	if len(args) == len(c.args) && !slices.ContainsFunc(args, func(v js.Value) bool { return v.Type() != js.TypeString }) {
		strs := make([]string, len(args))
		for i, arg := range args {
			strs[i] = arg.String()
		}
		value, err = c.call(strs)
	}
	out := map[string]any{"value": value}
	if err != nil {
		out = map[string]any{"error": err.Error()}
	}
	data, _ := json.Marshal(out)
	return string(data)
}
