//go:build js && wasm

// Command lwconf is the configuration engine as WebAssembly: it sets
// globalThis.lwconf for lwconf.js, calls taking strings and returning JSON,
// {"value"} or {"error"} with its path, one in a pipeline placed on its node
// and key, any other a preset's or flag's key. Pipelines are compose's JSON
// form; dirs answers config.IsDir by path; an error's ask is a path to answer.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"syscall/js"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
)

// calls are lwconf's, by name, with the string arguments each takes
var calls = map[string]struct {
	args []string
	call func(args []string) (any, error)
}{
	"schema": {nil, func([]string) (any, error) { return compose.NewSchema(), nil }},
	"preset": {[]string{"name", "values", "dirs"}, func(a []string) (any, error) {
		values, err := presetValues(a[1])
		if err != nil {
			return nil, err
		}
		isDir, err := answers(a[2])
		if err != nil {
			return nil, err
		}
		return pipelines(compose.FromPreset(a[0], values, isDir))
	}},
	"parse": {[]string{"text", "form", "dirs"}, func(a []string) (any, error) {
		f, err := form(a[1])
		if err != nil {
			return nil, err
		}
		isDir, err := answers(a[2])
		if err != nil {
			return nil, err
		}
		c, err := f.Parse(a[0], isDir)
		value, err := pipelines(c, err)
		if err != nil {
			return nil, err
		}
		return map[string]any{"pipelines": value, "left_out": append([]string{}, c.LeftOut...)}, nil
	}},
	"validate": {[]string{"pipelines"}, func(a []string) (any, error) {
		c, err := compose.FromJSON([]byte(a[0]))
		if c == nil {
			return nil, err
		}
		value, err := pipelines(c, nil) // a value of the wrong kind is a problem Validate names
		if err != nil {
			return nil, err
		}
		problems := []problem{}
		for _, p := range compose.Problems(c.Validate()) {
			problems = append(problems, place(p))
		}
		return map[string]any{"pipelines": value, "problems": problems}, nil
	}},
	"emit": {[]string{"pipelines", "form"}, func(a []string) (any, error) {
		c, err := compose.FromJSON([]byte(a[0]))
		if err != nil {
			return nil, err
		}
		f, err := form(a[1])
		if err != nil {
			return nil, err
		}
		return f.Write(c)
	}},
	"edit": {[]string{"pipelines", "op"}, func(a []string) (any, error) {
		c, err := compose.FromJSON([]byte(a[0]))
		if err != nil {
			return nil, err
		}
		var o op
		in := json.NewDecoder(bytes.NewReader([]byte(a[1])))
		in.DisallowUnknownFields()
		if err := in.Decode(&o); err != nil {
			return nil, fmt.Errorf("op: %w", err)
		}
		edit, ok := edits[o.Op]
		if !ok {
			return nil, fmt.Errorf("no op %q (valid: %s)", o.Op, strings.Join(slices.Sorted(maps.Keys(edits)), ", "))
		}
		n, err := edit(c, o)
		if _, ok := errors.AsType[*config.KeyError](err); ok && o.Node.Role != "" {
			err = config.At(o.Node.Path(o.Pipeline), err) // a key set or unset in the node
		}
		value, err := pipelines(c, err)
		if err != nil {
			return nil, err
		}
		return map[string]any{"pipelines": value, "node": n}, nil
	}},
}

// op is one edit: the compose method Op names, and its arguments
type op struct {
	Op       string       `json:"op"`
	Pipeline int          `json:"pipeline"`
	Node     compose.Node `json:"node"`
	Role     string       `json:"role"`
	Type     string       `json:"type"`
	Key      string       `json:"key"`
	Values   []string     `json:"values"`
	Name     string       `json:"name"`
	From     int          `json:"from"`
	To       int          `json:"to"`
}

// edits call compose's edit methods, each returning the node it leaves chosen
var edits = map[string]func(*compose.Composition, op) (compose.Node, error){
	"add_pipeline": func(c *compose.Composition, o op) (compose.Node, error) {
		return compose.Node{}, c.AddPipeline(o.Name)
	},
	"rename_pipeline": func(c *compose.Composition, o op) (compose.Node, error) {
		return compose.Node{}, c.RenamePipeline(o.Pipeline, o.Name)
	},
	"remove_pipeline": func(c *compose.Composition, o op) (compose.Node, error) {
		return compose.Node{}, c.RemovePipeline(o.Pipeline)
	},
	"add": func(c *compose.Composition, o op) (compose.Node, error) { return c.Add(o.Pipeline, o.Role, o.Type) },
	"retype": func(c *compose.Composition, o op) (compose.Node, error) {
		return c.Retype(o.Pipeline, o.Node, o.Type)
	},
	"remove": func(c *compose.Composition, o op) (compose.Node, error) {
		return compose.Node{}, c.Remove(o.Pipeline, o.Node)
	},
	"move_filter": func(c *compose.Composition, o op) (compose.Node, error) {
		return compose.Node{Role: "filters", Index: o.To}, c.MoveFilter(o.Pipeline, o.From, o.To)
	},
	"set": func(c *compose.Composition, o op) (compose.Node, error) {
		return o.Node, c.Set(o.Pipeline, o.Node, o.Key, o.Values...)
	},
	"unset": func(c *compose.Composition, o op) (compose.Node, error) {
		return o.Node, c.Unset(o.Pipeline, o.Node, o.Key)
	},
}

// problem is where a problem, or a call's refusal, lies as far as the engine
// knows: its path, and the pipeline, node and key Locate reads from it; ask
// is a preset's path whose kind dirs must answer
type problem struct {
	Error    string        `json:"error,omitempty"`
	Path     string        `json:"path,omitempty"`
	Pipeline *int          `json:"pipeline,omitempty"`
	Node     *compose.Node `json:"node,omitempty"`
	Key      string        `json:"key,omitempty"`
	Text     string        `json:"text,omitempty"`
	Ask      string        `json:"ask,omitempty"`
}

func place(err error) problem {
	p := problem{Text: err.Error()}
	if ke, ok := errors.AsType[*config.KeyError](err); ok {
		p.Path = ke.Key
	}
	if pk, ok := errors.AsType[*config.PathKindError](err); ok {
		p.Ask = pk.Path
	}
	if pi, n, key, text, ok := compose.Locate(err); ok {
		p.Pipeline, p.Key, p.Text = &pi, key, text
		if n.Role != "" {
			p.Node = &n
		}
	}
	return p
}

// presetValues reads a preset's values: a string each, or a list key's
// strings, which the preset takes ',' between them
func presetValues(data string) (map[string]string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, fmt.Errorf("values: %w", err)
	}
	values := map[string]string{}
	for k, v := range raw {
		var one string
		var many []string
		switch {
		case json.Unmarshal(v, &one) == nil:
			values[k] = one
		case json.Unmarshal(v, &many) == nil:
			values[k] = strings.Join(many, ",")
		default:
			return nil, &config.KeyError{Key: k, Err: errors.New("takes a string, or a list of strings")}
		}
	}
	return values, nil
}

// answers reads dirs: whether each path a preset names is a directory
func answers(dirs string) (config.IsDir, error) {
	var m map[string]bool
	if err := json.Unmarshal([]byte(dirs), &m); err != nil {
		return nil, fmt.Errorf("dirs: %w", err)
	}
	return config.Answers(m), nil
}

func form(name string) (compose.Form, error) {
	forms := compose.Forms()
	if i := slices.IndexFunc(forms, func(f compose.Form) bool { return f.Name == name }); i >= 0 {
		return forms[i], nil
	}
	return compose.Form{}, fmt.Errorf("no form %q", name)
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
	var out any = map[string]any{"value": value}
	if err != nil {
		p := place(err)
		p.Error, p.Text = err.Error(), ""
		out = p
	}
	data, _ := json.Marshal(out)
	return string(data)
}
