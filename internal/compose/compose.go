// Package compose is the configuration engine lw --tui and the website share:
// pipelines started empty, from a preset, a configuration or a command line,
// edited, validated, and written as a command line, environment or file. It
// reads no file and links no network or terminal code, so it builds as WebAssembly.
package compose

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/version"

	"github.com/lixenwraith/toml"
)

// Composition is the pipelines being composed. Its flow stages hold their
// defaults and its plugin options the kinds they declare, so each form it
// writes loads back to the same pipelines.
type Composition struct {
	Pipelines []config.PipelineConfig
}

// Node is a part of a pipeline: a source or sink by its id, or a flow stage
// by its key in the flow table: filters with an index, format, rate_limit or
// heartbeat
type Node struct {
	Role  string
	ID    string
	Index int
}

// FromConfig starts from a loaded configuration's pipelines, its console sinks
// leaving the top-level color inherited
func FromConfig(cfg *config.Config) (*Composition, error) {
	c := &Composition{}
	for _, p := range cfg.Pipelines {
		c.Pipelines = append(c.Pipelines, copyPipeline(p))
	}
	config.Uninherit(c.Pipelines, cfg.Color)
	return c, c.settle()
}

// FromPreset starts from a preset's pipeline; isDir answers whether its path
// is a directory, nil off the target host (see config.IsDir)
func FromPreset(name string, values map[string]string, isDir config.IsDir) (*Composition, error) {
	p, err := config.ExpandPreset(name, values, isDir)
	if err != nil {
		return nil, err
	}
	c := &Composition{Pipelines: []config.PipelineConfig{p}}
	return c, c.settle()
}

// FromCommandLine starts from a pasted lw command line, quoted as a POSIX
// shell reads it; it takes pipeline flags only, at least one, as a composition
// holds no settings
func FromCommandLine(line string, isDir config.IsDir) (*Composition, error) {
	words, err := split(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(line)) // pasted line ends
	if err != nil {
		return nil, err
	}
	if len(words) > 0 && (words[0] == "lw" || strings.HasSuffix(words[0], "/lw")) {
		words = words[1:]
	}
	var specs []config.Spec
	for i := 0; i < len(words); i++ {
		name, value, inline := strings.Cut(words[i], "=")
		if name == "-p" {
			name = "--preset"
		}
		flag, long := strings.CutPrefix(name, "--")
		if !long || !slices.ContainsFunc(config.SpecFlags(), func(f config.SpecFlag) bool { return f.Flag == flag }) {
			return nil, fmt.Errorf("%s: not a pipeline flag", words[i])
		}
		if !inline {
			if i++; i == len(words) || strings.HasPrefix(words[i], "-") {
				return nil, fmt.Errorf("%s requires a value; one that starts with '-' follows '='", name)
			}
			value = words[i]
		}
		specs = append(specs, config.Spec{Flag: flag, Value: value})
	}
	if len(specs) == 0 {
		return nil, errors.New("no pipeline flags")
	}
	pipelines, err := config.SpecPipelines(specs, isDir)
	if err != nil {
		return nil, err
	}
	c := &Composition{Pipelines: pipelines}
	return c, c.settle()
}

// settle gives every flow stage its defaults, every plugin's options their
// kinds and every source and sink an id; the rules are Validate's
func (c *Composition) settle() error {
	for i := range c.Pipelines {
		p := &c.Pipelines[i]
		if p.Flow == nil {
			p.Flow = &config.FlowConfig{}
		}
		name(len(p.PluginSources), func(j int) *string { return &p.PluginSources[j].ID },
			func(j int) string { return p.PluginSources[j].Type })
		name(len(p.PluginSinks), func(j int) *string { return &p.PluginSinks[j].ID },
			func(j int) string { return p.PluginSinks[j].Type })
		for _, stage := range stages(p.Flow) {
			if !stage.IsNil() {
				config.Fill(stage.Interface())
			}
		}
		for j := range p.Flow.Filters {
			config.Fill(&p.Flow.Filters[j])
		}
		for j, s := range p.PluginSources {
			p.PluginSources[j].Config = orEmpty(s.Config)
			if err := config.Coerce("source", s.Type, p.PluginSources[j].Config); err != nil {
				return config.At(fmt.Sprintf("pipelines[%d].plugin_sources[%s].config", i, s.ID), err)
			}
		}
		for j, s := range p.PluginSinks {
			p.PluginSinks[j].Config = orEmpty(s.Config)
			if err := config.Coerce("sink", s.Type, p.PluginSinks[j].Config); err != nil {
				return config.At(fmt.Sprintf("pipelines[%d].plugin_sinks[%s].config", i, s.ID), err)
			}
		}
	}
	return nil
}

// name gives the parts a file left unnamed the ids their specs would get: the
// shell forms write no empty id
func name(n int, id func(int) *string, typ func(int) string) {
	var taken []string
	for j := range n {
		if *id(j) != "" {
			taken = append(taken, *id(j))
		}
	}
	for j := range n {
		if *id(j) == "" {
			*id(j) = config.FreeID(typ(j), taken)
			taken = append(taken, *id(j))
		}
	}
}

// stages are the flow table's fields that hold one stage each, by key: a
// pointer, nil while the stage is off. The filters are a list.
func stages(f *config.FlowConfig) map[string]reflect.Value {
	v, out := reflect.ValueOf(f).Elem(), map[string]reflect.Value{}
	for i := range v.NumField() {
		if v.Field(i).Kind() == reflect.Pointer {
			key, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("toml"), ",")
			out[key] = v.Field(i)
		}
	}
	return out
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func (c *Composition) pipeline(i int) (*config.PipelineConfig, error) {
	if i < 0 || i >= len(c.Pipelines) {
		return nil, fmt.Errorf("no pipeline %d", i)
	}
	return &c.Pipelines[i], nil
}

// AddPipeline appends an empty pipeline under a name no other has
func (c *Composition) AddPipeline(name string) error {
	if err := c.free(name, -1); err != nil {
		return err
	}
	c.Pipelines = append(c.Pipelines, config.PipelineConfig{Name: name, Flow: &config.FlowConfig{}})
	return nil
}

// RenamePipeline gives pipeline i a name no other has
func (c *Composition) RenamePipeline(i int, name string) error {
	p, err := c.pipeline(i)
	if err == nil {
		err = c.free(name, i)
	}
	if err != nil {
		return err
	}
	p.Name = name
	return nil
}

// free refuses a name that is empty or held by a pipeline other than i
func (c *Composition) free(name string, i int) error {
	if j := slices.IndexFunc(c.Pipelines, func(p config.PipelineConfig) bool { return p.Name == name }); name == "" || j >= 0 && j != i {
		return fmt.Errorf("pipeline %q: a name no other pipeline has", name)
	}
	return nil
}

func (c *Composition) RemovePipeline(i int) error {
	if _, err := c.pipeline(i); err != nil {
		return err
	}
	c.Pipelines = slices.Delete(c.Pipelines, i, i+1)
	return nil
}

// Add appends a source or sink of a catalogue type under config.FreeID, or a
// filter of type include or exclude, and returns its node
func (c *Composition) Add(pi int, role, typ string) (Node, error) {
	p, err := c.pipeline(pi)
	if err != nil {
		return Node{}, err
	}
	var ids []string
	switch role {
	case "source":
		for _, s := range p.PluginSources {
			ids = append(ids, s.ID)
		}
	case "sink":
		for _, s := range p.PluginSinks {
			ids = append(ids, s.ID)
		}
	case "filters":
		f := config.FilterConfig{Type: config.FilterType(typ)}
		config.Fill(&f)
		p.Flow.Filters = append(p.Flow.Filters, f)
		return Node{Role: role, Index: len(p.Flow.Filters) - 1}, nil
	default:
		return Node{}, fmt.Errorf("cannot add to %s", role)
	}
	if _, ok := config.LookupPlugin(role, typ); !ok {
		return Node{}, fmt.Errorf("unknown %s type %q", role, typ)
	}
	n := Node{Role: role, ID: config.FreeID(typ, ids)}
	if role == "source" {
		p.PluginSources = append(p.PluginSources, config.PluginSourceConfig{ID: n.ID, Type: typ, Config: map[string]any{}})
	} else {
		p.PluginSinks = append(p.PluginSinks, config.PluginSinkConfig{ID: n.ID, Type: typ, Config: map[string]any{}})
	}
	return n, nil
}

// Retype gives a source or sink another type of its role, in its place: a
// chosen id stays and an automatic one follows the type. Options of the same
// name and kind carry over to a type on the same network side, where they
// mean the same; across sides host, port, tls and auth do not.
func (c *Composition) Retype(pi int, n Node, typ string) (Node, error) {
	p, err := c.pipeline(pi)
	if err != nil {
		return Node{}, err
	}
	to, ok := config.LookupPlugin(n.Role, typ)
	if !ok {
		return Node{}, fmt.Errorf("unknown %s type %q", n.Role, typ)
	}
	var id, old *string
	var opts *map[string]any
	var ids []string
	switch i := index(p, n); {
	case i >= 0 && n.Role == "source":
		id, old, opts = &p.PluginSources[i].ID, &p.PluginSources[i].Type, &p.PluginSources[i].Config
		for _, s := range p.PluginSources {
			ids = append(ids, s.ID)
		}
	case i >= 0 && n.Role == "sink":
		id, old, opts = &p.PluginSinks[i].ID, &p.PluginSinks[i].Type, &p.PluginSinks[i].Config
		for _, s := range p.PluginSinks {
			ids = append(ids, s.ID)
		}
	default:
		return Node{}, n.missing()
	}
	from, _ := config.LookupPlugin(n.Role, *old)
	kept := map[string]any{}
	for _, k := range from.Keys() {
		same := func(t config.Key) bool { return t.Name == k.Name && t.Kind == k.Kind }
		if v, set := (*opts)[k.Name]; set && from.Side == to.Side && slices.ContainsFunc(to.Keys(), same) {
			kept[k.Name] = v
		}
	}
	suffix, auto := strings.CutPrefix(*id, *old)
	if n, err := strconv.Atoi(strings.TrimPrefix(suffix, "_")); auto && (suffix == "" || suffix[0] == '_' && err == nil && n > 1) {
		*id = config.FreeID(typ, slices.DeleteFunc(ids, func(s string) bool { return s == *id }))
	}
	*old, *opts = typ, kept
	return Node{Role: n.Role, ID: *id}, nil
}

// Remove deletes a source, sink or filter, or turns a flow stage off
func (c *Composition) Remove(pi int, n Node) error {
	p, err := c.pipeline(pi)
	if err != nil {
		return err
	}
	switch i := index(p, n); {
	case i < 0:
	case n.Role == "source":
		p.PluginSources = slices.Delete(p.PluginSources, i, i+1)
		return nil
	case n.Role == "sink":
		p.PluginSinks = slices.Delete(p.PluginSinks, i, i+1)
		return nil
	case n.Role == "filters":
		p.Flow.Filters = slices.Delete(p.Flow.Filters, i, i+1)
		return nil
	}
	if stage, ok := stages(p.Flow)[n.Role]; ok {
		stage.SetZero()
		return nil
	}
	return n.missing()
}

// index finds a node in its list, -1 when it is in none
func index(p *config.PipelineConfig, n Node) int {
	switch n.Role {
	case "source":
		return slices.IndexFunc(p.PluginSources, func(s config.PluginSourceConfig) bool { return s.ID == n.ID })
	case "sink":
		return slices.IndexFunc(p.PluginSinks, func(s config.PluginSinkConfig) bool { return s.ID == n.ID })
	case "filters":
		if n.Index >= 0 && n.Index < len(p.Flow.Filters) {
			return n.Index
		}
	}
	return -1
}

func (n Node) missing() error {
	if n.Role == "filters" {
		return fmt.Errorf("no filter %d", n.Index)
	}
	return fmt.Errorf("no %s %q", n.Role, n.ID)
}

// MoveFilter moves a filter to index to; entries pass filters in order
func (c *Composition) MoveFilter(pi, from, to int) error {
	p, err := c.pipeline(pi)
	if err != nil {
		return err
	}
	if n := len(p.Flow.Filters); from < 0 || from >= n || to < 0 || to >= n {
		return fmt.Errorf("no filter %d or %d", from, to)
	}
	f := p.Flow.Filters[from]
	p.Flow.Filters = slices.Insert(slices.Delete(p.Flow.Filters, from, from+1), to, f)
	return nil
}

// Set gives a key at a dotted path its values: one, or several for a list. A
// flow stage that is off turns on. A value of the wrong kind leaves the key as
// it was; any other rule is Validate's.
func (c *Composition) Set(pi int, n Node, key string, values ...string) error {
	return c.edit(pi, n, func(m map[string]any) error {
		unset(m, strings.Split(key, "."))
		for _, v := range values {
			if err := config.SetOption(m, key, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// Unset returns a key to its default
func (c *Composition) Unset(pi int, n Node, key string) error {
	return c.edit(pi, n, func(m map[string]any) error {
		unset(m, strings.Split(key, "."))
		return nil
	})
}

// unset deletes a dotted key, and the tables it leaves empty
func unset(m map[string]any, path []string) {
	if sub, ok := m[path[0]].(map[string]any); ok && len(path) > 1 {
		if unset(sub, path[1:]); len(sub) > 0 {
			return
		}
	}
	delete(m, path[0])
}

// edit changes a copy of a node's options, which replaces them when they
// decode to the kinds they declare
func (c *Composition) edit(pi int, n Node, change func(map[string]any) error) error {
	p, err := c.pipeline(pi)
	if err != nil {
		return err
	}
	plugin := func(typ string, m *map[string]any) error {
		next := config.Clone(*m)
		if err := change(next); err != nil {
			return err
		}
		if err := config.Coerce(n.Role, typ, next); err != nil {
			return err
		}
		*m = next
		return nil
	}
	switch i := index(p, n); {
	case i < 0:
	case n.Role == "source":
		return plugin(p.PluginSources[i].Type, &p.PluginSources[i].Config)
	case n.Role == "sink":
		return plugin(p.PluginSinks[i].Type, &p.PluginSinks[i].Config)
	case n.Role == "filters":
		filter := &p.Flow.Filters[i]
		if err := editStage(reflect.ValueOf(&filter).Elem(), "", change); err != nil {
			return err
		}
		p.Flow.Filters[i] = *filter
		return nil
	}
	if stage, ok := stages(p.Flow)[n.Role]; ok {
		return editStage(stage, n.Role, change)
	}
	return n.missing()
}

// editStage edits a stage's keys as a spec sets them; the table they scan into
// replaces the stage, which turns on as a spec turns it on
func editStage(stage reflect.Value, key string, change func(map[string]any) error) error {
	m := config.StageOn(key, nil)
	if !stage.IsNil() {
		m = config.Values(stage.Interface())
	}
	if err := change(m); err != nil {
		return err
	}
	next := reflect.New(stage.Type().Elem())
	if err := config.Scan(m, next.Interface()); err != nil {
		return err
	}
	config.Fill(next.Interface())
	stage.Set(next)
	return nil
}

// Options returns a copy of a node's options that are set, and whether it is
// on: a flow stage that is off has none
func (c *Composition) Options(pi int, n Node) (map[string]any, bool, error) {
	p, err := c.pipeline(pi)
	if err != nil {
		return nil, false, err
	}
	switch i := index(p, n); {
	case i < 0:
	case n.Role == "source":
		return config.Clone(p.PluginSources[i].Config), true, nil
	case n.Role == "sink":
		return config.Clone(p.PluginSinks[i].Config), true, nil
	case n.Role == "filters":
		return config.Values(&p.Flow.Filters[i]), true, nil
	}
	if stage, ok := stages(p.Flow)[n.Role]; ok {
		if stage.IsNil() {
			return nil, false, nil
		}
		return config.Values(stage.Interface()), true, nil
	}
	return nil, false, n.missing()
}

// Validate applies every rule lw applies at load, naming the refused key's path
func (c *Composition) Validate() error { return config.ValidatePipelines(c.Pipelines) }

// CommandLine writes the composition as an lw command line, a flag a line,
// quoted for a POSIX shell
func (c *Composition) CommandLine() (string, error) {
	specs, err := c.shellSpecs()
	if err != nil {
		return "", err
	}
	lines := []string{"lw"}
	for _, s := range specs {
		if strings.HasPrefix(s.Value, "-") {
			lines = append(lines, quote("--"+s.Flag+"="+s.Value))
		} else {
			lines = append(lines, "--"+s.Flag+" "+quote(s.Value))
		}
	}
	return strings.Join(lines, " \\\n  ") + "\n", nil
}

// Environment writes the composition as LOGWISP_ variables, KEY='value' a
// line as an environment file holds them; the environment holds one pipeline
func (c *Composition) Environment() (string, error) {
	if len(c.Pipelines) != 1 {
		return "", fmt.Errorf("the environment holds one pipeline, not %d", len(c.Pipelines))
	}
	specs, err := c.shellSpecs()
	if err != nil {
		return "", err
	}
	flags, count := config.SpecFlags(), map[string]int{}
	var b strings.Builder
	for _, s := range specs {
		f := flags[slices.IndexFunc(flags, func(f config.SpecFlag) bool { return f.Flag == s.Flag })]
		name := f.Variable
		if f.Many {
			count[f.Flag]++
			name += "_" + strconv.Itoa(count[f.Flag])
		}
		fmt.Fprintf(&b, "%s='%s'\n", name, strings.ReplaceAll(s.Value, "'", `'\''`))
	}
	return b.String(), nil
}

// shellSpecs are the specs of a valid composition, for a form pasted into a
// shell, which carries no control character: a terminal acts on ^U or ESC
// before the shell reads the line
func (c *Composition) shellSpecs() ([]config.Spec, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	specs, pipeline := config.PipelineSpecs(c.Pipelines), ""
	for _, s := range specs {
		if s.Flag == "pipeline" {
			pipeline = s.Value
		}
		if strings.ContainsFunc(s.Value, func(r rune) bool { return unicode.IsControl(r) || r == utf8.RuneError }) {
			return nil, fmt.Errorf("pipeline %q: a --%s value holds a control character, which only the file form carries", pipeline, s.Flag)
		}
	}
	return specs, nil
}

// File writes the composition as a configuration file's pipelines, as lw
// --dump prints them
func (c *Composition) File() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return toml.Marshal(map[string]any{"pipelines": c.Pipelines})
}

// Form is a way to write a composition, named for what it is: each loads back
// to the same pipelines
type Form struct {
	Name, Hint string
	Write      func(*Composition) (string, error)
}

var forms = []Form{
	{"command", "lw's flags", (*Composition).CommandLine},
	{"environment", "LOGWISP_ variables: one pipeline", (*Composition).Environment},
	{"file", "a configuration file's pipelines", func(c *Composition) (string, error) {
		data, err := c.File()
		return string(data), err
	}},
}

// Forms are what a composition writes: lw --tui prints one, the website shows them
func Forms() []Form { return slices.Clone(forms) }

// FromJSON starts from pipelines as the website keeps them: a JSON list of
// tables in a file's shape, a misspelled key refused as a file's is, a null
// a value left unset
func FromJSON(data []byte) (*Composition, error) {
	var tables any
	if err := json.Unmarshal(data, &tables); err != nil {
		return nil, err
	}
	cfg := &config.Config{}
	if err := config.Scan(map[string]any{"pipelines": dropNulls(tables)}, cfg); err != nil {
		return nil, err
	}
	return FromConfig(cfg)
}

// dropNulls removes JSON's nulls from tables and lists, which the shell forms
// would write as text
func dropNulls(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			if e == nil {
				delete(v, k)
			} else {
				v[k] = dropNulls(e)
			}
		}
	case []any:
		v = slices.DeleteFunc(v, func(e any) bool { return e == nil })
		for i, e := range v {
			v[i] = dropNulls(e)
		}
		return v
	}
	return v
}

// JSON writes the pipelines as FromJSON reads them, keyed as File writes them
func (c *Composition) JSON() ([]byte, error) {
	data, err := toml.Marshal(map[string]any{"pipelines": c.Pipelines})
	if err != nil {
		return nil, err
	}
	root, err := toml.NewParser(data).Parse()
	if err != nil {
		return nil, err
	}
	return json.Marshal(root["pipelines"])
}

// quote leaves a word of these characters bare, and single-quotes any other,
// or one starting with '=', which zsh expands
func quote(word string) string {
	const bare = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
	if word != "" && word[0] != '=' && strings.Trim(word, bare) == "" {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

// split reads words as a POSIX shell does, without expansions: quotes, '\'
// escapes, and '\' before a newline continuing the line
func split(line string) ([]string, error) {
	var words []string
	var word strings.Builder
	in := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line):
			if i++; line[i] != '\n' {
				word.WriteByte(line[i])
				in = true
			}
		case c == '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated '")
			}
			word.WriteString(line[i+1 : i+1+end])
			i, in = i+1+end, true
		case c == '"':
			for i, in = i+1, true; ; i++ {
				if i == len(line) {
					return nil, errors.New(`unterminated "`)
				}
				if line[i] == '"' {
					break
				}
				if line[i] == '\\' && i+1 < len(line) && strings.IndexByte("$`\"\\\n", line[i+1]) >= 0 {
					if i++; line[i] == '\n' {
						continue
					}
				}
				word.WriteByte(line[i])
			}
		case c == ' ' || c == '\t' || c == '\n':
			if in {
				words, in = append(words, word.String()), false
				word.Reset()
			}
		default:
			word.WriteByte(c)
			in = true
		}
	}
	if in {
		words = append(words, word.String())
	}
	return words, nil
}

func copyPipeline(p config.PipelineConfig) config.PipelineConfig {
	f := config.FlowConfig{}
	if p.Flow != nil {
		f = *p.Flow
	}
	for _, stage := range stages(&f) {
		if !stage.IsNil() {
			next := reflect.New(stage.Type().Elem())
			next.Elem().Set(stage.Elem())
			stage.Set(next)
		}
	}
	f.Filters = slices.Clone(f.Filters)
	for i := range f.Filters {
		f.Filters[i].Patterns = slices.Clone(f.Filters[i].Patterns)
	}
	p.Flow = &f
	p.PluginSources = slices.Clone(p.PluginSources)
	for i, s := range p.PluginSources {
		p.PluginSources[i].Config = config.Clone(orEmpty(s.Config))
	}
	p.PluginSinks = slices.Clone(p.PluginSinks)
	for i, s := range p.PluginSinks {
		p.PluginSinks[i].Config = config.Clone(orEmpty(s.Config))
	}
	return p
}

// Schema is what lw --schema prints, and the website builds its catalogue
// from. A setting's flag is --KEY, a pipeline flag's --FLAG.
type Schema struct {
	Version  string                  `json:"version"`
	Settings []Setting               `json:"settings"`
	Flags    []config.SpecFlag       `json:"pipeline_flags"`
	Flow     []config.Stage          `json:"flow"`
	Tables   map[string][]config.Key `json:"tables"`
	Sources  []Plugin                `json:"sources"`
	Sinks    []Plugin                `json:"sinks"`
	Presets  []config.Preset         `json:"presets"`
}

// Setting is a settings key with its environment variable
type Setting struct {
	config.Key
	Variable string `json:"variable"`
}

// Plugin is a catalogue row with its options
type Plugin struct {
	config.Plugin
	Keys []config.Key `json:"keys"`
}

func NewSchema() Schema {
	s := Schema{
		Version: version.Short(),
		Flags:   config.SpecFlags(),
		Flow:    config.FlowStages(),
		Tables: map[string][]config.Key{
			"tls":  config.KeysOf[config.TLSOptions](),
			"auth": config.KeysOf[config.AuthOptions](),
			"acl":  config.KeysOf[config.ACLOptions](),
		},
		Presets: config.Presets(),
	}
	for _, k := range config.SettingKeys() {
		s.Settings = append(s.Settings, Setting{k, "LOGWISP_" + strings.ToUpper(strings.ReplaceAll(k.Name, ".", "_"))})
	}
	for _, p := range config.Plugins() {
		if p.Role == "source" {
			s.Sources = append(s.Sources, Plugin{p, p.Keys()})
		} else {
			s.Sinks = append(s.Sinks, Plugin{p, p.Keys()})
		}
	}
	return s
}
