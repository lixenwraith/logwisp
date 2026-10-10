package config

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// specKind is one pipeline spec flag. Its environment form is LOGWISP_ plus
// the flag uppercased, '-' as '_'.
type specKind struct {
	flag  string
	typed bool // SPEC starts with TYPE
	many  bool // repeatable within a pipeline; the environment adds _1.._N
	first bool // starts its pipeline, and names it by TYPE unless --pipeline did
	apply func(p *PipelineConfig, typ string, opts map[string]any, isDir IsDir) error
	write func(p *PipelineConfig) []string // its specs that build p's part; nil for preset
}

var specKinds = []specKind{
	{"preset", true, false, true, func(p *PipelineConfig, typ string, opts map[string]any, isDir IsDir) error {
		values := map[string][]string{}
		for k, v := range opts {
			switch v := v.(type) {
			case string:
				values[k] = []string{v}
			case []any: // a repeated key
				for _, e := range v {
					values[k] = append(values[k], e.(string))
				}
			default:
				return fmt.Errorf("preset keys do not nest: %q", k)
			}
		}
		return applyPreset(p, typ, values, isDir)
	}, nil},
	{"source", true, true, false, func(p *PipelineConfig, typ string, opts map[string]any, _ IsDir) error {
		ids := make([]string, len(p.PluginSources))
		for i, s := range p.PluginSources {
			ids[i] = s.ID
		}
		id, err := instanceID(typ, opts, ids)
		p.PluginSources = append(p.PluginSources, PluginSourceConfig{ID: id, Type: typ, Config: opts})
		return cmp.Or(err, Coerce("source", typ, opts))
	}, func(p *PipelineConfig) (specs []string) {
		for _, s := range p.PluginSources {
			specs = append(specs, formatSpec(s.Type, map[string]any{"id": s.ID}, s.Config))
		}
		return specs
	}},
	{"sink", true, true, false, func(p *PipelineConfig, typ string, opts map[string]any, _ IsDir) error {
		ids := make([]string, len(p.PluginSinks))
		for i, s := range p.PluginSinks {
			ids[i] = s.ID
		}
		id, err := instanceID(typ, opts, ids)
		p.PluginSinks = append(p.PluginSinks, PluginSinkConfig{ID: id, Type: typ, Config: opts})
		return cmp.Or(err, Coerce("sink", typ, opts))
	}, func(p *PipelineConfig) (specs []string) {
		for _, s := range p.PluginSinks {
			specs = append(specs, formatSpec(s.Type, map[string]any{"id": s.ID}, s.Config))
		}
		return specs
	}},
	{"filter", true, true, false, func(p *PipelineConfig, typ string, opts map[string]any, _ IsDir) error {
		opts["type"] = typ
		f := FilterConfig{}
		err := Scan(opts, &f)
		p.Flow.Filters = append(p.Flow.Filters, f)
		return err
	}, func(p *PipelineConfig) (specs []string) {
		for _, f := range p.Flow.Filters {
			Fill(&f)
			specs = append(specs, typedSpec(&f))
		}
		return specs
	}},
	{"format", true, false, false, func(p *PipelineConfig, typ string, opts map[string]any, _ IsDir) error {
		opts["type"] = typ
		p.Flow.Format = &FormatConfig{}
		return Scan(opts, p.Flow.Format)
	}, func(p *PipelineConfig) []string {
		if p.Flow.Format == nil {
			return nil
		}
		format := *p.Flow.Format
		Fill(&format)
		return []string{typedSpec(&format)}
	}},
	{"rate-limit", false, false, false, func(p *PipelineConfig, _ string, opts map[string]any, _ IsDir) error {
		p.Flow.RateLimit = &RateLimitConfig{}
		return Scan(StageOn("rate_limit", opts), p.Flow.RateLimit)
	}, func(p *PipelineConfig) []string {
		if p.Flow.RateLimit == nil {
			return nil
		}
		rate := *p.Flow.RateLimit
		Fill(&rate) // the policy, whose default here is drop
		return []string{formatSpec("", Values(&rate))}
	}},
	{"heartbeat", false, false, false, func(p *PipelineConfig, _ string, opts map[string]any, _ IsDir) error {
		p.Flow.Heartbeat = &HeartbeatConfig{}
		return Scan(StageOn("heartbeat", opts), p.Flow.Heartbeat)
	}, func(p *PipelineConfig) []string {
		if p.Flow.Heartbeat == nil {
			return nil
		}
		beat := *p.Flow.Heartbeat
		Fill(&beat)
		m := Values(&beat)
		m["enabled"] = beat.Enabled
		return []string{formatSpec("", m)}
	}},
}

// pipelineSpec is one pipeline flag or variable; a nil kind starts a pipeline.
type pipelineSpec struct {
	name  string // "--sink" or "LOGWISP_SINK_2", for errors
	kind  *specKind
	value string
}

// stageOn are the values naming a flow stage sets, in a spec or an engine
// edit: the file's defaults (pass, disabled) would leave it doing nothing
var stageOn = map[string]map[string]any{"rate_limit": {"policy": "drop"}, "heartbeat": {"enabled": true}}

// StageOn returns opts over the values that turn a flow stage on
func StageOn(stage string, opts map[string]any) map[string]any {
	on := map[string]any{}
	maps.Copy(on, stageOn[stage])
	maps.Copy(on, opts)
	return on
}

// Spec is one pipeline flag: its name without dashes, and its value.
type Spec struct{ Flag, Value string }

// SpecFlag is a pipeline flag, for the parser and lw --schema: its name
// without dashes, its environment variable, which takes _1.._N when Many, and
// whether SPEC starts with TYPE
type SpecFlag struct {
	Flag     string `json:"flag"`
	Variable string `json:"variable"`
	Typed    bool   `json:"typed"`
	Many     bool   `json:"many"`
}

func SpecFlags() []SpecFlag {
	flags := []SpecFlag{{"pipeline", specVariable("pipeline"), false, false}}
	for _, k := range specKinds {
		flags = append(flags, SpecFlag{k.flag, specVariable(k.flag), k.typed, k.many})
	}
	return flags
}

func specVariable(flag string) string {
	return "LOGWISP_" + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}

// cliSpecs looks up the kind of each command-line spec.
func cliSpecs(in []Spec) ([]pipelineSpec, error) {
	var specs []pipelineSpec
	for _, s := range in {
		var kind *specKind
		if s.Flag != "pipeline" {
			k := slices.IndexFunc(specKinds, func(k specKind) bool { return k.flag == s.Flag })
			if k < 0 {
				return nil, fmt.Errorf("--%s is no pipeline flag", s.Flag)
			}
			kind = &specKinds[k]
		}
		if s.Value == "" {
			return nil, fmt.Errorf("--%s requires a value", s.Flag)
		}
		specs = append(specs, pipelineSpec{"--" + s.Flag, kind, s.Value})
	}
	return specs, nil
}

// envPipelineSpecs reads the one-pipeline environment form. An empty variable
// counts as unset, so container templates may leave optional ones blank.
func envPipelineSpecs() []pipelineSpec {
	var specs []pipelineSpec
	if name := os.Getenv(specVariable("pipeline")); name != "" {
		specs = append(specs, pipelineSpec{specVariable("pipeline"), nil, name})
	}
	for i := range specKinds {
		kind := &specKinds[i]
		base := specVariable(kind.flag)
		type numbered struct {
			n          uint64
			name, spec string
		}
		var found []numbered
		for _, kv := range os.Environ() {
			name, spec, _ := strings.Cut(kv, "=")
			suffix, ok := strings.CutPrefix(name, base+"_")
			n, err := strconv.ParseUint(suffix, 10, 64)
			if name == base || ok && kind.many && err == nil {
				found = append(found, numbered{n, name, spec})
			}
		}
		slices.SortFunc(found, func(a, b numbered) int { return cmp.Or(cmp.Compare(a.n, b.n), cmp.Compare(a.name, b.name)) })
		for _, f := range found {
			if f.spec != "" {
				specs = append(specs, pipelineSpec{f.name, kind, f.spec})
			}
		}
	}
	return specs
}

// SpecPipelines builds the pipelines of command-line specs, as Load does
func SpecPipelines(specs []Spec, isDir IsDir) ([]PipelineConfig, error) {
	s, err := cliSpecs(specs)
	if err != nil {
		return nil, err
	}
	return buildPipelines(s, isDir)
}

// buildPipelines turns specs, in order, into pipelines; specs before the first
// --pipeline go to one named "cli". Every call returns fresh maps.
func buildPipelines(specs []pipelineSpec, isDir IsDir) ([]PipelineConfig, error) {
	var pipelines []PipelineConfig
	var seen map[*specKind]bool
	for _, s := range specs {
		if s.kind == nil {
			pipelines = append(pipelines, PipelineConfig{Name: s.value, Flow: &FlowConfig{}})
			seen = map[*specKind]bool{}
			continue
		}
		typ, opts, err := parseSpec(s.value, s.kind.typed)
		if err != nil {
			return nil, fmt.Errorf("%s %w", s.name, err)
		}
		if pipelines == nil {
			name := "cli"
			if s.kind.first {
				name = typ
			}
			pipelines = append(pipelines, PipelineConfig{Name: name, Flow: &FlowConfig{}})
			seen = map[*specKind]bool{}
		}
		p := &pipelines[len(pipelines)-1]
		switch {
		case seen[s.kind] && !s.kind.many:
			return nil, fmt.Errorf("%s %s: pipeline %q already has one", s.name, s.value, p.Name)
		case s.kind.first && len(seen) > 0:
			return nil, fmt.Errorf("%s %s: must start its pipeline", s.name, s.value)
		}
		seen[s.kind] = true
		if err := s.kind.apply(p, typ, opts, isDir); err != nil {
			return nil, fmt.Errorf("%s %s: %w", s.name, s.value, err)
		}
	}
	for i := range pipelines {
		useStdio(&pipelines[i])
	}
	return pipelines, nil
}

// PipelineSpecs writes pipelines as the flags that build them: --pipeline,
// ids, flow stage defaults and heartbeat's enabled explicit, as some flags'
// defaults differ from a file's
func PipelineSpecs(pipelines []PipelineConfig) []Spec {
	var specs []Spec
	for _, p := range pipelines {
		specs = append(specs, Spec{"pipeline", p.Name})
		p.Flow = cmp.Or(p.Flow, &FlowConfig{})
		for _, k := range specKinds {
			if k.write != nil {
				for _, value := range k.write(&p) {
					specs = append(specs, Spec{k.flag, value})
				}
			}
		}
	}
	return specs
}

// typedSpec writes a stage whose type key is its spec's TYPE
func typedSpec(stage any) string {
	m := Values(stage)
	typ, _ := m["type"].(string)
	delete(m, "type")
	return formatSpec(typ, m)
}

// formatSpec writes TYPE[:key=value,...] or key=value,...: tables as dotted
// keys, lists as a repeated key
func formatSpec(typ string, tables ...map[string]any) string {
	var parts []string
	var add func(prefix string, m map[string]any)
	add = func(prefix string, m map[string]any) {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			switch v := m[k].(type) {
			case map[string]any:
				add(prefix+k+".", v)
			case []any:
				for _, e := range v {
					parts = append(parts, escape(prefix+k)+"="+escape(text(e)))
				}
			default:
				parts = append(parts, escape(prefix+k)+"="+escape(text(v)))
			}
		}
	}
	for _, m := range tables {
		add("", m)
	}
	opts := strings.Join(parts, ",")
	if typ == "" || opts == "" {
		return typ + opts
	}
	return typ + ":" + opts
}

func text(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}

// escape is unescape's inverse: ',' and '=' escaped, and '\' where an escape
// would otherwise start, so a regex's \d stays as typed
func escape(s string) string {
	var b strings.Builder
	followed := s + "," // as a value is, unless it ends the spec
	for i := range len(s) {
		if s[i] == ',' || s[i] == '=' || escapes(followed, i) {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Values gives a table's keys that are not zero, as a spec sets them, for the
// composer to edit and Scan back
func Values(v any) map[string]any {
	rv, m := reflect.ValueOf(v).Elem(), map[string]any{}
	for _, o := range options(rv.Type()) {
		switch f := rv.Field(o.index); {
		case f.IsZero():
		case f.Kind() == reflect.String:
			m[o.Name] = f.String()
		case f.Kind() == reflect.Slice:
			var list []any
			for i := range f.Len() {
				list = append(list, f.Index(i).Interface())
			}
			m[o.Name] = list
		default:
			m[o.Name] = f.Interface()
		}
	}
	return m
}

// useStdio makes a pipeline without a source read stdin, and one without a
// sink write stdout, as a filter does.
func useStdio(p *PipelineConfig) {
	pipe := pipeDefault(p.Name)
	if len(p.PluginSources) == 0 {
		p.PluginSources = pipe.PluginSources
	}
	if len(p.PluginSinks) == 0 {
		p.PluginSinks = pipe.PluginSinks
	}
}

// parseSpec reads TYPE[:key=value,...] or key=value,...: TYPE ends at the
// first ':', dotted keys nest, a repeated key makes a list, and a backslash
// escapes ',', '=' and '\'. Errors name the part.
func parseSpec(spec string, typed bool) (typ string, opts map[string]any, err error) {
	rest, more := spec, true
	if typed {
		typ, rest, _ = strings.Cut(spec, ":")
		more = rest != ""
		if head, _, comma := cutUnescaped(typ, ','); comma && !strings.Contains(head, "=") {
			return "", nil, fmt.Errorf("%s: TYPE ends at ':', as in %s:%s", spec, head, spec[len(head)+1:])
		}
		if typ == "" || strings.ContainsAny(typ, "=,\\") {
			return "", nil, fmt.Errorf("%s: missing TYPE", spec)
		}
	}
	opts = map[string]any{}
	for more {
		var part string
		part, rest, more = cutUnescaped(rest, ',')
		key, value, eq := cutUnescaped(part, '=')
		switch key = unescape(key); {
		case !eq:
			err = errors.New(`missing "="`)
		case typed && key == "type":
			err = errors.New(`TYPE already sets "type"`)
		default:
			err = SetOption(opts, key, unescape(value))
		}
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", strings.TrimPrefix(typ+":"+part, ":"), err)
		}
	}
	return typ, opts, nil
}

// cutUnescaped cuts s at its first unescaped sep, leaving escapes in place.
func cutUnescaped(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if escapes(s, i) {
			i++
		} else if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if escapes(s, i) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// escapes keeps any other backslash literal, so regex escapes such as \d pass.
func escapes(s string, i int) bool {
	return s[i] == '\\' && i+1 < len(s) && strings.IndexByte(`,=\`, s[i+1]) >= 0
}

// SetOption stores value at a dotted key; a second value turns it into a list.
func SetOption(opts map[string]any, key, value string) error {
	segments := strings.Split(key, ".")
	if slices.Contains(segments, "") {
		return fmt.Errorf("empty key in %q", key)
	}
	table, last := opts, len(segments)-1
	for i, segment := range segments[:last] {
		switch existing := table[segment].(type) {
		case nil:
			next := map[string]any{}
			table[segment], table = next, next
		case map[string]any:
			table = existing
		default:
			return fmt.Errorf("%q is both a value and a table", strings.Join(segments[:i+1], "."))
		}
	}
	switch existing := table[segments[last]].(type) {
	case nil:
		table[segments[last]] = value
	case string:
		table[segments[last]] = []any{existing, value}
	case []any:
		table[segments[last]] = append(existing, value)
	default:
		return fmt.Errorf("%q is both a table and a value", key)
	}
	return nil
}

// instanceID takes the id option, or FreeID for an unnamed instance
func instanceID(typ string, opts map[string]any, taken []string) (string, error) {
	id, _ := opts["id"].(string)
	if _, set := opts["id"]; set && id == "" {
		return "", errors.New(`"id" takes one non-empty value`)
	}
	delete(opts, "id")
	if id != "" {
		return id, nil
	}
	return FreeID(typ, taken), nil
}

// FreeID is the first of TYPE, TYPE_2, TYPE_3... that no earlier instance of
// its role holds
func FreeID(typ string, taken []string) string {
	id := typ
	for n := 2; slices.Contains(taken, id); n++ {
		id = typ + "_" + strconv.Itoa(n)
	}
	return id
}
