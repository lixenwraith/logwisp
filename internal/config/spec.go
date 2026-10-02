package config

import (
	"cmp"
	"errors"
	"fmt"
	"os"
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
	apply func(p *PipelineConfig, typ string, opts map[string]any) error
}

var specKinds = []specKind{
	{"source", true, true, func(p *PipelineConfig, typ string, opts map[string]any) error {
		ids := make([]string, len(p.PluginSources))
		for i, s := range p.PluginSources {
			ids[i] = s.ID
		}
		id, err := instanceID(typ, opts, ids)
		p.PluginSources = append(p.PluginSources, PluginSourceConfig{ID: id, Type: typ, Config: opts})
		return err
	}},
	{"sink", true, true, func(p *PipelineConfig, typ string, opts map[string]any) error {
		ids := make([]string, len(p.PluginSinks))
		for i, s := range p.PluginSinks {
			ids[i] = s.ID
		}
		id, err := instanceID(typ, opts, ids)
		p.PluginSinks = append(p.PluginSinks, PluginSinkConfig{ID: id, Type: typ, Config: opts})
		return err
	}},
	{"filter", true, true, func(p *PipelineConfig, typ string, opts map[string]any) error {
		if s, ok := opts["patterns"].(string); ok {
			opts["patterns"] = []any{s} // one regex: the decoder must not split it at commas
		}
		opts["type"] = typ
		f := FilterConfig{}
		err := Scan(opts, &f)
		p.Flow.Filters = append(p.Flow.Filters, f)
		return err
	}},
	{"format", true, false, func(p *PipelineConfig, typ string, opts map[string]any) error {
		opts["type"] = typ
		p.Flow.Format = &FormatConfig{}
		return Scan(opts, p.Flow.Format)
	}},
	// Naming a stage turns it on: the file defaults (pass, disabled) would not.
	{"rate-limit", false, false, func(p *PipelineConfig, _ string, opts map[string]any) error {
		p.Flow.RateLimit = &RateLimitConfig{Policy: "drop"}
		return Scan(opts, p.Flow.RateLimit)
	}},
	{"heartbeat", false, false, func(p *PipelineConfig, _ string, opts map[string]any) error {
		p.Flow.Heartbeat = &HeartbeatConfig{Enabled: true}
		return Scan(opts, p.Flow.Heartbeat)
	}},
}

// pipelineSpec is one pipeline flag or variable; a nil kind starts a pipeline.
type pipelineSpec struct {
	name  string // "--sink" or "LOGWISP_SINK_2", for errors
	kind  *specKind
	value string
}

// takePipelineSpecs consumes the pipeline flags, which lixenwraith/config
// would report as unrecognized.
func takePipelineSpecs(args []string) (specs []pipelineSpec, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			return specs, append(rest, args[i:]...), nil
		}
		name, value, inline := strings.Cut(args[i], "=")
		var kind *specKind
		if name != "--pipeline" {
			k := slices.IndexFunc(specKinds, func(k specKind) bool { return "--"+k.flag == name })
			if k < 0 {
				rest = append(rest, args[i])
				continue
			}
			kind = &specKinds[k]
		}
		if !inline && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			value = args[i]
		}
		if value == "" {
			return nil, nil, fmt.Errorf("%s requires a value", name)
		}
		specs = append(specs, pipelineSpec{name, kind, value})
	}
	return specs, rest, nil
}

// envPipelineSpecs reads the one-pipeline environment form. An empty variable
// counts as unset, so container templates may leave optional ones blank.
func envPipelineSpecs() []pipelineSpec {
	var specs []pipelineSpec
	if name := os.Getenv("LOGWISP_PIPELINE"); name != "" {
		specs = append(specs, pipelineSpec{"LOGWISP_PIPELINE", nil, name})
	}
	for i := range specKinds {
		kind := &specKinds[i]
		base := "LOGWISP_" + strings.ToUpper(strings.ReplaceAll(kind.flag, "-", "_"))
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

// buildPipelines turns specs, in order, into pipelines; specs before the first
// --pipeline go to one named "cli". Every call returns fresh maps.
func buildPipelines(specs []pipelineSpec) ([]PipelineConfig, error) {
	var pipelines []PipelineConfig
	var seen map[*specKind]bool
	for _, s := range specs {
		if s.kind == nil || pipelines == nil {
			name := "cli"
			if s.kind == nil {
				name = s.value
			}
			pipelines = append(pipelines, PipelineConfig{Name: name, Flow: &FlowConfig{}})
			seen = map[*specKind]bool{}
			if s.kind == nil {
				continue
			}
		}
		p := &pipelines[len(pipelines)-1]
		if seen[s.kind] && !s.kind.many {
			return nil, fmt.Errorf("%s %s: pipeline %q already has one", s.name, s.value, p.Name)
		}
		seen[s.kind] = true
		typ, opts, err := parseSpec(s.value, s.kind.typed)
		if err != nil {
			return nil, fmt.Errorf("%s %w", s.name, err)
		}
		if err := s.kind.apply(p, typ, opts); err != nil {
			return nil, fmt.Errorf("%s %s: %w", s.name, s.value, err)
		}
	}
	return pipelines, nil
}

// parseSpec reads [TYPE,]key=value,...: dotted keys nest, a repeated key makes
// a list, and a backslash escapes ',', '=' and '\'. Errors name the part.
func parseSpec(spec string, typed bool) (typ string, opts map[string]any, err error) {
	rest, more := spec, true
	if typed {
		typ, rest, more = cutUnescaped(spec, ',')
		if _, _, eq := cutUnescaped(typ, '='); typ == "" || eq {
			return "", nil, fmt.Errorf("%s: missing TYPE", spec)
		}
		typ = unescape(typ)
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
			err = setOption(opts, key, unescape(value))
		}
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", strings.TrimPrefix(typ+","+part, ","), err)
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

// setOption stores value at a dotted key; a second value turns it into a list.
func setOption(opts map[string]any, key, value string) error {
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

// instanceID takes the id option; an unnamed instance gets the first of TYPE,
// TYPE_2, TYPE_3... that no earlier instance of its role holds.
func instanceID(typ string, opts map[string]any, taken []string) (string, error) {
	id, _ := opts["id"].(string)
	if _, set := opts["id"]; set && id == "" {
		return "", errors.New(`"id" takes one non-empty value`)
	}
	delete(opts, "id")
	if id != "" {
		return id, nil
	}
	id = typ
	for n := 2; slices.Contains(taken, id); n++ {
		id = typ + "_" + strconv.Itoa(n)
	}
	return id, nil
}
