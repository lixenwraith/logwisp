package config

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

// Side is how a plugin meets the network, which decides the tls, auth and acl
// keys it takes
type Side int

var sideNames = []string{"local", "listener", "chain_listener", "dialer"}

func (s Side) MarshalText() ([]byte, error) { return []byte(sideNames[s]), nil }

const (
	Local         Side = iota // no network
	Listener                  // the tcp and http sinks
	ChainListener             // the chain sources, which also bind the node label
	Dialer                    // the chain sinks
)

// Plugin is a catalogue row: a source or sink type and its options table
type Plugin struct {
	Role    string `json:"-"` // "source" or "sink"
	Type    string `json:"type"`
	Side    Side   `json:"side"`
	HTTP    bool   `json:"http"`   // speaks HTTP: takes bearer tokens and request limits
	Single  bool   `json:"single"` // one instance per process, as standard input is one
	Summary string `json:"summary"`
	options reflect.Type
}

var plugins = []Plugin{
	{"source", "console", Local, false, true, "Standard input, line by line", reflect.TypeFor[ConsoleSourceOptions]()},
	{"source", "file", Local, false, false, "Follow the files of a directory that match a pattern", reflect.TypeFor[FileSourceOptions]()},
	{"source", "random", Local, false, false, "Generated entries, to check a deployment before real logs", reflect.TypeFor[RandomSourceOptions]()},
	{"source", "null", Local, false, false, "Nothing; holds a source's place until one is chosen", reflect.TypeFor[NullSourceOptions]()},
	{"source", "tcp_chain", ChainListener, false, false, "Receive entries from other nodes' tcp_chain sinks, each over one lasting TCP connection", reflect.TypeFor[TCPChainSourceOptions]()},
	{"source", "http_chain", ChainListener, true, false, "Receive entries from other nodes' http_chain sinks, as batches each posts over HTTP", reflect.TypeFor[HTTPChainSourceOptions]()},
	{"sink", "console", Local, false, false, "Standard output or standard error", reflect.TypeFor[ConsoleSinkOptions]()},
	{"sink", "file", Local, false, false, "Rotating files", reflect.TypeFor[FileSinkOptions]()},
	{"sink", "null", Local, false, false, "Discards; holds a sink's place until one is chosen", reflect.TypeFor[NullSinkOptions]()},
	{"sink", "tcp", Listener, false, false, "Serve entries to TCP clients, one per line", reflect.TypeFor[TCPSinkOptions]()},
	{"sink", "http", Listener, true, false, "Serve entries as server-sent events, with a browser viewer", reflect.TypeFor[HTTPSinkOptions]()},
	{"sink", "tcp_chain", Dialer, false, false, "Forward entries to another node's tcp_chain source over one lasting TCP connection", reflect.TypeFor[TCPChainSinkOptions]()},
	{"sink", "http_chain", Dialer, true, false, "Forward entries to another node's http_chain source in batches, an HTTP POST each", reflect.TypeFor[HTTPChainSinkOptions]()},
}

// Plugins lists the catalogue
func Plugins() []Plugin { return slices.Clone(plugins) }

// Keys describes the plugin's options, its tables holding the keys of its
// side, and HTTP's keys only when it speaks HTTP
func (p Plugin) Keys() []Key { return p.applying(keys(p.options)) }

func (p Plugin) applying(all []Key) []Key {
	out := []Key{}
	for _, k := range all {
		if (k.Side == "" || k.Side == sideNames[p.Side] || k.Side == "listener" && p.Side == ChainListener) && (!k.HTTP || p.HTTP) {
			if k.Keys != nil {
				k.Keys = p.applying(k.Keys)
			}
			out = append(out, k)
		}
	}
	return out
}

// LookupPlugin finds the catalogue row of a source or sink type
func LookupPlugin(role, typ string) (Plugin, bool) {
	i := slices.IndexFunc(plugins, func(p Plugin) bool { return p.Role == role && p.Type == typ })
	if i < 0 {
		return Plugin{}, false
	}
	return plugins[i], true
}

// KeyError is a value refused at one key, which callers prefix with the path
// of the table holding it
type KeyError struct {
	Key string
	Err error
}

func (e *KeyError) Error() string { return e.Key + ": " + e.Err.Error() }
func (e *KeyError) Unwrap() error { return e.Err }

// option is one key of an options table, from its field's tags: toml names
// it, default: holds the default as a command line types it, help: says what
// it does, lw: lists its rules: required, enum=a|b, min=N, max=N, zero=MEANING
// (a value, not the default), hint=KIND, a side (listener, a chain source's
// too; chain_listener; dialer), and http (only plugins that speak HTTP take it).
type option struct {
	Key
	index int
}

// options reads the keys of an options table; a malformed tag panics, as the
// tables are static and every run would fail alike
func options(t reflect.Type) []option {
	var opts []option
	for i := range t.NumField() {
		f := t.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if key == "" || key == "-" {
			continue
		}
		o := option{Key{Name: key, Kind: kinds[f.Type.Kind()], Default: f.Tag.Get("default"), Help: f.Tag.Get("help")}, i}
		for rule := range strings.SplitSeq(f.Tag.Get("lw"), ",") {
			name, value, _ := strings.Cut(rule, "=")
			switch name {
			case "":
			case "required":
				o.Required = true
			case "listener", "chain_listener", "dialer":
				o.Side = name
			case "http":
				o.HTTP = true
			case "enum":
				o.Enum = strings.Split(value, "|")
			case "min", "max":
				n, err := strconv.ParseFloat(value, 64)
				if err != nil {
					panic(fmt.Sprintf("%s.%s: lw %s=%q", t.Name(), key, name, value))
				}
				if name == "min" {
					o.Min = &n
				} else {
					o.Max = &n
				}
			case "zero":
				o.Zero = value
			case "hint":
				o.Hint = value
			default:
				panic(fmt.Sprintf("%s.%s: unknown lw rule %q", t.Name(), key, rule))
			}
		}
		opts = append(opts, o)
	}
	return opts
}

// Key describes one option, for lw --schema and the composer: its tags, and
// its kind, a table's being "table" (tls, auth or acl) with the table's keys
type Key struct {
	Name     string   `json:"key"`
	Kind     string   `json:"kind"`
	Default  string   `json:"default,omitempty"`
	Help     string   `json:"help,omitempty"`
	Required bool     `json:"required,omitempty"`
	Enum     []string `json:"enum,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Zero     string   `json:"zero,omitempty"`
	Hint     string   `json:"hint,omitempty"`
	Side     string   `json:"side,omitempty"`
	HTTP     bool     `json:"http,omitempty"`
	Keys     []Key    `json:"keys,omitempty"`
}

var kinds = map[reflect.Kind]string{reflect.String: "string", reflect.Int64: "integer",
	reflect.Float64: "number", reflect.Bool: "bool", reflect.Slice: "list", reflect.Pointer: "table"}

// Stage is a flow stage: its key in the flow table, whether it is a list (the
// filters), its options, and the values that turn it on, which a file's
// defaults leave off
type Stage struct {
	Key  string         `json:"key"`
	List bool           `json:"list,omitempty"`
	Keys []Key          `json:"keys"`
	On   map[string]any `json:"on,omitempty"`
}

// FlowStages lists the flow table's stages, in the order entries pass them
func FlowStages() []Stage {
	var out []Stage
	t := reflect.TypeFor[FlowConfig]()
	for _, o := range options(t) {
		ft := t.Field(o.index).Type
		out = append(out, Stage{o.Name, ft.Kind() == reflect.Slice, keys(ft.Elem()), maps.Clone(stageOn[o.Name])})
	}
	return out
}

func keys(t reflect.Type) []Key {
	out := []Key{}
	for _, o := range options(t) {
		if o.Kind == "" {
			panic(fmt.Sprintf("%s.%s: no kind", t.Name(), o.Name))
		}
		if ft := t.Field(o.index).Type; ft.Kind() == reflect.Pointer {
			o.Keys = keys(ft.Elem())
		}
		out = append(out, o.Key)
	}
	return out
}

// SettingKeys describes the settings by their dotted paths, with the defaults
// lw has when it reads a file
func SettingKeys() []Key { return settingKeys(reflect.ValueOf(defaults()).Elem(), "") }

func settingKeys(v reflect.Value, prefix string) []Key {
	var out []Key
	for _, o := range options(v.Type()) {
		switch f := v.Field(o.index); f.Kind() {
		case reflect.Pointer:
			out = append(out, settingKeys(f.Elem(), prefix+o.Name+".")...)
		case reflect.Slice: // the pipelines, which their flags set
		default:
			k := o.Key
			k.Name = prefix + k.Name
			if !f.IsZero() {
				k.Default = fmt.Sprint(f.Interface())
			}
			out = append(out, k)
		}
	}
	return out
}

// Decode reads a plugin's config map into its options: unknown keys, kinds,
// the defaults, the tag rules and the options' own Check, then the host, tls,
// acl and auth rules of its side; a leading ~ in a path is the home directory.
// It reads no file.
func Decode[T any](role, typ string, m map[string]any) (*T, error) {
	v, err := decode(role, typ, m)
	if err != nil {
		return nil, err
	}
	return v.(*T), nil
}

func decode(role, typ string, m map[string]any) (any, error) {
	p, ok := LookupPlugin(role, typ)
	if !ok {
		return nil, fmt.Errorf("unknown %s type %q", role, typ)
	}
	if err := checkKeys(m, p.options, ""); err != nil {
		return nil, err
	}
	m = Clone(m)
	if err := coerce(p.options, m, ""); err != nil {
		return nil, err // a file's wrong kind, named by its key
	}
	v := reflect.New(p.options)
	preset(v.Elem(), m)
	if err := lconfig.ScanMap(m, v.Interface()); err != nil {
		return nil, err
	}
	if err := Settle(v.Interface()); err != nil {
		return nil, err
	}
	expandPaths(v.Elem())
	if n, ok := v.Interface().(networked); ok {
		if err := p.checkNetwork(n); err != nil {
			return nil, err
		}
	}
	return v.Interface(), nil
}

// Settle gives a decoded table its defaults, applies the tag rules, then its
// own Check, as Decode does before its side's rules, for the flow stages a
// file decodes typed
func Settle(v any) error {
	Fill(v)
	if err := checkTags(reflect.ValueOf(v).Elem(), ""); err != nil {
		return err
	}
	if c, ok := v.(interface{ Check() error }); ok {
		return c.Check()
	}
	return nil
}

// Fill gives a table its defaults and checks nothing: Settle's first step
func Fill(v any) { settle(reflect.ValueOf(v).Elem()) }

// expandPaths reads ~ (ExpandHome) in the dir and file keys of a table, its
// tables' too, where lw reads them; the forms keep ~ as typed
func expandPaths(v reflect.Value) {
	for _, o := range options(v.Type()) {
		switch f := v.Field(o.index); {
		case f.Kind() == reflect.Pointer && !f.IsNil() && f.Elem().Kind() == reflect.Struct:
			expandPaths(f.Elem())
		case o.Hint == "dir" || o.Hint == "file":
			f.SetString(ExpandHome(f.String()))
		}
	}
}

// ExpandHome reads a leading ~ or ~/ as the home directory; ~user, and a
// host without a home directory (js/wasm), keep the path as it is
func ExpandHome(path string) string {
	rest, ok := strings.CutPrefix(path, "~")
	if !ok || rest != "" && !os.IsPathSeparator(rest[0]) {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home + rest
	}
	return path
}

// preset sets every default before decoding, so a switch that defaults on
// stays on unless set off; it does so in the tables m sets
func preset(v reflect.Value, m map[string]any) {
	for _, o := range options(v.Type()) {
		f := v.Field(o.index)
		if sub, ok := m[o.Name].(map[string]any); ok && f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.Struct {
			f.Set(reflect.New(f.Type().Elem()))
			preset(f.Elem(), sub)
		} else if o.Default != "" {
			setDefault(f, o)
		}
	}
}

// settle gives each zero key its default, unless zero is a value there or
// the key is a switch, whose off a default would override
func settle(v reflect.Value) {
	for _, o := range options(v.Type()) {
		f := v.Field(o.index)
		switch {
		case f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.Struct:
			if !f.IsNil() {
				settle(f.Elem())
			}
		case o.Default != "" && o.Zero == "" && f.Kind() != reflect.Bool && f.IsZero():
			setDefault(f, o)
		}
	}
}

func setDefault(f reflect.Value, o option) {
	var err error
	switch f.Kind() {
	case reflect.String:
		f.SetString(o.Default)
	case reflect.Int64:
		var n int64
		n, err = strconv.ParseInt(o.Default, 10, 64)
		f.SetInt(n)
	case reflect.Float64:
		var n float64
		n, err = strconv.ParseFloat(o.Default, 64)
		f.SetFloat(n)
	case reflect.Bool:
		var b bool
		b, err = strconv.ParseBool(o.Default)
		f.SetBool(b)
	default:
		err = errors.New("no default for this kind")
	}
	if err != nil {
		panic(fmt.Sprintf("%s: default %q: %v", o.Name, o.Default, err))
	}
}

// checkTags applies the tag rules to a table's own keys, naming each by
// prefix and key. A zero number is the default or its zero meaning, and
// meets the range unless required; an empty enum is one only by its zero
// or default.
func checkTags(v reflect.Value, prefix string) error {
	for _, o := range options(v.Type()) {
		f := v.Field(o.index)
		var err error
		switch {
		case o.Required && (f.IsZero() || f.Kind() == reflect.String && strings.TrimSpace(f.String()) == ""):
			err = errors.New("must be set")
		case f.Kind() == reflect.String && len(o.Enum) > 0 && (f.String() != "" || o.Zero == "" && o.Default == "") && !slices.Contains(o.Enum, f.String()):
			err = fmt.Errorf("must be one of %s, got %q", strings.Join(o.Enum, ", "), f.String())
		case f.CanFloat() || f.CanInt():
			if f.IsZero() && !o.Required {
				break
			}
			n := float64(0)
			if f.CanInt() {
				n = float64(f.Int())
			} else {
				n = f.Float()
			}
			switch {
			case math.IsNaN(n) || math.IsInf(n, 0):
				err = errors.New("must be a finite number")
			case o.Min != nil && o.Max != nil && !(n >= *o.Min && n <= *o.Max):
				err = fmt.Errorf("must be from %s to %s, got %s", num(*o.Min), num(*o.Max), num(n))
			case o.Min != nil && !(n >= *o.Min):
				err = fmt.Errorf("must be at least %s, got %s", num(*o.Min), num(n))
			case o.Max != nil && !(n <= *o.Max):
				err = fmt.Errorf("must be at most %s, got %s", num(*o.Max), num(n))
			}
		}
		if err != nil {
			return &KeyError{prefix + o.Name, err}
		}
	}
	return nil
}

func num(n float64) string { return strconv.FormatFloat(n, 'f', -1, 64) }

// sideKeys lists, in order, the keys of a table that apply to one side only
func sideKeys(t reflect.Type, side string) []string {
	var keys []string
	for _, o := range options(t) {
		if o.Side == side {
			keys = append(keys, o.Name)
		}
	}
	return keys
}

// Coerce gives command-line and environment values, which are strings, and
// JSON's floats the kinds a plugin's options declare, so a dump prints them
// typed. Keys and types it does not know are Decode's to refuse.
func Coerce(role, typ string, m map[string]any) error {
	p, ok := LookupPlugin(role, typ)
	if !ok {
		return nil
	}
	return coerce(p.options, m, "")
}

func coerce(t reflect.Type, m map[string]any, prefix string) error {
	for _, o := range options(t) {
		value, ok := m[o.Name]
		if !ok {
			continue
		}
		ft := t.Field(o.index).Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if sub, ok := value.(map[string]any); ok && ft.Kind() == reflect.Struct {
			if err := coerce(ft, sub, prefix+o.Name+"."); err != nil {
				return err
			}
			continue
		}
		v, err := coerceValue(ft.Kind(), value)
		if err != nil {
			return &KeyError{prefix + o.Name, err}
		}
		m[o.Name] = v
	}
	return nil
}

// coerceValue converts text, a JSON float for an integer and a TOML integer
// for a number; its errors never hold the value, which may be a misplaced secret
func coerceValue(kind reflect.Kind, value any) (any, error) {
	s, text := value.(string)
	n, integer := value.(int64)
	switch {
	case kind == reflect.Float64 && integer:
		return float64(n), nil
	case kind == reflect.Slice && text:
		return []any{s}, nil
	case kind == reflect.Int64 && text:
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n, nil
		}
		return nil, errors.New("not an integer")
	case kind == reflect.Int64:
		if f, ok := value.(float64); ok {
			if f != math.Trunc(f) || math.Abs(f) > 1<<53 {
				return nil, errors.New("not an integer within 2^53")
			}
			return int64(f), nil
		}
	case kind == reflect.Float64 && text:
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, nil
		}
		return nil, errors.New("not a number")
	case kind == reflect.Bool && text:
		if b, err := strconv.ParseBool(s); err == nil {
			return b, nil
		}
		return nil, errors.New("not true or false")
	}
	return value, nil
}

// Clone copies an options map with its tables and lists, so decoding or an
// edit leaves the caller's map be
func Clone(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = cloneValue(v)
	}
	return c
}

func cloneValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		return Clone(v)
	case []any:
		return slices.Clone(v)
	}
	return v
}
