package config

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	lconfig "github.com/lixenwraith/config"
)

// Side is how a plugin meets the network, which decides the tls, auth and acl
// keys it takes
type Side int

const (
	Local         Side = iota // no network
	Listener                  // the tcp and http sinks
	ChainListener             // the chain sources, which also bind the node label
	Dialer                    // the chain sinks
)

// Plugin is a catalogue row: a source or sink type and its options table
type Plugin struct {
	Role, Type string // "source" or "sink", and the type its config names
	Side       Side
	HTTP       bool // speaks HTTP: takes bearer tokens and request limits
	Single     bool // one instance per process
	Summary    string
	options    reflect.Type
}

var plugins = []Plugin{
	{"source", "console", Local, false, true, "Standard input, line by line", reflect.TypeFor[ConsoleSourceOptions]()},
	{"source", "file", Local, false, false, "Follow the files of a directory that match a pattern", reflect.TypeFor[FileSourceOptions]()},
	{"source", "random", Local, false, false, "Random entries, for tests", reflect.TypeFor[RandomSourceOptions]()},
	{"source", "null", Local, false, false, "Nothing, ever", reflect.TypeFor[NullSourceOptions]()},
	{"source", "tcp_chain", ChainListener, false, false, "Entries from tcp_chain sinks of other instances", reflect.TypeFor[TCPChainSourceOptions]()},
	{"source", "http_chain", ChainListener, true, false, "Entry batches from http_chain sinks of other instances", reflect.TypeFor[HTTPChainSourceOptions]()},
	{"sink", "console", Local, false, false, "Standard output or standard error", reflect.TypeFor[ConsoleSinkOptions]()},
	{"sink", "file", Local, false, false, "Rotating files", reflect.TypeFor[FileSinkOptions]()},
	{"sink", "null", Local, false, false, "Discard", reflect.TypeFor[NullSinkOptions]()},
	{"sink", "tcp", Listener, false, false, "Serve entries to TCP clients, one per line", reflect.TypeFor[TCPSinkOptions]()},
	{"sink", "http", Listener, true, false, "Serve entries as server-sent events, with a browser viewer", reflect.TypeFor[HTTPSinkOptions]()},
	{"sink", "tcp_chain", Dialer, false, false, "Forward entries to a tcp_chain source", reflect.TypeFor[TCPChainSinkOptions]()},
	{"sink", "http_chain", Dialer, true, false, "Post entry batches to an http_chain source", reflect.TypeFor[HTTPChainSinkOptions]()},
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
// it, default: holds the default as typed on a command line, help: says what
// it does, and lw: lists its rules: required, enum=a|b, min=N, max=N,
// zero=MEANING (zero is a value, not the default), hint=KIND, listener or dialer.
type option struct {
	key, def, help string
	required       bool
	enum           []string
	min, max       *float64
	zero           string
	hint, side     string
	index          int
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
		o := option{key: key, def: f.Tag.Get("default"), help: f.Tag.Get("help"), index: i}
		for rule := range strings.SplitSeq(f.Tag.Get("lw"), ",") {
			name, value, _ := strings.Cut(rule, "=")
			switch name {
			case "":
			case "required":
				o.required = true
			case "listener", "dialer":
				o.side = name
			case "enum":
				o.enum = strings.Split(value, "|")
			case "min", "max":
				n, err := strconv.ParseFloat(value, 64)
				if err != nil {
					panic(fmt.Sprintf("%s.%s: lw %s=%q", t.Name(), key, name, value))
				}
				if name == "min" {
					o.min = &n
				} else {
					o.max = &n
				}
			case "zero":
				o.zero = value
			case "hint":
				o.hint = value
			default:
				panic(fmt.Sprintf("%s.%s: unknown lw rule %q", t.Name(), key, rule))
			}
		}
		opts = append(opts, o)
	}
	return opts
}

// Decode reads a plugin's config map into its options: unknown keys, kinds,
// the defaults, the tag rules, the tls, auth and acl rules of its side, then the
// options' own Check. It reads no file.
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
	m = clone(m)
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
	if n, ok := v.Interface().(networked); ok {
		if err := p.checkNetwork(n); err != nil {
			return nil, err
		}
	}
	return v.Interface(), nil
}

// Settle gives a decoded table its defaults, applies the tag rules, then its
// own Check: Decode's last steps, for the flow stages a file decodes typed
func Settle(v any) error {
	rv := reflect.ValueOf(v).Elem()
	settle(rv)
	if err := checkTags(rv, ""); err != nil {
		return err
	}
	if c, ok := v.(interface{ Check() error }); ok {
		return c.Check()
	}
	return nil
}

// preset sets every default before decoding, so a switch that defaults on
// stays on unless set off; it does so in the tables m sets
func preset(v reflect.Value, m map[string]any) {
	for _, o := range options(v.Type()) {
		f := v.Field(o.index)
		if sub, ok := m[o.key].(map[string]any); ok && f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.Struct {
			f.Set(reflect.New(f.Type().Elem()))
			preset(f.Elem(), sub)
		} else if o.def != "" {
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
		case o.def != "" && o.zero == "" && f.Kind() != reflect.Bool && f.IsZero():
			setDefault(f, o)
		}
	}
}

func setDefault(f reflect.Value, o option) {
	var err error
	switch f.Kind() {
	case reflect.String:
		f.SetString(o.def)
	case reflect.Int64:
		var n int64
		n, err = strconv.ParseInt(o.def, 10, 64)
		f.SetInt(n)
	case reflect.Float64:
		var n float64
		n, err = strconv.ParseFloat(o.def, 64)
		f.SetFloat(n)
	case reflect.Bool:
		var b bool
		b, err = strconv.ParseBool(o.def)
		f.SetBool(b)
	default:
		err = errors.New("no default for this kind")
	}
	if err != nil {
		panic(fmt.Sprintf("%s: default %q: %v", o.key, o.def, err))
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
		case o.required && (f.IsZero() || f.Kind() == reflect.String && strings.TrimSpace(f.String()) == ""):
			err = errors.New("must be set")
		case f.Kind() == reflect.String && len(o.enum) > 0 && (f.String() != "" || o.zero == "" && o.def == "") && !slices.Contains(o.enum, f.String()):
			err = fmt.Errorf("must be one of %s, got %q", strings.Join(o.enum, ", "), f.String())
		case f.CanFloat() || f.CanInt():
			if f.IsZero() && !o.required {
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
			case o.min != nil && o.max != nil && !(n >= *o.min && n <= *o.max):
				err = fmt.Errorf("must be from %s to %s, got %s", num(*o.min), num(*o.max), num(n))
			case o.min != nil && !(n >= *o.min):
				err = fmt.Errorf("must be at least %s, got %s", num(*o.min), num(n))
			case o.max != nil && !(n <= *o.max):
				err = fmt.Errorf("must be at most %s, got %s", num(*o.max), num(n))
			}
		}
		if err != nil {
			return &KeyError{prefix + o.key, err}
		}
	}
	return nil
}

func num(n float64) string { return strconv.FormatFloat(n, 'f', -1, 64) }

// sideKeys lists, in order, the keys of a table that apply to one side only
func sideKeys(t reflect.Type, side string) []string {
	var keys []string
	for _, o := range options(t) {
		if o.side == side {
			keys = append(keys, o.key)
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
		value, ok := m[o.key]
		if !ok {
			continue
		}
		ft := t.Field(o.index).Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if sub, ok := value.(map[string]any); ok && ft.Kind() == reflect.Struct {
			if err := coerce(ft, sub, prefix+o.key+"."); err != nil {
				return err
			}
			continue
		}
		v, err := coerceValue(ft.Kind(), value)
		if err != nil {
			return &KeyError{prefix + o.key, err}
		}
		m[o.key] = v
	}
	return nil
}

// coerceValue converts text, and a JSON float for an integer; its errors
// never hold the value, which may be a misplaced secret
func coerceValue(kind reflect.Kind, value any) (any, error) {
	s, text := value.(string)
	switch {
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

// clone copies m and the tables in it, so decoding leaves the caller's map be
func clone(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			v = clone(sub)
		}
		c[k] = v
	}
	return c
}
