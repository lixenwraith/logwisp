package config

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Preset is a pipeline built from a few keys: --preset NAME:key=value starts
// a pipeline with it. Later flags add sources, sinks and filters, or replace
// its format, rate limit and heartbeat.
type Preset struct {
	Name    string        `json:"name"`
	Summary string        `json:"summary"`
	Params  []PresetParam `json:"keys"`
	build   func(p *PipelineConfig, v map[string]string, isDir IsDir) error
}

// PresetParam is one key. A list takes several values, ',' between them or
// the key repeated; any other key takes one.
type PresetParam struct {
	Name     string `json:"name"`
	Default  string `json:"default,omitempty"`
	Help     string `json:"help"`
	Required bool   `json:"required,omitempty"`
	List     bool   `json:"list,omitempty"`
}

// IsDir tells whether a preset's path is a directory, whose files it follows,
// or a file pattern. Off the target host it is the user's answer, or nil: a
// path ending in '/' is then a directory, one with a glob a pattern, and any
// other fails with ErrPathKind.
type IsDir func(path string) (bool, error)

var ErrPathKind = errors.New("path: a directory or a file pattern?")

// HostIsDir asks this host: a path that does not exist is a pattern
func HostIsDir(path string) (bool, error) {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir(), nil
}

// Keys several presets share
var (
	pathParam   = PresetParam{Name: "path", Help: "file, directory (its files) or glob to follow; default: standard input"}
	fromParam   = PresetParam{Name: "from", Default: "end", Help: "start|end: where reading a file starts"}
	formatParam = func(def string) PresetParam { return PresetParam{Name: "format", Default: def, Help: "raw|txt|json"} }
	tlsParams   = []PresetParam{
		{Name: "cert", Help: "certificate file, for tls=files"},
		{Name: "key", Help: "key file, for tls=files"},
		{Name: "issuer_cert", Help: "CA certificate file (lw tls ca), for tls=issuer"},
		{Name: "issuer_key", Help: "CA key file, for tls=issuer"},
		{Name: "hosts", List: true, Help: "names and addresses, beyond this host's, of a self or issuer certificate; ',' between them"},
	}
	aclParams = []PresetParam{
		{Name: "allow", List: true, Help: "addresses or CIDRs that may connect, of listen's family (either behind proxy=); default: all; ',' between them"},
		{Name: "deny", List: true, Help: "addresses or CIDRs refused, allow or not; ',' between them"},
	}
	transportParam = PresetParam{Name: "transport", Default: "tcp", Help: "tcp|http: tcp_chain or http_chain"}
	userParams     = []PresetParam{
		{Name: "user", Help: "SCRAM user: an edge's login, or a listener's only user in place of users"},
		{Name: "password_file", Help: "file holding user's password; /dev/fd/N or a pipe is read once; default: /dev/tty, which asks"},
	}
)

var presets = []Preset{
	{"pipe", "Standard input to standard output, line for line: lw without a file",
		[]PresetParam{formatParam("raw")},
		func(p *PipelineConfig, v map[string]string, isDir IsDir) error {
			stdio := pipeDefault("")
			p.PluginSources, p.PluginSinks = stdio.PluginSources, stdio.PluginSinks
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			return nil
		}},
	{"tail", "Follow files to standard output, like tail -F",
		[]PresetParam{{Name: "path", Required: true, Help: "file, directory (its files) or glob to follow"}, fromParam, formatParam("raw")},
		func(p *PipelineConfig, v map[string]string, isDir IsDir) error {
			sources, err := pathOrStdin(v, isDir)
			p.PluginSources, p.PluginSinks = sources, pipeDefault("").PluginSinks
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			return err
		}},
	{"serve", "Serve files or standard input live: a browser viewer at /, SSE at /stream",
		slices.Concat([]PresetParam{pathParam, fromParam, formatParam("json"),
			{Name: "listen", Default: "127.0.0.1:8080", Help: "HOST:PORT; [IPV6]:PORT"},
			{Name: "tls", Default: "off", Help: "off|self|issuer|files: a certificate made at startup (self-signed or from issuer_*), or files"},
			{Name: "users", Help: "credentials file (lw auth add-user): readers log in with SCRAM"},
		}, userParams, []PresetParam{
			{Name: "proxy", List: true, Help: "addresses or CIDRs of the TLS-terminating proxies browsers come through; ',' between them"},
			{Name: "viewer", Default: "false", Help: "true: the login page and viewer, behind proxy; without user or users the viewer is always on"},
		}, aclParams, tlsParams),
		func(p *PipelineConfig, v map[string]string, isDir IsDir) error {
			sources, err := pathOrStdin(v, isDir)
			if err != nil {
				return err
			}
			p.PluginSources = sources
			sink, err := listener(v, "off")
			if err != nil {
				return err
			}
			auth, err := scramAuth(v)
			switch {
			case err != nil:
				return err
			case auth != nil && v["tls"] == "off" && v["proxy"] == "":
				return fmt.Errorf("user and users need tls (self, issuer or files), or proxy")
			case auth != nil:
				sink["auth"] = auth
			case v["proxy"] != "":
				return fmt.Errorf("proxy needs user or users: browsers log in with SCRAM")
			}
			if v["proxy"] != "" {
				auth["trusted_proxies"] = list(v["proxy"])
			}
			switch v["viewer"] {
			case "true":
				if v["proxy"] == "" {
					return fmt.Errorf("viewer=true needs proxy, behind which browsers log in; without users the viewer is always on")
				}
				sink["login_page"], sink["viewer_page"] = true, true
			case "false":
			default:
				return fmt.Errorf("viewer %q (valid: true, false)", v["viewer"])
			}
			sink["replay_lines"] = int64(1000) // a browser opened late sees the recent entries
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			p.PluginSinks = append(p.PluginSinks, PluginSinkConfig{ID: "http", Type: "http", Config: sink})
			return nil
		}},
	{"edge", "Forward files or standard input to an aggregator over TLS, authenticated",
		slices.Concat([]PresetParam{pathParam, fromParam,
			{Name: "to", Required: true, Help: "the aggregator's HOST:PORT; [IPV6]:PORT"},
			transportParam,
			{Name: "ca", Help: "CA file that verifies the aggregator; default: system roots"},
			{Name: "pin", Help: "sha256//BASE64 of the aggregator's key, which it logs with tls=self"},
			{Name: "server_name", Help: "name the aggregator's certificate carries; default: to's host"},
		}, userParams, []PresetParam{
			{Name: "cert", Help: "client certificate file, for an aggregator with client_ca"},
			{Name: "key", Help: "client key file"},
			{Name: "node", Help: "origin label; default: this host's name"},
		}),
		func(p *PipelineConfig, v map[string]string, isDir IsDir) error {
			sources, err := pathOrStdin(v, isDir)
			if err != nil {
				return err
			}
			p.PluginSources = sources
			typ, err := chainType(v["transport"])
			if err != nil {
				return err
			}
			host, port, err := splitAddr("to", v["to"])
			if err != nil {
				return err
			}
			tls := map[string]any{"enabled": true}
			for key, option := range map[string]string{"ca": "ca_file", "pin": "pin_sha256", "server_name": "server_name", "cert": "cert_file", "key": "key_file"} {
				if v[key] != "" {
					tls[option] = v[key]
				}
			}
			auth, err := scramAuth(v)
			switch {
			case err != nil:
				return err
			case auth != nil:
			case v["cert"] != "" && v["key"] != "":
				auth = map[string]any{"type": "mtls"}
			default:
				return fmt.Errorf("edge needs user, or cert and key: it never sends unauthenticated")
			}
			sink := map[string]any{"host": host, "port": port, "tls": tls, "auth": auth}
			if v["node"] != "" {
				sink["node"] = v["node"]
			}
			p.PluginSinks = append(p.PluginSinks, PluginSinkConfig{ID: "edge", Type: typ, Config: sink})
			return nil
		}},
	{"aggregator", "Receive from edges over TLS, authenticated, to files or standard output",
		slices.Concat([]PresetParam{
			{Name: "listen", Default: "0.0.0.0:9000", Help: "HOST:PORT; [IPV6]:PORT; [::] for IPv6 only"},
			transportParam,
			{Name: "tls", Default: "self", Help: "self|issuer|files: a certificate made at startup (self-signed or from issuer_*), or files"},
			{Name: "users", Help: "credentials file (lw auth add-user): edges log in with SCRAM"},
		}, userParams, []PresetParam{
			{Name: "client_ca", Help: "CA file that verifies edge certificates (mTLS)"},
			{Name: "out", Help: "directory for the received entries; default: standard output"},
			formatParam("json"),
		}, aclParams, tlsParams),
		func(p *PipelineConfig, v map[string]string, isDir IsDir) error {
			typ, err := chainType(v["transport"])
			if err != nil {
				return err
			}
			if v["tls"] == "off" {
				return fmt.Errorf("tls=off: edges send credentials and logs, the aggregator always serves TLS")
			}
			src, err := listener(v, "self")
			if err != nil {
				return err
			}
			if v["client_ca"] != "" {
				tls := src["tls"].(map[string]any)
				tls["client_auth"], tls["client_ca_file"] = true, v["client_ca"]
			}
			auth, err := scramAuth(v)
			switch {
			case err != nil:
				return err
			case auth != nil:
				src["auth"] = auth
			case v["client_ca"] != "":
				src["auth"] = map[string]any{"type": "mtls"}
			default:
				return fmt.Errorf("aggregator needs user, users or client_ca: it never receives unauthenticated")
			}
			p.PluginSources = append(p.PluginSources, PluginSourceConfig{ID: "edges", Type: typ, Config: src})
			p.PluginSinks = pipeDefault("").PluginSinks
			if v["out"] != "" {
				p.PluginSinks = []PluginSinkConfig{{ID: "file", Type: "file", Config: map[string]any{"directory": v["out"], "name": "aggregate"}}}
			}
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			return nil
		}},
}

// Presets lists the presets, for lw preset
func Presets() []Preset { return slices.Clone(presets) }

// ExpandPreset builds the pipeline a preset makes of values, as --preset does
func ExpandPreset(name string, values map[string]string, isDir IsDir) (PipelineConfig, error) {
	p := PipelineConfig{Flow: &FlowConfig{}}
	each := map[string][]string{}
	for k, v := range values {
		each[k] = []string{v}
	}
	err := applyPreset(&p, name, each, isDir)
	return p, err
}

// applyPreset fills defaults and checks keys before the preset's build
func applyPreset(p *PipelineConfig, name string, values map[string][]string, isDir IsDir) error {
	i := slices.IndexFunc(presets, func(r Preset) bool { return r.Name == name })
	if i < 0 {
		var names []string
		for _, r := range presets {
			names = append(names, r.Name)
		}
		return fmt.Errorf("no preset %q (valid: %s)", name, strings.Join(names, ", "))
	}
	r := presets[i]
	v, keys := map[string]string{}, []string{}
	for _, k := range r.Params {
		v[k.Name] = k.Default
		keys = append(keys, k.Name)
	}
	for k, each := range values {
		j := slices.IndexFunc(r.Params, func(p PresetParam) bool { return p.Name == k })
		switch {
		case j < 0:
			return fmt.Errorf("preset %s has no key %q (valid: %s)", name, k, strings.Join(keys, ", "))
		case len(each) > 1 && !r.Params[j].List:
			return fmt.Errorf("preset %s key %q takes one value", name, k)
		}
		v[k] = cmp.Or(strings.Join(each, ","), v[k])
	}
	for _, k := range r.Params {
		if k.Required && v[k.Name] == "" {
			return fmt.Errorf("preset %s needs %s", name, k.Name)
		}
	}
	p.Name = cmp.Or(p.Name, name)
	return r.build(p, v, isDir)
}

// pathOrStdin follows path: a directory's files, or the files a glob or a
// file name matches in its directory; without one, standard input
func pathOrStdin(v map[string]string, isDir IsDir) ([]PluginSourceConfig, error) {
	path := v["path"]
	if path == "" {
		return pipeDefault("").PluginSources, nil
	}
	dir, err := strings.HasSuffix(path, "/"), error(nil)
	switch {
	case isDir != nil:
		dir, err = isDir(path)
	case !dir && !strings.ContainsAny(path, `*?[\`):
		err = ErrPathKind
	}
	if err != nil {
		return nil, err
	}
	directory, pattern := path, "*"
	if !dir {
		directory, pattern = filepath.Dir(path), filepath.Base(path)
	}
	return []PluginSourceConfig{{ID: "file", Type: "file", Config: map[string]any{"directory": directory, "pattern": pattern, "from": v["from"]}}}, nil
}

// tlsModes is what each preset tls mode sets, and the preset keys it needs
// by the tls option each fills; made marks a certificate made at startup,
// which takes hosts.
var tlsModes = map[string]struct {
	set   map[string]any
	needs map[string]string
	made  bool
}{
	"off":    {},
	"self":   {set: map[string]any{"self_signed": true}, made: true},
	"issuer": {needs: map[string]string{"issuer_cert": "issuer_cert_file", "issuer_key": "issuer_key_file"}, made: true},
	"files":  {needs: map[string]string{"cert": "cert_file", "key": "key_file"}},
}

// listener starts a listening plugin's options: host, port, acl and tls,
// whose mode decides which certificate keys apply.
func listener(v map[string]string, def string) (map[string]any, error) {
	host, port, err := splitAddr("listen", v["listen"])
	if err != nil {
		return nil, err
	}
	opts, acl := map[string]any{"host": host, "port": port}, map[string]any{}
	for _, k := range []string{"allow", "deny"} {
		if v[k] != "" {
			acl[k] = list(v[k])
		}
	}
	if len(acl) > 0 {
		opts["acl"] = acl
	}
	mode := cmp.Or(v["tls"], def)
	m, ok := tlsModes[mode]
	if !ok {
		return nil, fmt.Errorf("tls %q (valid: %s)", mode, strings.Join(slices.Sorted(maps.Keys(tlsModes)), ", "))
	}
	for _, other := range tlsModes {
		for k := range other.needs {
			if _, needed := m.needs[k]; needed && v[k] == "" {
				return nil, fmt.Errorf("tls=%s needs %s", mode, k)
			} else if !needed && v[k] != "" {
				return nil, fmt.Errorf("%s does not apply to tls=%s", k, mode)
			}
		}
	}
	if v["hosts"] != "" && !m.made {
		return nil, fmt.Errorf("hosts does not apply to tls=%s", mode)
	}
	if mode == "off" {
		return opts, nil
	}
	tls := map[string]any{"enabled": true}
	maps.Copy(tls, m.set)
	for k, option := range m.needs {
		tls[option] = v[k]
	}
	if v["hosts"] != "" {
		tls["hosts"] = list(v["hosts"])
	}
	opts["tls"] = tls
	return opts, nil
}

// scramAuth is the scram table of user, whose password the terminal asks for
// unless password_file names it, or of a listener's users file; nil without
func scramAuth(v map[string]string) (map[string]any, error) {
	switch {
	case v["user"] != "" && v["users"] != "":
		return nil, fmt.Errorf("user or users, not both")
	case v["user"] != "":
		return map[string]any{"type": "scram", "username": v["user"], "password_file": cmp.Or(v["password_file"], "/dev/tty")}, nil
	case v["password_file"] != "":
		return nil, fmt.Errorf("password_file needs user")
	case v["users"] != "":
		return map[string]any{"type": "scram", "credentials_file": v["users"]}, nil
	}
	return nil, nil
}

func splitAddr(key, addr string) (string, int64, error) {
	host, p, err := net.SplitHostPort(addr)
	port, perr := strconv.ParseUint(p, 10, 16)
	if err != nil || perr != nil || port == 0 {
		return "", 0, fmt.Errorf("%s %q: want HOST:PORT, an IPv6 address in brackets", key, addr)
	}
	return host, int64(port), nil
}

func chainType(transport string) (string, error) {
	if transport != "tcp" && transport != "http" {
		return "", fmt.Errorf("transport %q (valid: tcp, http)", transport)
	}
	return transport + "_chain", nil
}

func list(s string) []any {
	var out []any
	for e := range strings.SplitSeq(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}
