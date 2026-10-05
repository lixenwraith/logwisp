package config

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Preset is a pipeline built from a few keys: --preset NAME,key=value starts
// a pipeline with it. Later flags add sources, sinks and filters, or replace
// its format, rate limit and heartbeat.
type Preset struct {
	Name, Summary string
	Params        []PresetParam
	build         func(p *PipelineConfig, v map[string]string) error
}

// PresetParam is one key. A list takes several values, ',' between them or
// the key repeated; any other key takes one.
type PresetParam struct {
	Name, Default, Help string
	Required, List      bool
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
		{Name: "allow", List: true, Help: "addresses or CIDRs that may connect, of listen's family; default: all; ',' between them"},
		{Name: "deny", List: true, Help: "addresses or CIDRs refused, allow or not; ',' between them"},
	}
	transportParam = PresetParam{Name: "transport", Default: "tcp", Help: "tcp|http: tcp_chain or http_chain"}
)

var presets = []Preset{
	{"pipe", "Standard input to standard output, line for line: lw without a file",
		[]PresetParam{formatParam("raw")},
		func(p *PipelineConfig, v map[string]string) error {
			stdio := pipeDefault("")
			p.PluginSources, p.PluginSinks = stdio.PluginSources, stdio.PluginSinks
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			return nil
		}},
	{"tail", "Follow files to standard output, like tail -F",
		[]PresetParam{{Name: "path", Required: true, Help: "file, directory (its files) or glob to follow"}, fromParam, formatParam("raw")},
		func(p *PipelineConfig, v map[string]string) error {
			p.PluginSources, p.PluginSinks = pathOrStdin(v), pipeDefault("").PluginSinks
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			return nil
		}},
	{"serve", "Serve files or standard input live: a browser viewer at /, SSE at /stream",
		slices.Concat([]PresetParam{pathParam, fromParam, formatParam("json"),
			{Name: "listen", Default: "127.0.0.1:8080", Help: "HOST:PORT; [IPV6]:PORT"},
			{Name: "tls", Default: "off", Help: "off|self|issuer|files: a certificate made at startup (self-signed or from issuer_*), or files"},
			{Name: "users", Help: "credentials file (lw auth add-user): readers log in with SCRAM"},
			{Name: "proxy", List: true, Help: "addresses or CIDRs of the TLS-terminating proxies browsers come through; ',' between them"},
			{Name: "viewer", Default: "false", Help: "true: the login page and viewer for users, behind proxy; without users the viewer is always on"},
		}, aclParams, tlsParams),
		func(p *PipelineConfig, v map[string]string) error {
			p.PluginSources = pathOrStdin(v)
			sink, err := listener(v, "off")
			if err != nil {
				return err
			}
			if v["users"] != "" {
				sink["auth"] = map[string]any{"type": "scram", "credentials_file": v["users"]}
			}
			if v["proxy"] != "" {
				auth, ok := sink["auth"].(map[string]any)
				if !ok {
					return fmt.Errorf("proxy needs users: browsers log in with SCRAM")
				}
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
			p.Flow.Format = &FormatConfig{Type: v["format"]}
			p.PluginSinks = append(p.PluginSinks, PluginSinkConfig{ID: "http", Type: "http", Config: sink})
			return nil
		}},
	{"edge", "Forward files or standard input to an aggregator over TLS, authenticated",
		[]PresetParam{pathParam, fromParam,
			{Name: "to", Required: true, Help: "the aggregator's HOST:PORT; [IPV6]:PORT"},
			transportParam,
			{Name: "ca", Help: "CA file that verifies the aggregator; default: system roots"},
			{Name: "pin", Help: "sha256//BASE64 of the aggregator's key, which it logs with tls=self"},
			{Name: "server_name", Help: "name the aggregator's certificate carries; default: to's host"},
			{Name: "user", Help: "SCRAM user (lw auth add-user on the aggregator)"},
			{Name: "password_file", Help: "file holding the SCRAM password"},
			{Name: "cert", Help: "client certificate file, for an aggregator with client_ca"},
			{Name: "key", Help: "client key file"},
			{Name: "node", Help: "origin label; default: this host's name"},
		},
		func(p *PipelineConfig, v map[string]string) error {
			p.PluginSources = pathOrStdin(v)
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
			var auth map[string]any
			switch {
			case v["user"] != "" && v["password_file"] != "":
				auth = map[string]any{"type": "scram", "username": v["user"], "password_file": v["password_file"]}
			case v["user"] != "" || v["password_file"] != "":
				return fmt.Errorf("user and password_file go together")
			case v["cert"] != "" && v["key"] != "":
				auth = map[string]any{"type": "mtls"}
			default:
				return fmt.Errorf("edge needs user and password_file, or cert and key: it never sends unauthenticated")
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
			{Name: "client_ca", Help: "CA file that verifies edge certificates (mTLS)"},
			{Name: "out", Help: "directory for the received entries; default: standard output"},
			formatParam("json"),
		}, aclParams, tlsParams),
		func(p *PipelineConfig, v map[string]string) error {
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
			switch {
			case v["users"] != "":
				src["auth"] = map[string]any{"type": "scram", "credentials_file": v["users"]}
			case v["client_ca"] != "":
				src["auth"] = map[string]any{"type": "mtls"}
			default:
				return fmt.Errorf("aggregator needs users or client_ca: it never receives unauthenticated")
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
func ExpandPreset(name string, values map[string]string) (PipelineConfig, error) {
	p := PipelineConfig{Flow: &FlowConfig{}}
	each := map[string][]string{}
	for k, v := range values {
		each[k] = []string{v}
	}
	err := applyPreset(&p, name, each)
	return p, err
}

// applyPreset fills defaults and checks keys before the preset's build
func applyPreset(p *PipelineConfig, name string, values map[string][]string) error {
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
	return r.build(p, v)
}

func pathOrStdin(v map[string]string) []PluginSourceConfig {
	if v["path"] == "" {
		return pipeDefault("").PluginSources
	}
	return []PluginSourceConfig{fileSource(v["path"], v["from"])}
}

// fileSource follows path: a directory's files, or the files a glob or a
// file name matches in its directory.
func fileSource(path, from string) PluginSourceConfig {
	dir, pattern := path, "*"
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		dir, pattern = filepath.Dir(path), filepath.Base(path)
	}
	return PluginSourceConfig{ID: "file", Type: "file", Config: map[string]any{"directory": dir, "pattern": pattern, "from": from}}
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
