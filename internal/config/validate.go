package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/lixenwraith/logwisp/internal/chain"
	"github.com/lixenwraith/logwisp/internal/core"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/toml"
)

// ValidateConfig checks a configuration without reading a file it names:
// the settings, then each pipeline's flow stages, and its sources and sinks
// decoded in full, naming the path of a refused key. lw --check opens them.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := checkTags(reflect.ValueOf(cfg).Elem(), ""); err != nil {
		return err
	}
	if l := cfg.Logging; l != nil {
		if err := checkTags(reflect.ValueOf(l).Elem(), "logging."); err != nil {
			return err
		}
		if l.Console != nil {
			if err := checkTags(reflect.ValueOf(l.Console).Elem(), "logging.console."); err != nil {
				return err
			}
		}
	}

	return ValidatePipelines(cfg.Pipelines)
}

// ValidatePipelines is ValidateConfig's check of the pipelines
func ValidatePipelines(pipelines []PipelineConfig) error {
	if len(pipelines) == 0 {
		return fmt.Errorf("no pipelines configured")
	}
	// Reject duplicate pipeline names (service map is keyed by name)
	names := make(map[string]struct{}, len(pipelines))
	for i, p := range pipelines {
		if _, dup := names[p.Name]; dup {
			return fmt.Errorf("pipeline[%d]: duplicate name %q", i, p.Name)
		}
		names[p.Name] = struct{}{}
	}
	single := map[string]string{} // role and type of a single-instance plugin: its pipeline
	for i, p := range pipelines {
		if err := lconfig.NonEmpty(p.Name); err != nil {
			return fmt.Errorf("pipeline[%d].name: %w", i, err)
		}
		if len(p.PluginSources) == 0 {
			return fmt.Errorf("pipeline[%d]: no sources defined", i)
		}
		if len(p.PluginSinks) == 0 {
			return fmt.Errorf("pipeline[%d]: no sinks defined", i)
		}
		if err := checkFlow(p.Flow, fmt.Sprintf("pipelines[%d].flow", i)); err != nil {
			return err
		}
		ids := map[string]bool{}
		check := func(role, list, id, typ string, m map[string]any) error {
			path := fmt.Sprintf("pipelines[%d].%s[%s]", i, list, id)
			plugin, ok := LookupPlugin(role, typ)
			switch {
			case ids[list+id]:
				return fmt.Errorf("%s: duplicate id", path)
			case !ok:
				return fmt.Errorf("%s.type: unknown %s type %q", path, role, typ)
			case plugin.Single && single[role+typ] != "":
				return fmt.Errorf("pipeline %q: one %s %s may run, and pipeline %q has it", p.Name, typ, role, single[role+typ])
			}
			ids[list+id] = true
			if plugin.Single {
				single[role+typ] = p.Name
			}
			if _, err := decode(role, typ, m); err != nil {
				return at(path+".config", err)
			}
			return nil
		}
		for _, s := range p.PluginSources {
			if err := check("source", "plugin_sources", s.ID, s.Type, s.Config); err != nil {
				return err
			}
		}
		for _, s := range p.PluginSinks {
			if err := check("sink", "plugin_sinks", s.ID, s.Type, s.Config); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkFlow settles copies of a pipeline's flow stages, which keep their
// defaults for the dump
func checkFlow(f *FlowConfig, path string) error {
	if f == nil {
		return nil
	}
	stages := map[string]any{}
	if f.Heartbeat != nil {
		stages["heartbeat"] = new(*f.Heartbeat)
	}
	if f.RateLimit != nil {
		stages["rate_limit"] = new(*f.RateLimit)
	}
	if f.Format != nil {
		stages["format"] = new(*f.Format)
	}
	for i, filter := range f.Filters {
		stages[fmt.Sprintf("filters[%d]", i)] = &filter
	}
	for _, key := range slices.Sorted(maps.Keys(stages)) {
		if err := Settle(stages[key]); err != nil {
			return at(path+"."+key, err)
		}
	}
	return nil
}

// at prefixes err with the path of the table it was found in
func at(path string, err error) error {
	if ke, ok := errors.AsType[*KeyError](err); ok {
		return fmt.Errorf("%s.%s: %w", path, ke.Key, ke.Err)
	}
	return fmt.Errorf("%s: %w", path, err)
}

// networked is the options of a plugin that listens or dials
type networked interface {
	network() (host string, tls *TLSOptions, auth *AuthOptions, acl *ACLOptions)
}

func (o *TCPChainSourceOptions) network() (string, *TLSOptions, *AuthOptions, *ACLOptions) {
	return o.Host, o.TLS, o.Auth, o.ACL
}
func (o *HTTPChainSourceOptions) network() (string, *TLSOptions, *AuthOptions, *ACLOptions) {
	return o.Host, o.TLS, o.Auth, o.ACL
}
func (o *TCPSinkOptions) network() (string, *TLSOptions, *AuthOptions, *ACLOptions) {
	return o.Host, o.TLS, o.Auth, o.ACL
}
func (o *HTTPSinkOptions) network() (string, *TLSOptions, *AuthOptions, *ACLOptions) {
	return o.Host, o.TLS, o.Auth, o.ACL
}
func (o *TCPChainSinkOptions) network() (string, *TLSOptions, *AuthOptions, *ACLOptions) {
	return o.Host, o.TLS, o.Auth, nil
}
func (o *HTTPChainSinkOptions) network() (string, *TLSOptions, *AuthOptions, *ACLOptions) {
	return o.Host, o.TLS, o.Auth, nil
}

// checkNetwork applies the host, tls, acl and auth rules of the plugin's side
func (p Plugin) checkNetwork(n networked) error {
	host, t, a, acl := n.network()
	if _, err := core.Network(host); err != nil {
		return &KeyError{"host", err}
	}
	if err := t.Check(p.Side != Dialer); err != nil {
		return err
	}
	if err := acl.Check(host, p.HTTP, a != nil && len(a.TrustedProxies) > 0); err != nil {
		return err
	}
	return a.Check(p.Side, p.HTTP, t.State())
}

// Check holds the rules between tls keys on a listener or a dialer; a table
// not enabled is ignored whole
func (o *TLSOptions) Check(listener bool) error {
	if o == nil || !o.Enabled {
		return nil
	}
	v := reflect.ValueOf(o).Elem()
	if err := checkTags(v, "tls."); err != nil {
		return err
	}
	other := "dialer"
	if !listener {
		other = "listener"
	}
	for _, opt := range options(v.Type()) {
		if f := v.Field(opt.index); opt.Side == other && !f.IsZero() && (f.Kind() != reflect.Slice || f.Len() > 0) {
			return fmt.Errorf("tls: %s apply to %ss", and(sideKeys(v.Type(), other)), other)
		}
	}
	files, issuer := o.CertFile != "" || o.KeyFile != "", o.IssuerCertFile != "" || o.IssuerKeyFile != ""
	switch {
	case !listener && o.PinSHA256 != "" && (o.CAFile != "" || o.InsecureSkipVerify):
		return fmt.Errorf("tls: pin_sha256 replaces ca_file and insecure_skip_verify: set one")
	case !listener:
	case files && (issuer || o.SelfSigned) || issuer && o.SelfSigned:
		return fmt.Errorf("tls: set one of cert_file and key_file, self_signed, or issuer_cert_file and issuer_key_file")
	case len(o.Hosts) > 0 && !issuer && !o.SelfSigned:
		return fmt.Errorf("tls: hosts applies to self_signed and issuer certificates")
	case issuer && (o.IssuerCertFile == "" || o.IssuerKeyFile == ""):
		return fmt.Errorf("tls: issuer_cert_file and issuer_key_file must be set together")
	case !files && !issuer && !o.SelfSigned:
		return fmt.Errorf("tls: listeners need cert_file and key_file, self_signed, or issuer_cert_file and issuer_key_file")
	case o.ClientAuth && o.ClientCAFile == "":
		return fmt.Errorf("tls: client_auth requires client_ca_file")
	}
	if (o.CertFile == "") != (o.KeyFile == "") {
		return fmt.Errorf("tls: cert_file and key_file must be set together")
	}
	if o.PinSHA256 != "" {
		_, err := ParsePins(o.PinSHA256)
		return err
	}
	return nil
}

// PinPrefix starts each pin_sha256 entry
const PinPrefix = "sha256//"

// ParsePins reads pin_sha256: SHA-256 hashes of server keys, ';' between several
func ParsePins(s string) ([][]byte, error) {
	var pins [][]byte
	for p := range strings.SplitSeq(s, ";") {
		b64, ok := strings.CutPrefix(strings.TrimSpace(p), PinPrefix)
		h, err := base64.StdEncoding.DecodeString(b64)
		if !ok || err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("tls: pin_sha256 %q: want %sBASE64 of a SHA-256, ';' between several", p, PinPrefix)
		}
		pins = append(pins, h)
	}
	return pins, nil
}

// TLSState is what the auth rules ask of the tls table beside them
type TLSState struct {
	On         bool // enabled
	ClientAuth bool // a listener verifies client certificates
	Unverified bool // a dialer skips verifying the server, and pins nothing instead
}

func (o *TLSOptions) State() TLSState {
	if o == nil || !o.Enabled {
		return TLSState{}
	}
	return TLSState{On: true, ClientAuth: o.ClientAuth, Unverified: o.InsecureSkipVerify && o.PinSHA256 == ""}
}

// Check holds the auth rules of a side, http for a plugin that speaks it,
// beside a tls table in state t. It reads no credentials or passwords.
func (o *AuthOptions) Check(side Side, http bool, t TLSState) error {
	if o == nil {
		return nil
	}
	if err := checkTags(reflect.ValueOf(o).Elem(), "auth."); err != nil {
		return err
	}
	if o.Type == "" || o.Type == "none" {
		// Tuning keys are ignored with the table, but one that names peers or
		// credentials means auth was intended and the type was forgotten
		if key := o.intentKey(); key != "" {
			return fmt.Errorf("auth: %s is set but auth.type is %q", key, "none")
		}
		return nil
	}
	switch {
	case !t.On && (o.Type != "scram" || len(o.TrustedProxies) == 0):
		return fmt.Errorf("auth: type %q requires tls.enabled", o.Type)
	case side == Dialer && t.Unverified:
		// An unverified server makes identities claims and exposes credentials
		return fmt.Errorf("auth: type %q cannot be used with tls.insecure_skip_verify", o.Type)
	case side != ChainListener && o.NodeBinding != "" && o.NodeBinding != "none":
		return fmt.Errorf("auth: node_binding %q applies only to chain sources", o.NodeBinding)
	case o.Type == "mtls" && o.scramKey() != "":
		return fmt.Errorf("auth: %s applies only to type %q", o.scramKey(), "scram")
	case o.Type == "mtls" && side != Dialer && !t.ClientAuth:
		return fmt.Errorf("auth: type %q requires tls.client_auth", "mtls")
	case o.Type == "mtls":
		for i, pattern := range o.AllowPatterns {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("auth: allow_patterns[%d] %q: %w", i, pattern, err)
			}
		}
		return nil
	case len(o.Allow) > 0 || len(o.AllowPatterns) > 0:
		return fmt.Errorf("auth: allow and allow_patterns apply only to type %q; the credentials file is the allow list", "mtls")
	case side == Dialer && (o.CredentialsFile != "" || o.TokenLifetimeMS != 0 || len(o.TrustedProxies) > 0):
		return errors.New("auth: credentials_file, token_lifetime_ms and trusted_proxies apply only to listeners")
	case side == Dialer && o.Identity != "":
		return fmt.Errorf("auth: identity on a dialer pins the server and applies only to type %q", "mtls")
	case side == Dialer && (o.Username == "" || o.PasswordFile == ""):
		return fmt.Errorf("auth: type %q on a dialer requires username and password_file", "scram")
	case side == Dialer:
		return nil
	case o.Username != "" || o.PasswordFile != "":
		return errors.New("auth: username and password_file apply only to dialers")
	case o.CredentialsFile == "":
		return fmt.Errorf("auth: type %q requires credentials_file", "scram")
	case o.TokenLifetimeMS > 0 && !http:
		return errors.New("auth: token_lifetime_ms applies only to HTTP listeners")
	case len(o.TrustedProxies) > 0 && (side != Listener || !http):
		return errors.New("auth: trusted_proxies applies only to the http sink")
	case len(o.TrustedProxies) > 0 && o.Identity != "":
		return errors.New("auth: identity binds a client certificate, which a TLS-terminating proxy does not pass on; drop it or trusted_proxies")
	case o.Identity != "" && !t.ClientAuth:
		// Binds the certificate to the user: a peer needs its own of both
		return fmt.Errorf("auth: identity under type %q binds the client certificate to the user and requires tls.client_auth", "scram")
	}
	for _, e := range o.TrustedProxies {
		if _, err := ParsePrefix(e, "tcp"); err != nil {
			return fmt.Errorf("auth: trusted_proxies entry %q: %w", e, err)
		}
	}
	return nil
}

// intentKey names the first key that only makes sense with authentication on
func (o *AuthOptions) intentKey() string {
	switch {
	case len(o.Allow) > 0:
		return "allow"
	case len(o.AllowPatterns) > 0:
		return "allow_patterns"
	}
	return o.scramKey()
}

func (o *AuthOptions) scramKey() string {
	switch {
	case o.CredentialsFile != "":
		return "credentials_file"
	case o.TokenLifetimeMS != 0:
		return "token_lifetime_ms"
	case o.Username != "":
		return "username"
	case o.PasswordFile != "":
		return "password_file"
	case len(o.TrustedProxies) > 0:
		return "trusted_proxies"
	}
	return ""
}

// Check holds the acl rules of a listener on host, http for one serving
// requests, proxied for one behind auth.trusted_proxies, whose rules take
// clients of either family, as does a PROXY header
func (o *ACLOptions) Check(host string, http, proxied bool) error {
	if o == nil {
		return nil
	}
	if err := checkTags(reflect.ValueOf(o).Elem(), "acl."); err != nil {
		return err
	}
	header := o.ProxyProtocol == "optional" || o.ProxyProtocol == "required"
	rps := o.RequestsPerSecondPerClient
	switch {
	case header && len(o.ProxyFrom) == 0:
		return fmt.Errorf("acl: proxy_protocol %s needs proxy_from, the proxies that may send the header", o.ProxyProtocol)
	case !header && len(o.ProxyFrom) > 0:
		return errors.New("acl: proxy_from needs proxy_protocol optional or required")
	case rps > 0 && !http:
		return errors.New("acl: requests_per_second_per_client applies only to HTTP listeners")
	case o.MaxConnectionsPerClient > 0 && proxied:
		return errors.New("acl: max_connections_per_client counts connections, behind trusted_proxies the proxy's; cap clients at the proxy")
	}
	network, err := core.Network(host)
	if err != nil {
		return err
	}
	clients := network
	if header || proxied {
		clients = "tcp"
	}
	for _, list := range []struct {
		key, network string
		entries      []string
	}{{"proxy_from", network, o.ProxyFrom}, {"allow", clients, o.Allow}, {"deny", clients, o.Deny}} {
		for _, e := range list.entries {
			if _, err := ParsePrefix(e, list.network); err != nil {
				return fmt.Errorf("acl: %s entry %q: %w", list.key, e, err)
			}
		}
	}
	return nil
}

// ParsePrefix reads an address or CIDR of network's family ("tcp": either)
func ParsePrefix(entry, network string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		addr, aerr := netip.ParseAddr(entry)
		if aerr != nil || addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("neither an address nor a CIDR (and no zone)")
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	switch a := prefix.Addr(); {
	case a.Is4In6():
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped; write it as IPv4")
	case network == "tcp4" && !a.Is4(), network == "tcp6" && a.Is4():
		return netip.Prefix{}, fmt.Errorf("not of the listener's family (%s)", network)
	}
	return prefix, nil
}

// and joins keys as a sentence does: "a, b and c"
func and(keys []string) string {
	if len(keys) < 2 {
		return strings.Join(keys, "")
	}
	return strings.Join(keys[:len(keys)-1], ", ") + " and " + keys[len(keys)-1]
}

// Check keeps a stream and a status path ServeMux and a URL take literally,
// apart, and off the authentication paths; a login page needs browsers that
// log in, behind a proxy
func (o *HTTPSinkOptions) Check() error {
	for _, p := range []struct{ key, path string }{{"stream_path", o.StreamPath}, {"status_path", o.StatusPath}} {
		c := path.Clean(p.path)
		switch {
		case !strings.HasPrefix(p.path, "/") || strings.ContainsAny(p.path, "{}%?#") || c != p.path && (c == "/" || c+"/" != p.path):
			return &KeyError{p.key, fmt.Errorf("%q must start with '/', hold no '//', '.' or '..' segment, and none of '{', '}', '%%', '?', '#'", p.path)}
		case p.path == chain.AuthPath || strings.HasPrefix(p.path, chain.AuthPath+"/"):
			return &KeyError{p.key, fmt.Errorf("%s and the paths under it are reserved for authentication", chain.AuthPath)}
		}
	}
	behind := o.Auth != nil && o.Auth.Type == "scram" && len(o.Auth.TrustedProxies) > 0
	switch {
	case o.StreamPath == o.StatusPath:
		return fmt.Errorf("stream_path and status_path must differ")
	case (o.LoginPage || o.ViewerPage) && !behind:
		return errors.New("login_page and viewer_page apply to scram behind auth.trusted_proxies, where browsers log in; without auth or under mtls the viewer is always served")
	case o.ViewerPage && !o.LoginPage:
		return errors.New("viewer_page needs login_page, where it sends a signed-out viewer")
	}
	return nil
}

func (o *HTTPChainSourceOptions) Check() error { return checkIngestPath(o.IngestPath) }
func (o *HTTPChainSinkOptions) Check() error {
	o.BackoffMaxMS = backoffMax(o.BackoffMinMS, o.BackoffMaxMS)
	return checkIngestPath(o.IngestPath)
}

func checkIngestPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return &KeyError{"ingest_path", errors.New("must start with '/'")}
	case p == chain.AuthPath:
		return &KeyError{"ingest_path", fmt.Errorf("%s is reserved for authentication", chain.AuthPath)}
	}
	return nil
}

func (o *TCPChainSinkOptions) Check() error {
	o.BackoffMaxMS = backoffMax(o.BackoffMinMS, o.BackoffMaxMS)
	return nil
}

// backoffMax replaces a maximum below the minimum with the default maximum
func backoffMax(lo, hi int64) int64 {
	if hi < lo {
		return 30000
	}
	return hi
}

// Check reads a negative min_disk_free_mb as 100; 0, or none set, keeps no space free
func (o *FileSinkOptions) Check() error {
	if o.MinDiskFreeMB < 0 {
		o.MinDiskFreeMB = 100
	}
	return nil
}

// Check caps the jitter at the interval
func (o *RandomSourceOptions) Check() error {
	o.JitterMS = min(o.JitterMS, o.IntervalMS)
	return nil
}

// Check compiles the patterns
func (c *FilterConfig) Check() error {
	for i, pattern := range c.Patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return &KeyError{fmt.Sprintf("patterns[%d]", i), fmt.Errorf("%q: %w", pattern, err)}
		}
	}
	return nil
}

// Scan decodes a flow stage's command-line map into target, rejecting keys
// target does not declare: a misspelled key must fail, not be dropped.
func Scan(configMap map[string]any, target any) error {
	if err := checkKeys(configMap, reflect.TypeOf(target), ""); err != nil {
		return err
	}
	return lconfig.ScanMap(configMap, target)
}

// checkKeys walks nested tables against the toml tags of t, refusing unknown
// keys. Map-typed fields hold free-form keys and are not descended into.
func checkKeys(m map[string]any, t reflect.Type, prefix string) error {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	fields := make(map[string]reflect.Type, t.NumField())
	for f := range t.Fields() {
		if name, _, _ := strings.Cut(f.Tag.Get("toml"), ","); name != "" && name != "-" {
			fields[name] = f.Type
		}
	}
	for _, key := range slices.Sorted(maps.Keys(m)) {
		ft, ok := fields[key]
		if !ok {
			return fmt.Errorf("unknown key %q", prefix+key)
		}
		var tables []map[string]any
		switch v := m[key].(type) {
		case map[string]any:
			if err := checkKeys(v, ft, prefix+key+"."); err != nil {
				return err
			}
		case []map[string]any:
			tables = v
		case []any:
			for _, e := range v {
				if table, ok := e.(map[string]any); ok {
					tables = append(tables, table)
				}
			}
		}
		for i, table := range tables {
			if err := checkKeys(table, ft, fmt.Sprintf("%s%s[%d].", prefix, key, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkFileKeys rejects keys the configuration file declares that Config does
// not: a misspelled table path such as plugin_sinks.confg.tls would otherwise
// drop the whole table. Plugin config maps are checked by Scan instead.
func checkFileKeys(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	root, err := toml.NewParser(data).Parse()
	if err != nil {
		return err
	}
	delete(root, "config_file") // runtime metadata, documented as ignored in the file
	for _, key := range []string{"version", "check", "dump"} {
		delete(root, key) // command-line switches, which earlier lw --dump output wrote
	}
	return checkKeys(root, reflect.TypeOf(Config{}), "")
}
