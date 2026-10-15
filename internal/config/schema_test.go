package config

import (
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Every catalogue row decodes from its required keys alone: its tags parse,
// its defaults meet its own rules, and an enum's default is one of its values
func TestEveryRowDecodesFromItsRequiredKeys(t *testing.T) {
	for _, p := range plugins {
		m := map[string]any{}
		for _, o := range options(p.options) {
			if o.Required {
				m[o.Name] = "1"
			}
		}
		if err := Coerce(p.Role, p.Type, m); err != nil {
			t.Fatalf("%s %s: %v", p.Type, p.Role, err)
		}
		if _, err := decode(p.Role, p.Type, m); err != nil {
			t.Errorf("%s %s from %v: %v", p.Type, p.Role, m, err)
		}
	}
	for _, stage := range []any{&HeartbeatConfig{}, &RateLimitConfig{}, &FormatConfig{}, &FilterConfig{Patterns: []string{"1"}}} {
		if err := Settle(stage); err != nil {
			t.Errorf("%T: %v", stage, err)
		}
	}
}

// A zero number takes the default unless zero means something there (a file
// sink's retention_hours 0 keeps files), a switch that defaults on stays off
// when set off, a negative number is refused, and what moved from the
// constructors keeps its meaning: min_disk_free_mb below zero is the default,
// a backoff maximum below the minimum the default maximum
func TestZeroDefaultsAndNegatives(t *testing.T) {
	tcp, err := Decode[TCPSinkOptions]("sink", "tcp", map[string]any{"port": int64(1), "buffer_size": int64(0), "keep_alive": false})
	if err != nil || tcp.BufferSize != 1000 || tcp.KeepAlive || tcp.Host != "0.0.0.0" {
		t.Fatalf("tcp sink: %+v %v", tcp, err)
	}
	if _, err := Decode[TCPSinkOptions]("sink", "tcp", map[string]any{"port": int64(1), "buffer_size": int64(-1)}); err == nil ||
		err.Error() != "buffer_size: must be at least 1, got -1" {
		t.Fatalf("negative buffer_size: %v", err)
	}
	for in, want := range map[any]int64{nil: 0, int64(0): 0, int64(-1): 100, int64(7): 7} {
		m := map[string]any{"directory": "d", "name": "n", "min_disk_free_mb": in}
		if in == nil {
			delete(m, "min_disk_free_mb")
		}
		file, err := Decode[FileSinkOptions]("sink", "file", m)
		if err != nil || file.MinDiskFreeMB != want {
			t.Errorf("min_disk_free_mb %v: %+v %v, want %d", in, file, err, want)
		}
	}
	for in, want := range map[any]float64{nil: 168, int64(0): 0, 0.0: 0, 2.5: 2.5} {
		m := map[string]any{"directory": "d", "name": "n", "retention_hours": in}
		if in == nil {
			delete(m, "retention_hours")
		}
		file, err := Decode[FileSinkOptions]("sink", "file", m)
		if err != nil || file.RetentionHours != want {
			t.Errorf("retention_hours %v: %+v %v, want %v", in, file, err, want)
		}
	}
	chain, err := Decode[TCPChainSinkOptions]("sink", "tcp_chain", map[string]any{"host": "h", "port": int64(1), "backoff_min_ms": int64(800), "backoff_max_ms": int64(700)})
	if err != nil || chain.BackoffMaxMS != 30000 {
		t.Fatalf("backoff maximum below the minimum: %+v %v", chain, err)
	}
}

// Command-line text and JSON numbers become the kinds the options declare, so
// a dump prints them typed; a fraction for an integer is refused
func TestCoerceGivesTheDeclaredKinds(t *testing.T) {
	m := map[string]any{"port": "8080", "max_connections": float64(3), "keep_alive": "false",
		"acl": map[string]any{"allow": "10.0.0.1", "requests_per_second_per_client": "2.5"}, "unknown": "x"}
	if err := Coerce("sink", "tcp", m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"port": int64(8080), "max_connections": int64(3), "keep_alive": false,
		"acl": map[string]any{"allow": []any{"10.0.0.1"}, "requests_per_second_per_client": 2.5}, "unknown": "x"}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("coerced %v, want %v", m, want)
	}
	if err := Coerce("sink", "tcp", map[string]any{"port": 80.5}); err == nil || !strings.HasPrefix(err.Error(), "port: ") {
		t.Fatalf("a fraction for an integer: %v", err)
	}
}

// ValidateConfig decodes every plugin and flow stage without opening a file,
// and names the path of what it refuses: a rule between a table's keys by
// the table's
func TestValidateConfigNamesThePath(t *testing.T) {
	valid := func() *Config {
		return &Config{Color: "auto", Pipelines: []PipelineConfig{{
			Name:          "p",
			Flow:          &FlowConfig{},
			PluginSources: []PluginSourceConfig{{ID: "in", Type: "null"}},
			PluginSinks: []PluginSinkConfig{{ID: "out", Type: "http", Config: map[string]any{"port": int64(1),
				"tls": map[string]any{"enabled": true, "cert_file": "/missing", "key_file": "/missing"}}}},
		}}}
	}
	if err := ValidateConfig(valid()); err != nil {
		t.Fatalf("valid configuration, its files missing: %v", err)
	}
	for want, change := range map[string]func(*Config){
		"pipelines[0].plugin_sinks[out].config.port: must be from 1 to 65535, got 70000": func(c *Config) {
			c.Pipelines[0].PluginSinks[0].Config["port"] = int64(70000)
		},
		"pipelines[0].plugin_sinks[out].config.tls: client_auth requires client_ca_file": func(c *Config) {
			c.Pipelines[0].PluginSinks[0].Config["tls"].(map[string]any)["client_auth"] = true
		},
		"pipelines[0].plugin_sinks[out].config.acl: requests_per_second_per_client applies only to HTTP listeners": func(c *Config) {
			c.Pipelines[0].PluginSinks[0].Type = "tcp"
			c.Pipelines[0].PluginSinks[0].Config["acl"] = map[string]any{"requests_per_second_per_client": 2.5}
		},
		"pipelines[0].plugin_sinks[out]: duplicate id": func(c *Config) {
			c.Pipelines[0].PluginSinks = append(c.Pipelines[0].PluginSinks, PluginSinkConfig{ID: "out", Type: "null"})
		},
		`pipelines[0].plugin_sources[in].type: unknown source type "nil"`: func(c *Config) {
			c.Pipelines[0].PluginSources[0].Type = "nil"
		},
		"pipelines[0].plugin_sinks[out].config.port: not an integer": func(c *Config) {
			c.Pipelines[0].PluginSinks[0].Config["port"] = "http"
		},
		`pipelines[0].plugin_sinks[up].config.auth: type "mtls" cannot be used with tls.insecure_skip_verify`: func(c *Config) {
			c.Pipelines[0].PluginSinks[0] = PluginSinkConfig{ID: "up", Type: "tcp_chain", Config: map[string]any{"host": "h", "port": int64(1),
				"tls": map[string]any{"enabled": true, "insecure_skip_verify": true}, "auth": map[string]any{"type": "mtls"}}}
		},
		"pipelines[0].flow.rate_limit.entries_per_second: must be a finite number": func(c *Config) {
			c.Pipelines[0].Flow.RateLimit = &RateLimitConfig{EntriesPerSecond: math.Inf(1)}
		},
		"color: must be one of auto, always, never, got \"\"": func(c *Config) {
			c.Color = ""
		},
		`pipelines[0].flow.format.type: must be one of raw, txt, json, got "text"`: func(c *Config) {
			c.Pipelines[0].Flow.Format = &FormatConfig{Type: "text"}
		},
		"pipelines[0].flow.heartbeat.interval_ms: must be at least 100, got 10": func(c *Config) {
			c.Pipelines[0].Flow.Heartbeat = &HeartbeatConfig{IntervalMS: 10}
		},
	} {
		c := valid()
		change(c)
		if err := ValidateConfig(c); err == nil || err.Error() != want {
			t.Errorf("err = %v, want %s", err, want)
		}
	}
}

// A configuration that does not load names every problem, a line each, each
// part's first: the settings, each flow stage, each plugin, each pipeline
func TestLoadReportsEveryProblemALine(t *testing.T) {
	isolateConfig(t)
	_, err := Load(Args{Overrides: []string{"--color=bogus"}, Specs: specs("pipeline", "a", "source", "file",
		"sink", "tcp:port=70000", "rate-limit", "policy=bogus", "filter", "include:patterns=(",
		"pipeline", "a", "sink", "null")})
	want := strings.Join([]string{"invalid configuration:",
		`color: must be one of auto, always, never, got "bogus"`,
		`pipelines[0].flow.rate_limit.policy: must be one of pass, drop, got "bogus"`,
		"pipelines[0].flow.filters[0].patterns[0]: \"(\": error parsing regexp: missing closing ): `(`",
		"pipelines[0].plugin_sources[file].config.directory: must be set",
		"pipelines[0].plugin_sinks[tcp].config.port: must be from 1 to 65535, got 70000",
		`pipelines[1].name: duplicate name "a"`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Fatalf("got\n%v\nwant\n%s", err, want)
	}
}

// A plugin lists the table keys that apply to it: those of its side, a chain
// source's being a listener's and its own, and the HTTP ones only when it
// speaks HTTP
func TestTableKeysFollowThePlugin(t *testing.T) {
	has := func(role, typ, path string) bool {
		p, _ := LookupPlugin(role, typ)
		keys := p.Keys()
		for part := range strings.SplitSeq(path, ".") {
			i := slices.IndexFunc(keys, func(k Key) bool { return k.Name == part })
			if i < 0 {
				return false
			}
			keys = keys[i].Keys
		}
		return true
	}
	for path, want := range map[string]bool{
		"sink tcp_chain tls.pin_sha256": true, "sink tcp_chain tls.self_signed": false,
		"source tcp_chain tls.self_signed": true, "source tcp_chain tls.pin_sha256": false,
		"source tcp_chain auth.node_binding": true, "sink http auth.node_binding": false, "sink tcp_chain auth.credentials_file": false,
		"sink tcp acl.requests_per_second_per_client": false, "sink tcp auth.token_lifetime_ms": false,
		"sink http acl.requests_per_second_per_client": true, "sink http auth.trusted_proxies": true,
	} {
		f := strings.Fields(path)
		if has(f[0], f[1], f[2]) != want {
			t.Errorf("%s: listed %v, want %v", path, !want, want)
		}
	}
}

// A leading ~ or ~/ in a dir or file key is the home directory where lw reads
// it, in a plugin's options, its tables too, while the configuration keeps it
// as typed, the settings' too (lw's log reads it at startup); ~user, other
// keys and a host without a home directory keep it
func TestTildeIsHomeInPathKeys(t *testing.T) {
	isolateConfig(t)
	home := os.Getenv("HOME")
	src, err := Decode[FileSourceOptions]("source", "file", map[string]any{"directory": "~/logs", "pattern": "~*"})
	if err != nil || src.Directory != home+"/logs" || src.Pattern != "~*" {
		t.Fatalf("file source: %+v %v", src, err)
	}
	tls := map[string]any{"enabled": true, "ca_file": "~", "cert_file": "~/c", "key_file": "~other/k"}
	sink, err := Decode[TCPChainSinkOptions]("sink", "tcp_chain", map[string]any{"host": "h", "port": int64(1), "tls": tls})
	if err != nil || sink.TLS.CAFile != home || sink.TLS.CertFile != home+"/c" || sink.TLS.KeyFile != "~other/k" {
		t.Fatalf("tls table: %+v %v", sink.TLS, err)
	}
	m, err := Load(Args{Overrides: []string{"--logging.file.directory=~/lw"}, Specs: specs("source", "file:directory=~/logs")})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil || cfg.Logging.File.Directory != "~/lw" || cfg.Pipelines[0].PluginSources[0].Config["directory"] != "~/logs" {
		t.Fatalf("as typed: %+v %v %v", cfg.Logging.File, cfg.Pipelines, err)
	}
	t.Setenv("HOME", "")
	if src, err := Decode[FileSourceOptions]("source", "file", map[string]any{"directory": "~/logs"}); err != nil || src.Directory != "~/logs" {
		t.Fatalf("without a home directory: %+v %v", src, err)
	}
}
