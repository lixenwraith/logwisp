package config

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// Every catalogue row decodes from its required keys alone: its tags parse,
// its defaults meet its own rules, and an enum's default is one of its values
func TestEveryRowDecodesFromItsRequiredKeys(t *testing.T) {
	for _, p := range plugins {
		m := map[string]any{}
		for _, o := range options(p.options) {
			if o.required {
				m[o.key] = "1"
			}
		}
		if err := Coerce(p.Role, p.Type, m); err != nil {
			t.Fatalf("%s %s: %v", p.Type, p.Role, err)
		}
		if _, err := decode(p.Role, p.Type, m); err != nil {
			t.Errorf("%s %s from %v: %v", p.Type, p.Role, m, err)
		}
	}
	for _, stage := range []any{&HeartbeatConfig{}, &RateLimitConfig{}, &FormatConfig{}, &FilterConfig{}} {
		if err := Settle(stage); err != nil {
			t.Errorf("%T: %v", stage, err)
		}
	}
}

// A zero number takes the default unless zero means something there, a switch
// that defaults on stays off when set off, a negative number is refused, and
// what moved from the constructors keeps its meaning: min_disk_free_mb below
// zero is the default, a backoff maximum below the minimum the default maximum
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
	chain, err := Decode[TCPChainSinkOptions]("sink", "tcp_chain", map[string]any{"host": "h", "port": int64(1), "backoff_min_ms": int64(800), "backoff_max_ms": int64(700)})
	if err != nil || chain.BackoffMaxMS != 30000 {
		t.Fatalf("backoff maximum below the minimum: %+v %v", chain, err)
	}
	format := FormatConfig{Type: "text"}
	if err := Settle(&format); err != nil {
		t.Fatalf("format text: %v", err)
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
// and names the path of what it refuses
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
		"pipelines[0].plugin_sinks[out].config: tls: client_auth requires client_ca_file": func(c *Config) {
			c.Pipelines[0].PluginSinks[0].Config["tls"].(map[string]any)["client_auth"] = true
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
		`pipelines[0].plugin_sinks[up].config: auth: type "mtls" cannot be used with tls.insecure_skip_verify`: func(c *Config) {
			c.Pipelines[0].PluginSinks[0] = PluginSinkConfig{ID: "up", Type: "tcp_chain", Config: map[string]any{"host": "h", "port": int64(1),
				"tls": map[string]any{"enabled": true, "insecure_skip_verify": true}, "auth": map[string]any{"type": "mtls"}}}
		},
		"pipelines[0].flow.rate_limit.rate: must be a finite number": func(c *Config) {
			c.Pipelines[0].Flow.RateLimit = &RateLimitConfig{Rate: math.Inf(1)}
		},
		"color: must be one of auto, always, never, got \"\"": func(c *Config) {
			c.Color = ""
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
