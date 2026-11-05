package service

import (
	"context"
	"reflect"
	"testing"

	"github.com/lixenwraith/logwisp/internal/config"
	_ "github.com/lixenwraith/logwisp/internal/sink/null"
	_ "github.com/lixenwraith/logwisp/internal/source/null"

	"github.com/lixenwraith/log"
)

// configured is a configuration of one pipeline, p, from a null source to
// sinks of the ids given, through the flow given
func configured(flow *config.FlowConfig, sinks ...string) *config.Config {
	p := config.PipelineConfig{Name: "p", Flow: flow,
		PluginSources: []config.PluginSourceConfig{{ID: "in", Type: "null", Config: map[string]any{}}}}
	for _, id := range sinks {
		p.PluginSinks = append(p.PluginSinks, config.PluginSinkConfig{ID: id, Type: "null", Config: map[string]any{}})
	}
	return &config.Config{Pipelines: []config.PipelineConfig{p}}
}

// flowWith is a flow excluding pattern, written as txt with a heartbeat: the
// stages whose options are settled with their defaults
func flowWith(pattern string) *config.FlowConfig {
	return &config.FlowConfig{
		Filters:   []config.FilterConfig{{Type: "exclude", Patterns: []string{pattern}}},
		Format:    &config.FormatConfig{Type: "txt"},
		Heartbeat: &config.HeartbeatConfig{Enabled: true},
	}
}

func running(t *testing.T, cfg *config.Config) *Service {
	t.Helper()
	svc, err := NewService(context.Background(), cfg, log.NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Shutdown)
	return svc
}

// Building a service leaves its configuration as written, so a reload that
// rereads the same file compares equal and is no edit
func TestAServiceLeavesItsConfigurationAsWritten(t *testing.T) {
	cfg := configured(flowWith("x"), "out")
	running(t, cfg)
	if want := configured(flowWith("x"), "out"); !reflect.DeepEqual(cfg, want) {
		t.Fatalf("building changed the configuration:\n%+v\nwant\n%+v", cfg.Pipelines[0].Flow, want.Pipelines[0].Flow)
	}
}

// Patch swaps an edited flow in place and reports it; any other edit, or a
// shut down service, it leaves to a rebuild, changing nothing; a flow that
// does not build is an error, and changes nothing either
func TestPatchSwapsFlowsAloneInPlace(t *testing.T) {
	svc := running(t, configured(flowWith("x"), "out"))
	p, err := svc.GetPipeline("p")
	if err != nil {
		t.Fatal(err)
	}
	flowIs := func(pattern string) bool { return reflect.DeepEqual(p.Config.Flow, flowWith(pattern)) }

	edited := configured(flowWith("y"), "out")
	if ok, err := svc.Patch(edited); !ok || err != nil || p.Config.Flow != edited.Pipelines[0].Flow {
		t.Fatalf("a flow edit: patched %v, %v", ok, err)
	}
	if ok, err := svc.Patch(configured(flowWith("y"), "out")); !ok || err != nil || !flowIs("y") {
		t.Fatalf("no edit: patched %v, %v", ok, err)
	}

	renamed := configured(flowWith("z"), "out")
	renamed.Pipelines[0].Name = "q"
	twice := configured(flowWith("z"), "out")
	twice.Pipelines = append(twice.Pipelines, renamed.Pipelines[0])
	option := configured(flowWith("z"), "out")
	option.Pipelines[0].PluginSinks[0].Config["buffer_size"] = 8
	for name, cfg := range map[string]*config.Config{
		"a sink added":       configured(flowWith("z"), "out", "more"),
		"a sink option":      option,
		"a pipeline renamed": renamed,
		"a pipeline added":   twice,
	} {
		if ok, err := svc.Patch(cfg); ok || err != nil || !flowIs("y") {
			t.Errorf("%s: patched %v, %v; flow now %+v", name, ok, err, p.Config.Flow)
		}
	}

	if ok, err := svc.Patch(configured(flowWith("("), "out")); ok || err == nil || !flowIs("y") {
		t.Fatalf("a flow that does not build: patched %v, %v", ok, err)
	}

	svc.Shutdown()
	if ok, err := svc.Patch(configured(flowWith("z"), "out")); ok || err != nil || !flowIs("y") {
		t.Fatalf("shut down: patched %v, %v", ok, err)
	}
}
