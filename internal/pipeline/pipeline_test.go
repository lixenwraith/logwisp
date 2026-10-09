package pipeline

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/source"

	"github.com/lixenwraith/log"
)

// finiteSource publishes n entries as soon as it starts, then ends
type finiteSource struct {
	n    int
	subs []chan core.LogEntry
}

func (s *finiteSource) Capabilities() []core.Capability { return nil }
func (s *finiteSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, 1)
	s.subs = append(s.subs, ch)
	return ch
}
func (s *finiteSource) Start() error {
	go func() {
		for i := range s.n {
			for _, ch := range s.subs {
				ch <- core.LogEntry{Time: time.Now(), Message: strconv.Itoa(i)}
			}
		}
		for _, ch := range s.subs {
			close(ch)
		}
	}()
	return nil
}
func (s *finiteSource) Stop()                        {}
func (s *finiteSource) GetStats() source.SourceStats { return source.SourceStats{} }

// slowSink applies backpressure; a nil out never reads at all
type slowSink struct {
	in  chan core.TransportEvent
	out chan string
}

func (s *slowSink) Capabilities() []core.Capability   { return []core.Capability{core.CapBackpressure} }
func (s *slowSink) Input() chan<- core.TransportEvent { return s.in }
func (s *slowSink) Start(context.Context) error {
	if s.out != nil {
		go func() {
			for e := range s.in {
				time.Sleep(10 * time.Microsecond)
				s.out <- e.Entry.Message
			}
		}()
	}
	return nil
}
func (s *slowSink) Stop()                    {}
func (s *slowSink) GetStats() sink.SinkStats { return sink.SinkStats{} }

var testSinks = map[string]*slowSink{}

// The fakes take catalogue types that no plugin package registers in this
// test binary
func init() {
	plugin.RegisterSource("random", func(id string, cfg map[string]any, _ *log.Logger, _ *session.Proxy) (source.Source, error) {
		n, _ := strconv.Atoi(fmt.Sprint(cfg["n"]))
		return &finiteSource{n: n}, nil
	})
	plugin.RegisterSink("null", func(id string, _ map[string]any, _ *log.Logger, _ *session.Proxy) (sink.Sink, error) {
		return testSinks[id], nil
	})
}

func newTestPipeline(t *testing.T, n int, s *slowSink) *Pipeline {
	t.Helper()
	testSinks[t.Name()] = s
	p, err := NewPipeline(&config.PipelineConfig{
		Name:          t.Name(),
		PluginSources: []config.PluginSourceConfig{{ID: "src", Type: "random", Config: map[string]any{"n": n}}},
		PluginSinks:   []config.PluginSinkConfig{{ID: t.Name(), Type: "null"}},
	}, log.NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A source that publishes from its first moment loses nothing to a slow sink,
// and the pipeline reports Finished when its input ends.
func TestFiniteInputReachesBackpressureSinkWhole(t *testing.T) {
	const n = 2000
	s := &slowSink{in: make(chan core.TransportEvent, 1), out: make(chan string, n)}
	p := newTestPipeline(t, n, s)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Finished():
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline did not finish at the end of its input")
	}
	for i := range n {
		if got := <-s.out; got != strconv.Itoa(i) {
			t.Fatalf("entry %d = %s", i, got)
		}
	}
	p.Shutdown()
}

// Stop releases a dispatch blocked on a sink that never reads
func TestStopReleasesStalledBackpressureSink(t *testing.T) {
	p := newTestPipeline(t, 100, &slowSink{in: make(chan core.TransportEvent, 1)})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	stopped := make(chan struct{})
	go func() { p.Shutdown(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked behind a stalled backpressure sink")
	}
}
