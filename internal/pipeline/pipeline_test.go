package pipeline

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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

// finiteSource publishes n entries as soon as it starts, then ends, once hold
// closes when there is one. Entries carry its id as their Source.
type finiteSource struct {
	id   string
	n    int
	hold chan struct{}
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
				msg := strconv.Itoa(i)
				ch <- core.LogEntry{Time: time.Now(), Source: s.id, Message: msg, RawSize: int64(len(msg))}
			}
		}
		if s.hold != nil {
			<-s.hold
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
		hold, _ := cfg["hold"].(chan struct{})
		return &finiteSource{id: id, n: n, hold: hold}, nil
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

// The tap gets each entry's verdict under its source's id: the stage that
// dropped it, or what dispatch offered the sinks. Drops come only when All is
// set, and heartbeats come as passed, from no source.
func TestTapSeesEachVerdict(t *testing.T) {
	const n = 1000
	verdict := func(msg string) (string, int) {
		switch {
		case len(msg) > 2:
			return "rate_limit", 0
		case strings.HasPrefix(msg, "1"):
			return "filters", 0
		case !strings.HasSuffix(msg, "0"):
			return "filters", 1
		}
		return "", 0
	}
	for _, all := range []bool{false, true} {
		hold := make(chan struct{})
		sink := &slowSink{in: make(chan core.TransportEvent, 4*n)}
		testSinks[t.Name()] = sink
		p, err := NewPipeline(&config.PipelineConfig{
			Name: t.Name(),
			Flow: &config.FlowConfig{
				RateLimit: &config.RateLimitConfig{EntriesPerSecond: 1e6, Policy: "drop", MaxEntrySizeBytes: 2},
				Filters:   []config.FilterConfig{{Type: "exclude", Patterns: []string{" 1"}}, {Type: "include", Patterns: []string{"0$"}}},
				Heartbeat: &config.HeartbeatConfig{Enabled: true, IntervalMS: 100},
			},
			PluginSources: []config.PluginSourceConfig{
				{ID: "a", Type: "random", Config: map[string]any{"n": n, "hold": hold}},
				{ID: "b", Type: "random", Config: map[string]any{"n": n, "hold": hold}},
			},
			PluginSinks: []config.PluginSinkConfig{{ID: t.Name(), Type: "null"}},
		}, log.NewLogger())
		if err != nil {
			t.Fatal(err)
		}
		tap := core.NewTap(4 * n)
		tap.All.Store(all)
		p.SetTap(tap)
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		var got []core.Tapped
		for beat := false; !beat; {
			select {
			case r := <-tap.Records():
				if beat = r.Source == ""; beat && (r.Stage != "" || r.Event.Entry.Source != "heartbeat" || len(r.Event.Payload) == 0) {
					t.Errorf("heartbeat %+v", r)
				}
				got = append(got, r)
			case <-time.After(5 * time.Second):
				t.Fatal("no heartbeat reached the tap")
			}
		}
		close(hold)
		<-p.Finished()
		p.Shutdown()
		for len(tap.Records()) > 0 {
			got = append(got, <-tap.Records())
		}

		seen, passed := map[string]int{}, 0
		for _, r := range got {
			e := r.Event.Entry
			if r.Stage == "" {
				passed++
			}
			if r.Source == "" {
				continue
			}
			stage, index := verdict(e.Message)
			if r.Pipeline != t.Name() || r.Source != e.Source || r.Stage != stage || r.Index != index ||
				stage == "" && string(r.Event.Payload) != e.Message+"\n" {
				t.Errorf("all=%v: %s %q: got %s %s[%d] %q, want %s[%d]", all, r.Source, e.Message, r.Pipeline, r.Stage, r.Index, r.Event.Payload, stage, index)
			}
			seen[r.Source+e.Message]++
		}
		for i := range n {
			msg := strconv.Itoa(i)
			want := 1
			if stage, _ := verdict(msg); stage != "" && !all {
				want = 0
			}
			for _, id := range []string{"a", "b"} {
				if seen[id+msg] != want {
					t.Errorf("all=%v: %s %q tapped %d times, want %d", all, id, msg, seen[id+msg], want)
				}
			}
		}
		if tap.Dropped() != 0 || len(sink.in) != passed {
			t.Errorf("all=%v: a tap with room dropped %d; the sink got %d, %d passed", all, tap.Dropped(), len(sink.in), passed)
		}
	}
}

// A tap nobody reads costs the pipeline nothing: every entry still reaches
// the sink, and the tap counts what it could not take.
func TestFullTapNeverStallsAPipeline(t *testing.T) {
	const n = 2000
	s := &slowSink{in: make(chan core.TransportEvent, 1), out: make(chan string, n)}
	p := newTestPipeline(t, n, s)
	tap := core.NewTap(1)
	p.SetTap(tap)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Finished():
	case <-time.After(10 * time.Second):
		t.Fatal("a full tap stalled the pipeline")
	}
	for i := range n {
		select {
		case <-s.out:
		case <-time.After(5 * time.Second):
			t.Fatalf("the sink got %d of %d", i, n)
		}
	}
	p.Shutdown()
	if tap.Dropped() != n-1 {
		t.Fatalf("tap dropped %d, want %d", tap.Dropped(), n-1)
	}
}
