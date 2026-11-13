package pipeline

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/flow"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"
	"github.com/lixenwraith/logwisp/internal/source"

	"github.com/lixenwraith/log"
)

// finiteSource publishes n entries as soon as it starts, then those feed
// sends when there is one, and ends once feed and hold close, when there are
// those. Entries carry its id as their Source. With fail it does not start,
// as a source whose port is taken; stopped unstarted, it closes its channels,
// as the plugins do.
type finiteSource struct {
	id    string
	n     int
	fail  bool
	hold  chan struct{}
	feed  chan string
	subs  []chan core.LogEntry
	begun atomic.Bool // taken by Start, or by a Stop before it
}

func (s *finiteSource) Capabilities() []core.Capability { return nil }
func (s *finiteSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, 1)
	s.subs = append(s.subs, ch)
	return ch
}
func (s *finiteSource) Start() error {
	if s.fail {
		return errors.New("address already in use")
	}
	if !s.begun.CompareAndSwap(false, true) {
		return nil
	}
	go func() {
		for i := range s.n {
			for _, ch := range s.subs {
				msg := strconv.Itoa(i)
				ch <- core.LogEntry{Time: time.Now(), Source: s.id, Message: msg, RawSize: int64(len(msg))}
			}
		}
		for s.feed != nil {
			msg, ok := <-s.feed
			if !ok {
				break
			}
			for _, ch := range s.subs {
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
func (s *finiteSource) Stop() {
	if s.begun.CompareAndSwap(false, true) {
		for _, ch := range s.subs {
			close(ch)
		}
	}
}
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

// fullSink declares no backpressure and never reads its unbuffered input:
// dispatch drops every event for it
type fullSink struct{ in chan core.TransportEvent }

func (s *fullSink) Capabilities() []core.Capability   { return nil }
func (s *fullSink) Input() chan<- core.TransportEvent { return s.in }
func (s *fullSink) Start(context.Context) error       { return nil }
func (s *fullSink) Stop()                             {}
func (s *fullSink) GetStats() sink.SinkStats          { return sink.SinkStats{} }

var testSinks = map[string]sink.Sink{}

// The fakes take catalogue types that no plugin package registers in this
// test binary
func init() {
	plugin.RegisterSource("random", func(id string, cfg map[string]any, _ *log.Logger, _ *session.Proxy) (source.Source, error) {
		n, _ := strconv.Atoi(fmt.Sprint(cfg["n"]))
		hold, _ := cfg["hold"].(chan struct{})
		feed, _ := cfg["feed"].(chan string)
		fail, _ := cfg["fail"].(bool)
		return &finiteSource{id: id, n: n, fail: fail, hold: hold, feed: feed}, nil
	})
	for _, typ := range []string{"null", "tcp_chain"} {
		plugin.RegisterSink(typ, func(id string, _ map[string]any, _ *log.Logger, _ *session.Proxy) (sink.Sink, error) {
			return testSinks[id], nil
		})
	}
}

// What sources published before another failed to start reaches the sinks
// once the pipeline stops, whichever of them started first
func TestAFailedStartDeliversWhatStartedSourcesPublished(t *testing.T) {
	s := &slowSink{in: make(chan core.TransportEvent, 1000)}
	testSinks[t.Name()] = s
	for range 20 {
		p, err := NewPipeline(&config.PipelineConfig{
			Name: t.Name(),
			PluginSources: []config.PluginSourceConfig{
				{ID: "eager", Type: "random", Config: map[string]any{"n": 100}},
				{ID: "taken", Type: "random", Config: map[string]any{"fail": true}},
			},
			PluginSinks: []config.PluginSinkConfig{{ID: t.Name(), Type: "null"}},
		}, log.NewLogger())
		if err != nil {
			t.Fatal(err)
		}
		if p.Start() == nil {
			t.Fatal("a source failing to start went unreported")
		}
		want := 0
		if p.Sources["eager"].(*finiteSource).begun.Load() {
			want = 100
		}
		p.Shutdown()
		if got := len(s.in); got != want {
			t.Fatalf("the sinks got %d of the %d entries published", got, want)
		}
		for len(s.in) > 0 {
			<-s.in
		}
	}
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

// A pipeline whose sinks are all chain sinks, which send the entry itself,
// formats nothing, unless a viewer's tap shows the payload
func TestChainSinksAloneSkipFormattingUnlessTapped(t *testing.T) {
	const n = 10
	for _, tapped := range []bool{false, true} {
		s := &fullSink{in: make(chan core.TransportEvent, n)}
		testSinks[t.Name()] = s
		p, err := NewPipeline(&config.PipelineConfig{
			Name:          t.Name(),
			PluginSources: []config.PluginSourceConfig{{ID: "src", Type: "random", Config: map[string]any{"n": n}}},
			PluginSinks:   []config.PluginSinkConfig{{ID: t.Name(), Type: "tcp_chain"}},
		}, log.NewLogger())
		if err != nil {
			t.Fatal(err)
		}
		if tapped {
			p.SetTap(core.NewTap(n, 0))
		}
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		<-p.Finished()
		p.Shutdown()
		formatted, first := p.flow.Load().GetStats()["total_formatted"], <-s.in
		if want := map[bool]uint64{true: n}[tapped]; formatted != want || len(s.in) != n-1 ||
			first.Entry.Message != "0" || (len(first.Payload) > 0) != tapped {
			t.Errorf("tapped %v: %v formatted, %d events, the first %+v", tapped, formatted, len(s.in)+1, first)
		}
	}
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
		tap := core.NewTap(4*n, 0)
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
	tap := core.NewTap(1, 0)
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

// SetFlow swaps the flow under running sources: the next entry takes the new
// stages, the heartbeat follows the flow, and the flow's totals go on while
// its filters' start over
func TestSetFlowSwapsTheFlowInPlace(t *testing.T) {
	feed := make(chan string)
	testSinks[t.Name()] = &slowSink{in: make(chan core.TransportEvent, 64)}
	exclude := func(pattern string) []config.FilterConfig {
		return []config.FilterConfig{{Type: "exclude", Patterns: []string{pattern}}}
	}
	p, err := NewPipeline(&config.PipelineConfig{
		Name:          t.Name(),
		Flow:          &config.FlowConfig{Filters: exclude("a")},
		PluginSources: []config.PluginSourceConfig{{ID: "src", Type: "random", Config: map[string]any{"feed": feed}}},
		PluginSinks:   []config.PluginSinkConfig{{ID: t.Name(), Type: "null"}},
	}, log.NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	tap := core.NewTap(64, 0)
	tap.All.Store(true)
	p.SetTap(tap)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { close(feed); p.Shutdown() }()
	beats := 0
	next := func() core.Tapped {
		t.Helper()
		for {
			select {
			case r := <-tap.Records():
				if r.Source != "" {
					return r
				}
				beats++
			case <-time.After(5 * time.Second):
				t.Fatal("nothing reached the tap")
			}
		}
	}
	verdicts := func() (out []string) {
		t.Helper()
		for _, msg := range []string{"a", "b"} {
			feed <- msg
			r := next()
			out = append(out, r.Event.Entry.Message+":"+r.Stage)
		}
		return out
	}
	swap := func(cfg *config.FlowConfig) {
		t.Helper()
		f, err := flow.NewFlow(cfg, log.NewLogger())
		if err != nil {
			t.Fatal(err)
		}
		p.SetFlow(cfg, f)
		if p.Config.Flow != cfg {
			t.Fatal("the pipeline's configuration kept the earlier flow")
		}
	}

	if got := verdicts(); !slices.Equal(got, []string{"a:filters", "b:"}) {
		t.Fatalf("before the swap: %v", got)
	}
	swap(&config.FlowConfig{Filters: exclude("b"), Heartbeat: &config.HeartbeatConfig{Enabled: true, IntervalMS: 100}})
	if got := verdicts(); !slices.Equal(got, []string{"a:", "b:filters"}) {
		t.Fatalf("after the swap: %v", got)
	}
	for deadline := time.Now().Add(5 * time.Second); beats == 0; {
		select {
		case r := <-tap.Records():
			if r.Source == "" {
				beats++
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("the swapped-in flow's heartbeat never beat")
		}
	}
	stats := p.GetStats()
	flowStats := stats["flow"].(map[string]any)
	filters := flowStats["filters"].(map[string]any)
	if stats["total_processed"] != uint64(4) || stats["total_filtered"] != uint64(2) || flowStats["total_dropped"] != uint64(2) || filters["total_processed"] != uint64(2) {
		t.Fatalf("totals: processed %v, filtered %v, flow dropped %v, the new filters took %v",
			stats["total_processed"], stats["total_filtered"], flowStats["total_dropped"], filters["total_processed"])
	}

	swap(&config.FlowConfig{})
	time.Sleep(20 * time.Millisecond) // a beat already sent may still arrive
	for len(tap.Records()) > 0 {
		<-tap.Records()
	}
	time.Sleep(250 * time.Millisecond)
	for len(tap.Records()) > 0 {
		if r := <-tap.Records(); r.Source == "" {
			t.Fatal("the heartbeat outlived its flow")
		}
	}
}

// A full sink's drops count for it alone; the pipeline's total is their sum
func TestDispatchCountsEachSinksDrops(t *testing.T) {
	const n = 200
	full, slow := t.Name()+"/full", t.Name()+"/slow"
	testSinks[full] = &fullSink{in: make(chan core.TransportEvent)}
	got := &slowSink{in: make(chan core.TransportEvent, 1), out: make(chan string, n)}
	testSinks[slow] = got
	p, err := NewPipeline(&config.PipelineConfig{
		Name:          t.Name(),
		PluginSources: []config.PluginSourceConfig{{ID: "src", Type: "random", Config: map[string]any{"n": n}}},
		PluginSinks:   []config.PluginSinkConfig{{ID: full, Type: "null"}, {ID: slow, Type: "null"}},
	}, log.NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	<-p.Finished()
	for range n {
		<-got.out
	}
	p.Shutdown()
	stats := p.GetStats()
	dropped := map[string]any{}
	for _, s := range stats["sinks"].([]map[string]any) {
		dropped[s["id"].(string)] = s["dropped_entries"]
	}
	if dropped[full] != uint64(n) || dropped[slow] != uint64(0) || stats["total_dropped_by_sink"] != uint64(n) {
		t.Fatalf("dropped %v, in all %v", dropped, stats["total_dropped_by_sink"])
	}
}

// Once Stop releases dispatch, a backpressure sink with room still takes each
// entry, and only a full one drops it: a select with the release ready too
// picks at random, which dropped about half of what was in flight
func TestReleasedDispatchStillFillsASinkWithRoom(t *testing.T) {
	const n = 1000
	room, full := &slowSink{in: make(chan core.TransportEvent, n)}, &slowSink{in: make(chan core.TransportEvent)}
	p := &Pipeline{halt: make(chan struct{}), outlets: []*outlet{{sink: room, backpressure: true}, {sink: full, backpressure: true}}}
	close(p.halt)
	for range n {
		p.dispatch(core.TransportEvent{})
	}
	if len(room.in) != n || p.outlets[0].dropped.Load() != 0 || p.outlets[1].dropped.Load() != n {
		t.Fatalf("a sink with room took %d of %d, dropped %d; a full one dropped %d",
			len(room.in), n, p.outlets[0].dropped.Load(), p.outlets[1].dropped.Load())
	}
}

// benchSource publishes n copies of entry as fast as the pipeline takes them
type benchSource struct {
	n     int
	entry core.LogEntry
	subs  []chan core.LogEntry
}

func (s *benchSource) Capabilities() []core.Capability { return nil }
func (s *benchSource) Subscribe() <-chan core.LogEntry {
	ch := make(chan core.LogEntry, 1000)
	s.subs = append(s.subs, ch)
	return ch
}
func (s *benchSource) Start() error {
	go func() {
		for range s.n {
			for _, ch := range s.subs {
				ch <- s.entry
			}
		}
		for _, ch := range s.subs {
			close(ch)
		}
	}()
	return nil
}
func (s *benchSource) Stop()                        {}
func (s *benchSource) GetStats() source.SourceStats { return source.SourceStats{} }

// countSink takes n events, then closes done
type countSink struct {
	in   chan core.TransportEvent
	n    int
	done chan struct{}
}

func (s *countSink) Capabilities() []core.Capability   { return []core.Capability{core.CapBackpressure} }
func (s *countSink) Input() chan<- core.TransportEvent { return s.in }
func (s *countSink) Start(context.Context) error {
	go func() {
		for range s.n {
			<-s.in
		}
		close(s.done)
	}()
	return nil
}
func (s *countSink) Stop()                    {}
func (s *countSink) GetStats() sink.SinkStats { return sink.SinkStats{} }

func init() {
	plugin.RegisterSource("null", func(_ string, cfg map[string]any, _ *log.Logger, _ *session.Proxy) (source.Source, error) {
		return &benchSource{n: cfg["n"].(int), entry: cfg["entry"].(core.LogEntry)}, nil
	})
}

// BenchmarkPipeline is an entry's way from a source's channel through the
// flow to every sink's input, per entry
func BenchmarkPipeline(b *testing.B) {
	entry := core.LogEntry{Time: time.Now(), Source: "app.log", Level: "INFO",
		Message: "GET /api/v1/users/42 200 1.2ms user=alice request_id=7f3a9c2e", RawSize: 64}
	for _, c := range []struct {
		format string
		sinks  int
	}{{"txt", 1}, {"json", 1}, {"json", 3}} {
		b.Run(fmt.Sprintf("%s-%dsinks", c.format, c.sinks), func(b *testing.B) {
			b.ReportAllocs()
			cfg := &config.PipelineConfig{
				Name:          b.Name(),
				Flow:          &config.FlowConfig{Format: &config.FormatConfig{Type: c.format}},
				PluginSources: []config.PluginSourceConfig{{ID: "src", Type: "null", Config: map[string]any{"n": b.N, "entry": entry}}},
			}
			var sinks []*countSink
			for i := range c.sinks {
				id := fmt.Sprintf("%s/%d", b.Name(), i)
				s := &countSink{in: make(chan core.TransportEvent, 1000), n: b.N, done: make(chan struct{})}
				testSinks[id], sinks = s, append(sinks, s)
				cfg.PluginSinks = append(cfg.PluginSinks, config.PluginSinkConfig{ID: id, Type: "null"})
			}
			p, err := NewPipeline(cfg, log.NewLogger())
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			if err := p.Start(); err != nil {
				b.Fatal(err)
			}
			for _, s := range sinks {
				<-s.done
			}
			b.StopTimer()
			p.Shutdown()
		})
	}
}
