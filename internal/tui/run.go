package tui

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"os/signal"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	ui "github.com/lixenwraith/terminal/tui"
)

// Runner runs pipelines in lw's process while the screen stays. Its calls
// block: the screen makes Start and Stop one at a time on a goroutine of its
// own, and reads State from another.
type Runner interface {
	// Start runs specs in place of what runs, as a reload does, and returns
	// the tap of what runs then: on an error the earlier run's when the new
	// pipelines did not build, nil when nothing runs
	Start(specs []config.Spec, ask Ask) (*core.Tap, error)
	Stop()
	State() RunState
}

// Ask answers a password prompt a terminal would show; with generate, an
// empty answer draws a password, shown once
type Ask func(user string, generate bool) ([]byte, error)

// RunState is what a run reports beside its tap
type RunState struct {
	Counts map[string]Counts // by pipeline
	Ended  bool              // every pipeline's input ended
	Log    *core.Tap         // lw's own log, nil while it does not reach the terminal
}

// Counts are a pipeline's entries: in from its sources, dropped by its flow,
// and dropped by sinks that could not take them
type Counts struct{ In, Filtered, SinksDropped uint64 }

func (s RunState) same(o RunState) bool {
	return s.Ended == o.Ended && s.Log == o.Log && maps.Equal(s.Counts, o.Counts)
}

// run is the screen's side of a Runner. A worker makes the calls; what they
// bring back waits in later for a tick, which wake posts once until handled.
type run struct {
	runner Runner
	post   func() // posts a tick to the screen
	jobs   chan func()
	worker sync.Once
	busy   sync.WaitGroup
	mu     sync.Mutex
	later  []func(a *app)
	posted atomic.Bool
	gone   chan struct{} // closed when the screen leaves: asks fail
	ended  sync.Once
	fed    atomic.Pointer[core.Tap] // the run's tap, for the watch

	// the screen's goroutine only
	op      string        // "starting" or "stopping" while a job runs
	specs   []config.Spec // what runs, nil while nothing does
	tap     *core.Tap
	state   RunState
	leaving bool
}

func newRun(runner Runner, post func()) *run {
	return &run{runner: runner, post: post, jobs: make(chan func(), 4), gone: make(chan struct{})}
}

// do runs job on the worker, after the jobs before it
func (r *run) do(job func()) {
	r.worker.Do(func() {
		go func() {
			for job := range r.jobs {
				job()
				r.busy.Done()
			}
		}()
	})
	r.busy.Add(1)
	r.jobs <- job
}

// send has f run on the screen's goroutine at the next tick
func (r *run) send(f func(a *app)) {
	r.mu.Lock()
	r.later = append(r.later, f)
	r.mu.Unlock()
	r.wake()
}

// wake posts a tick unless one is waiting
func (r *run) wake() {
	if r.posted.CompareAndSwap(false, true) {
		r.post()
	}
}

// watch wakes the screen while a tap holds records, every drainEvery at
// most, and reads the run's state every so often, waking the screen only
// when it changed; until the screen leaves
func (r *run) watch(every time.Duration) {
	pace, state := time.NewTicker(drainEvery), time.NewTicker(every)
	defer pace.Stop()
	defer state.Stop()
	var last RunState
	for {
		select {
		case <-r.gone:
			return
		case <-pace.C:
			if holds(r.fed.Load()) || holds(last.Log) {
				r.wake()
			}
		case <-state.C:
			if st := r.runner.State(); !st.same(last) {
				last = st
				r.send(func(a *app) { a.live.state = st })
			}
		}
	}
}

func holds(t *core.Tap) bool { return t != nil && len(t.Records()) > 0 }

// onSignals leaves on SIGTERM and SIGHUP (an ssh session's end), stopping
// what runs, so sinks flush and the terminal is restored. A closed stdout or
// stderr fails the write with EPIPE, which the run logs, instead of killing lw
// on screen; stop gives SIGPIPE back to the runtime.
func (r *run) onSignals() (stop func()) {
	sigs, pipe := make(chan os.Signal, 1), make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	signal.Notify(pipe, syscall.SIGPIPE)
	go func() {
		select {
		case <-sigs:
			r.send(func(a *app) { a.leave(Result{}) })
		case <-r.gone:
		}
	}()
	return func() { signal.Stop(sigs); signal.Stop(pipe) }
}

func (r *run) endAsks() { r.ended.Do(func() { close(r.gone) }) }

// close fails the asks, waits for the worker and stops what still runs
func (r *run) close() {
	r.endAsks()
	r.busy.Wait()
	if r.runner != nil && !r.leaving {
		r.runner.Stop()
	}
	close(r.jobs)
}

// active reports a run, or one starting
func (r *run) active() bool { return r.specs != nil || r.op != "" }

// ask is the Ask Start gets: the worker waits while the screen asks in a
// masked form, until it is answered or the screen leaves
func (r *run) ask(user string, generate bool) ([]byte, error) {
	reply := make(chan []byte, 1)
	r.send(func(a *app) { a.askPassword(user, generate, reply) })
	select {
	case pw := <-reply:
		if pw == nil {
			return nil, errors.New("no password given")
		}
		return pw, nil
	case <-r.gone:
		return nil, errors.New("the screen closed")
	}
}

// tick runs what the worker and the state watch brought, then reads the
// taps into the view; before any key handling, so it neither clears the
// status nor reaches a text field
func (a *app) tick() {
	r := a.live
	r.posted.Store(false)
	r.mu.Lock()
	later := r.later
	r.later = nil
	r.mu.Unlock()
	for _, f := range later {
		f(a)
	}
	a.drain(drainBytes, r.state.Log, r.tap)
}

// tap runs the pipelines here, the screen staying, and gives the view the
// keys: t. After an edit it runs them again in place of the earlier ones, as
// a reload does.
func (a *app) tap() {
	r := a.live
	switch {
	case r.runner == nil:
		a.note = "t runs the pipelines here only from lw --tui"
		return
	case a.problem != nil:
		a.status = "not valid yet: ! shows the problem"
		return
	case r.op != "":
		a.note = r.op + "…"
		return
	}
	specs := config.PipelineSpecs(a.comp.Pipelines)
	if r.specs != nil && slices.Equal(specs, r.specs) {
		a.viewing = true
		return
	}
	r.op = "starting"
	r.do(func() {
		tap, err := r.runner.Start(specs, r.ask)
		r.send(func(a *app) { a.started(specs, tap, err) })
	})
}

// started applies Start's outcome: what runs, and the view, or why the new
// pipelines do not, on the part that failed. An earlier run that stopped is
// read whole first, so a rule in the view marks where the next began.
func (a *app) started(specs []config.Spec, tap *core.Tap, err error) {
	r := a.live
	if r.leaving {
		return
	}
	if old := r.tap; old != nil && old != tap {
		a.drain(math.MaxInt, old)
		mark := "rerun "
		if tap == nil {
			mark = "stopped "
		}
		a.view.mark(mark + time.Now().Format("15:04:05"))
	}
	r.op, r.tap = "", tap
	r.fed.Store(tap)
	switch {
	case err == nil:
		r.specs, a.viewing = specs, true
	case tap != nil:
		a.fault(err, "not rerun: %s; the earlier pipelines still run")
	default:
		r.specs = nil
		a.fault(err, "%s")
	}
}

// fault chooses the part a start error names, placed as a problem is, and
// shows the error in format
func (a *app) fault(err error, format string) {
	text := err.Error()
	if pi, n, key, why, ok := compose.Locate(err); ok && pi >= 0 && pi < len(a.comp.Pipelines) {
		if pi != a.pi {
			a.pi, a.row = pi, [3]int{}
		}
		a.bar, a.inspect = false, false
		a.choose(n)
		text = why
		if where := a.where(pi, n, key); where != "" {
			text = where + ": " + why
		}
	}
	a.dialog = textNotice("Not started", fmt.Sprintf(format, text))
}

// leave ends the screen with res once nothing runs: q, r and o's choices
func (a *app) leave(res Result) {
	r := a.live
	a.result, a.dialog = res, nil
	if !r.active() {
		a.done = true
		return
	}
	r.leaving, r.op, a.note = true, "stopping", "stopping the pipelines…"
	r.endAsks()
	r.do(func() {
		r.runner.Stop()
		r.send(func(a *app) { a.done = true })
	})
}

// runMark says on the bar what runs: a call underway, or the counts of the
// pipeline shown
func (a *app) runMark() (string, ui.Style) {
	r := a.live
	switch {
	case r.op != "":
		return r.op + "…", a.th.Muted
	case r.specs == nil:
		return "", a.th.Muted
	}
	c := r.state.Counts[a.pipeline().Name]
	mark, style := string(a.font.arrow)+" running", a.th.Accent
	if r.state.Ended {
		mark, style = "input ended", a.th.Muted
	}
	mark += fmt.Sprintf(" · %d in · %d filtered", c.In, c.Filtered)
	if c.SinksDropped > 0 {
		mark += fmt.Sprintf(" · %d sinks dropped", c.SinksDropped)
	}
	if r.tap != nil && r.tap.Dropped() > 0 {
		mark += fmt.Sprintf(" · screen missed %d", r.tap.Dropped())
	}
	return mark, style
}
