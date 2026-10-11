package tui

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/terminal"
)

// fakeRunner keeps the screen's calls; start, when set, answers Start
type fakeRunner struct {
	mu    sync.Mutex
	specs [][]config.Spec
	stops int
	state RunState
	start func(ask Ask) (*core.Tap, error)
}

func (f *fakeRunner) Start(specs []config.Spec, ask Ask) (*core.Tap, error) {
	f.mu.Lock()
	f.specs = append(f.specs, specs)
	start := f.start
	f.mu.Unlock()
	if start != nil {
		return start(ask)
	}
	return core.NewTap(1), nil
}

func (f *fakeRunner) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeRunner) State() RunState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *fakeRunner) calls() (starts, stops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.specs), f.stops
}

// running is a screen on c whose runner is f, already running c, back on
// the diagram from the view t opened
func running(t *testing.T, c *compose.Composition, f *fakeRunner) *app {
	t.Helper()
	a := mono(c)
	a.live = newRun(f, func() {})
	press(a, "t")
	await(t, a)
	if a.live.specs == nil || !a.viewing {
		t.Fatalf("t did not run, viewing %v: %T %s", a.viewing, a.dialog, a.status)
	}
	press(a, "t")
	return a
}

// await ticks once the runner's side brought something back, as the woken
// screen would
func await(t *testing.T, a *app) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		a.live.mu.Lock()
		n := len(a.live.later)
		a.live.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing came back from the runner")
		}
	}
	press(a, terminal.KeyNone)
}

// The tick is handled before any key: it clears no status and types nothing
// into the field being edited
func TestATickKeepsTheStatusAndTheField(t *testing.T) {
	a := mono(pipeline(t, []string{"file"}, []string{"null"}))
	press(a, terminal.KeyEnter, terminal.KeyEnter, "ab")
	a.status = "refused"
	press(a, terminal.KeyNone)
	if a.status != "refused" || a.insp.field == nil || a.insp.field.Value() != "ab" {
		t.Fatalf("status %q, field %v", a.status, a.insp.field)
	}
}

// Wakes coalesce: one tick waits at a time, and handling it allows the next
func TestWakesCoalesce(t *testing.T) {
	posts := 0
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	a.live = newRun(nil, func() { posts++ })
	a.live.wake()
	a.live.wake()
	if press(a, terminal.KeyNone); posts != 1 {
		t.Fatalf("%d ticks posted for two wakes", posts)
	}
	if a.live.wake(); posts != 2 {
		t.Fatal("a handled tick kept the next wake from posting")
	}
}

// The state is read on, but the screen is woken only by a change
func TestTheStateWakesTheScreenOnlyWhenItChanges(t *testing.T) {
	var posts sync.WaitGroup
	f := &fakeRunner{state: RunState{Counts: map[string]Counts{"p": {In: 1}}}}
	r := newRun(f, func() { posts.Done() })
	posts.Add(1)
	go r.watch(time.Millisecond)
	defer r.endAsks()
	posts.Wait()
	time.Sleep(20 * time.Millisecond)
	r.posted.Store(false)
	time.Sleep(20 * time.Millisecond)
	if r.posted.Load() {
		t.Fatal("an unchanged state woke the screen")
	}
	posts.Add(1)
	f.mu.Lock()
	f.state = RunState{Counts: map[string]Counts{"p": {In: 2}}}
	f.mu.Unlock()
	posts.Wait()
}

// t runs only a valid composition
func TestTapRefusesAnInvalidComposition(t *testing.T) {
	f := &fakeRunner{}
	a := mono(pipeline(t, []string{"null"}, []string{"tcp"}))
	a.live = newRun(f, func() {})
	if press(a, "t"); a.status != "not valid yet: ! shows the problem" || a.live.op != "" {
		t.Fatalf("status %q, op %q", a.status, a.live.op)
	}
	if starts, _ := f.calls(); starts != 0 {
		t.Fatal("started an invalid composition")
	}
}

// t runs the pipelines and marks the bar; unchanged, t only opens the view,
// and after an edit it runs the edited pipelines
func TestTapRerunsAfterAnEdit(t *testing.T) {
	f := &fakeRunner{state: RunState{Counts: map[string]Counts{"p": {In: 7, Filtered: 2}}}}
	a := running(t, pipeline(t, []string{"null"}, []string{"null"}), f)
	a.live.state = f.State()
	first := config.PipelineSpecs(a.comp.Pipelines)
	if top := text(render(a, 100, 24), 100)[0]; !strings.Contains(top, "running · 7 in · 2 filtered") || !slices.Equal(f.specs[0], first) {
		t.Fatalf("%q, specs %v", top, f.specs)
	}
	if press(a, "t"); a.live.op != "" || !a.viewing {
		t.Fatalf("t on what runs: op %q, viewing %v", a.live.op, a.viewing)
	}
	press(a, "t")
	_, err := a.comp.Add(0, "sink", "console")
	a.edit(err)
	press(a, "t")
	await(t, a)
	if starts, _ := f.calls(); starts != 2 || slices.Equal(f.specs[1], first) || !slices.Equal(a.live.specs, f.specs[1]) {
		t.Fatalf("rerun: %d starts, running %v", starts, a.live.specs)
	}
}

// A rerun that does not build leaves the earlier pipelines running, and says
// so; one that fails once they stopped leaves nothing running
func TestAFailedRerunSaysWhatRuns(t *testing.T) {
	f := &fakeRunner{}
	a := running(t, pipeline(t, []string{"null"}, []string{"null"}), f)
	earlier, tap := a.live.specs, a.live.tap
	notice := func() string { return strings.Join(text(render(a, 120, 30), 120), "\n") }
	f.start = func(Ask) (*core.Tap, error) { return tap, errors.New("bad sink") }
	a.edit(a.comp.Set(0, compose.Node{Role: "format"}, "type", "txt"))
	press(a, "t")
	await(t, a)
	if !slices.Equal(a.live.specs, earlier) || a.live.tap != tap || !strings.Contains(notice(), "not rerun: bad sink; the earlier pipelines still run") {
		t.Fatalf("running %v\n%s", a.live.specs, notice())
	}
	f.start = func(Ask) (*core.Tap, error) { return nil, errors.New("port taken") }
	press(a, terminal.KeyEscape, "t")
	await(t, a)
	if a.live.specs != nil || a.live.tap != nil || strings.Contains(notice(), "still run") {
		t.Fatalf("running %v\n%s", a.live.specs, notice())
	}
}

// A start error chooses the part its path names, as a problem's does, and
// shows its text
func TestAStartErrorChoosesItsPart(t *testing.T) {
	why := config.At(compose.Node{Role: "sink", ID: "console"}.Path(0), errors.New("failed to start sink console: write: broken pipe"))
	f := &fakeRunner{start: func(Ask) (*core.Tap, error) { return nil, why }}
	a := mono(pipeline(t, []string{"null"}, []string{"null", "console"}))
	a.live = newRun(f, func() {})
	press(a, "t")
	await(t, a)
	n, _ := a.node()
	if screen := strings.Join(text(render(a, 120, 30), 120), " "); n != (compose.Node{Role: "sink", ID: "console"}) || !strings.Contains(screen, "sink console: write") {
		t.Fatalf("on %+v\n%s", n, screen)
	}
}

// q asks before it stops what runs, and quits once it stopped
func TestQuitAsksWhileRunning(t *testing.T) {
	f := &fakeRunner{}
	a := running(t, pipeline(t, []string{"null"}, []string{"null"}), f)
	press(a, "q")
	if c, asks := a.dialog.(*confirm); !asks || !strings.Contains(c.question, "Stop the pipelines") {
		t.Fatalf("q while running: %T", a.dialog)
	}
	press(a, "y")
	await(t, a)
	if _, stops := f.calls(); !a.done || stops != 1 {
		t.Fatalf("done %v after %d stops", a.done, stops)
	}
}

// r and o's choices stop the run before the screen leaves, and take no key
// meanwhile
func TestLeavingStopsTheRunFirst(t *testing.T) {
	for _, keys := range []string{"r", "oc"} {
		f := &fakeRunner{}
		a := running(t, pipeline(t, []string{"null"}, []string{"null"}), f)
		if press(a, keys, "q"); a.done || a.dialog != nil {
			t.Fatalf("%s left before stopping: %T", keys, a.dialog)
		}
		await(t, a)
		if _, stops := f.calls(); !a.done || stops != 1 || a.result.Exit == Quit {
			t.Fatalf("%s: done %v after %d stops, %+v", keys, a.done, stops, a.result)
		}
	}
}

// A password a terminal would be asked for is asked in a masked form; with
// generate, Enter alone draws one, shown once, and that is the answer
func TestPasswordsAreAskedMasked(t *testing.T) {
	for _, generate := range []bool{false, true} {
		var got []byte
		f := &fakeRunner{start: func(ask Ask) (*core.Tap, error) {
			pw, err := ask("alice", generate)
			got = pw
			return core.NewTap(1), err
		}}
		a := mono(pipeline(t, []string{"null"}, []string{"null"}))
		a.live = newRun(f, func() {})
		press(a, "t")
		await(t, a)
		typed := "s3cret"
		if generate {
			typed = ""
		}
		press(a, typed)
		if screen := strings.Join(text(render(a, 100, 30), 100), "\n"); !strings.Contains(screen, "Password for alice") ||
			strings.Contains(screen, "s3cret") || !strings.Contains(screen, strings.Repeat("*", len(typed))) {
			t.Fatalf("the form:\n%s", screen)
		}
		press(a, terminal.KeyEnter)
		shown := strings.Join(text(render(a, 100, 30), 100), " ")
		if generate {
			press(a, terminal.KeyEnter) // read
		}
		await(t, a)
		if a.live.specs == nil || len(got) == 0 || !generate && string(got) != typed || generate && !strings.Contains(shown, "shown this once: "+string(got)) {
			t.Fatalf("generate %v: answered %q\n%s", generate, got, shown)
		}
	}
}

// A generated password stays on screen until a key closes its notice: the
// start goes on only then, so neither a start error nor the next ask hides it
func TestAGeneratedPasswordStaysUntilRead(t *testing.T) {
	for name, then := range map[string]func(Ask) error{
		"a start error": func(Ask) error { return errors.New("port taken") },
		"the next ask":  func(ask Ask) error { _, err := ask("bob", true); return err },
	} {
		answered := make(chan struct{})
		f := &fakeRunner{start: func(ask Ask) (*core.Tap, error) {
			if _, err := ask("alice", true); err != nil {
				return nil, err
			}
			close(answered)
			return core.NewTap(1), then(ask)
		}}
		a := mono(pipeline(t, []string{"null"}, []string{"null"}))
		a.live = newRun(f, func() {})
		press(a, "t")
		await(t, a)
		press(a, terminal.KeyEnter)
		select {
		case <-answered:
			t.Fatalf("%s: answered before the password was read", name)
		case <-time.After(50 * time.Millisecond):
		}
		if press(a, terminal.KeyNone); !strings.Contains(strings.Join(text(render(a, 100, 30), 100), " "), "shown this once") {
			t.Fatalf("%s: the password left the screen unread: %T", name, a.dialog)
		}
		press(a, "x")
		<-answered
		await(t, a)
		if screen := strings.Join(text(render(a, 100, 30), 100), " "); strings.Contains(screen, "shown this once") {
			t.Fatalf("%s: the notice outlived its key\n%s", name, screen)
		}
		a.live.close()
	}
}

// On screen a closed stdout fails the write with EPIPE instead of killing lw
// with the terminal raw; leaving gives SIGPIPE back to the runtime
func TestAClosedStdoutFailsWritesOnScreen(t *testing.T) {
	if os.Getenv("LW_TEST_CLOSED_STDOUT") != "" {
		stop := newRun(nil, func() {}).onSignals()
		_, err := os.Stdout.Write([]byte("x\n"))
		fmt.Fprintln(os.Stderr, "on screen:", err)
		stop()
		os.Stdout.Write([]byte("x\n"))
		fmt.Fprintln(os.Stderr, "lived on")
		os.Exit(0)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	var stderr strings.Builder
	cmd := exec.Command(os.Args[0], "-test.run=^TestAClosedStdoutFailsWritesOnScreen$")
	cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), "LW_TEST_CLOSED_STDOUT=1"), w, &stderr
	cmd.Run()
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !strings.Contains(stderr.String(), "on screen: write /dev/stdout: broken pipe") || !ws.Signaled() || ws.Signal() != syscall.SIGPIPE {
		t.Fatalf("%v\n%s", ws, stderr.String())
	}
}

// SIGTERM and SIGHUP stop what runs and leave
func TestSignalsStopTheRunAndLeave(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		f := &fakeRunner{}
		a := running(t, pipeline(t, []string{"null"}, []string{"null"}), f)
		stop := a.live.onSignals()
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		await(t, a)
		await(t, a)
		stop()
		if _, stops := f.calls(); !a.done || stops != 1 {
			t.Fatalf("%v: done %v after %d stops", sig, a.done, stops)
		}
	}
}
