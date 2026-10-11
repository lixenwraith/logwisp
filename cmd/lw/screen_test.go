package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/testutil"

	"github.com/lixenwraith/log"
	"golang.org/x/term"
)

// onTerminal makes *stream a pseudo-terminal's master, which is a terminal,
// until the test ends
func onTerminal(t *testing.T, stream **os.File) {
	t.Helper()
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil || !term.IsTerminal(int(pty.Fd())) {
		t.Skip("no pseudo-terminal here")
	}
	was := *stream
	*stream = pty
	t.Cleanup(func() { *stream = was; pty.Close() })
}

// screenRunnerFor is a runner on lw's settings in args, with specs to start
func screenRunnerFor(t *testing.T, args ...string) (*screenRunner, func(pipeline ...string) []config.Spec) {
	t.Helper()
	testutil.ClearEnvPrefix(t, "LOGWISP_")
	path := filepath.Join(t.TempDir(), "empty.toml")
	testutil.WriteFile(t, path, "")
	inv, err := parseCommandLine(append([]string{"-c", path}, args...))
	if err != nil {
		t.Fatal(err)
	}
	r := &screenRunner{load: inv.load}
	t.Cleanup(func() { r.Stop(); authz.SetAsker(nil) })
	return r, func(pipeline ...string) []config.Spec {
		inv, err := parseCommandLine(append([]string{"--pipeline", "p"}, pipeline...))
		if err != nil {
			t.Fatal(err)
		}
		return inv.load.Specs
	}
}

// A console sink writing to the terminal runs as a null sink with its id, which
// keeps the console's back-pressure, so the screen counts no sink drops a run
// would not have; one writing elsewhere keeps writing there
func TestConsoleSinksOnTheTerminalRunAsNullSinks(t *testing.T) {
	onTerminal(t, &os.Stdout)
	cfg := &config.Config{Pipelines: []config.PipelineConfig{{Name: "p", PluginSinks: []config.PluginSinkConfig{
		{ID: "out", Type: "console"}, {ID: "err", Type: "console", Config: map[string]any{"target": "stderr"}}}}}}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	stderr := os.Stderr
	os.Stderr = null
	defer func() { os.Stderr = stderr }()
	if err := onScreen(cfg); err != nil {
		t.Fatal(err)
	}
	s := cfg.Pipelines[0].PluginSinks
	if s[0].ID != "out" || s[0].Type != "null" || s[0].Config != nil || s[1].Type != "console" {
		t.Fatalf("%+v", s)
	}
	build, _ := plugin.GetSink(s[0].Type)
	stand, err := build(s[0].ID, s[0].Config, log.NewLogger(), session.NewProxy(session.NewManager(time.Minute), s[0].ID))
	if err != nil || !slices.Contains(stand.Capabilities(), core.CapBackpressure) {
		t.Fatalf("the stand-in drops where the console waits: %v", err)
	}
}

// A console source would read the screen's keys: it needs piped input, and
// the refusal names its part
func TestAConsoleSourceNeedsPipedInput(t *testing.T) {
	cfg := &config.Config{Pipelines: []config.PipelineConfig{{Name: "p", PluginSources: []config.PluginSourceConfig{{ID: "in", Type: "console"}}}}}
	in, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	stdin := os.Stdin
	os.Stdin = in
	err = onScreen(cfg)
	os.Stdin = stdin
	in.Close()
	if err != nil {
		t.Fatalf("piped: %v", err)
	}
	onTerminal(t, &os.Stdin)
	err = onScreen(cfg)
	if pi, n, _, why, ok := compose.Locate(err); !ok || pi != 0 || n != (compose.Node{Role: "source", ID: "in"}) || !strings.HasPrefix(why, "console reads the keyboard") {
		t.Fatalf("on a terminal: %v", err)
	}
}

// A start error names the part that failed, as a problem's path does, both
// when the part does not build and when it does not start
func TestAStartErrorNamesItsPart(t *testing.T) {
	testLogger(t)
	missing := filepath.Join(t.TempDir(), "missing")
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	for name, sink := range map[string]string{
		"does not build": fmt.Sprintf("tcp:host=127.0.0.1,port=9,tls.enabled=true,tls.cert_file=%s.pem,tls.key_file=%s.key", missing, missing),
		"does not start": fmt.Sprintf("tcp:host=127.0.0.1,port=%d", held.Addr().(*net.TCPAddr).Port),
	} {
		r, specs := screenRunnerFor(t, "--quiet")
		_, err := r.Start(specs("--source", "null", "--sink", "null", "--sink", sink), nil)
		if pi, n, _, _, ok := compose.Locate(err); !ok || pi != 0 || n != (compose.Node{Role: "sink", ID: "tcp"}) {
			t.Errorf("a sink that %s: %+v in %v", name, n, err)
		}
	}
}

// While the screen runs, a password the terminal would be asked for is asked
// through Start's ask; once the screen closes, the terminal is asked again.
// It runs alone: an earlier test's startup end stops every terminal read.
func TestTheScreenAsksInTheTerminalsPlace(t *testing.T) {
	if os.Getenv("LW_TEST_SCREEN_ASKS") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheScreenAsksInTheTerminalsPlace$", "-test.v")
		cmd.Env = append(os.Environ(), "LW_TEST_SCREEN_ASKS=1")
		out, err := cmd.CombinedOutput()
		switch {
		case strings.Contains(string(out), "--- SKIP"):
			t.Skip("no pseudo-terminal here")
		case err != nil || !strings.Contains(string(out), "--- PASS"):
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	if probe, err := os.Open("/dev/ptmx"); err != nil || !term.IsTerminal(int(probe.Fd())) {
		t.Skip("no pseudo-terminal here")
	} else {
		probe.Close()
	}
	testLogger(t)
	r, specs := screenRunnerFor(t, "--quiet")
	asked := make(chan string, 2)
	ask := func(user string, generate bool) ([]byte, error) {
		asked <- user
		return []byte("from-the-screen"), nil
	}
	started := make(chan struct{})
	go func() {
		defer close(started)
		r.Start(specs("--preset", "edge:path="+t.TempDir()+",to=127.0.0.1:9,pin=sha256//"+strings.Repeat("A", 43)+"=,user=on-screen,password_file=/dev/ptmx"), ask)
	}()
	select {
	case user := <-asked:
		if user != "on-screen" {
			t.Fatalf("asked for %s", user)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal was asked, not the screen")
	}
	<-started
	r.close()
	go authz.ReadPassword("/dev/ptmx", "after-the-screen", false)
	select {
	case user := <-asked:
		t.Fatalf("the closed screen was asked for %s", user)
	case <-time.After(200 * time.Millisecond):
	}
}

// A run on screen has no status reporter, whatever the file says: the bar
// shows the counts, and a rerun keeps no cancel for one
func TestARunOnScreenHasNoStatusReporter(t *testing.T) {
	r, specs := screenRunnerFor(t, "--status_reporter=true")
	cfg, err := r.config(specs("--source", "null", "--sink", "null"))
	if err != nil || cfg.StatusReporter {
		t.Fatalf("status reporter %v: %v", cfg != nil && cfg.StatusReporter, err)
	}
}

// The state counts each pipeline's entries in and filtered by its flow apart
// from those its sinks dropped
func TestTheStateCountsInFilteredAndSinkDrops(t *testing.T) {
	testLogger(t)
	r, specs := screenRunnerFor(t, "--quiet")
	if _, err := r.Start(specs("--source", "random:interval_ms=1", "--filter", "exclude:patterns=.", "--sink", "null"), nil); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		c := r.State().Counts["p"]
		if c.In > 0 && c.Filtered > 0 && c.SinksDropped == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("counts %+v", c)
		}
	}
}

// A run's entries reach its tap. A rerun replaces what runs as a reload does:
// pipelines that do not build leave the earlier ones running, with their tap;
// a start that fails once those stopped leaves nothing.
func TestARerunKeepsWhatRunsUntilTheNewPipelinesBuild(t *testing.T) {
	testLogger(t)
	r, specs := screenRunnerFor(t, "--quiet")
	tap, err := r.Start(specs("--source", "random:interval_ms=1", "--sink", "null"), nil)
	if err != nil || tap == nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case rec := <-tap.Records():
		if rec.Pipeline != "p" || rec.Stage != "" {
			t.Fatalf("%+v", rec)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no entry reached the run's tap")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	bad := fmt.Sprintf("tcp:host=127.0.0.1,port=9,tls.enabled=true,tls.cert_file=%s.pem,tls.key_file=%s.key", missing, missing)
	if kept, err := r.Start(specs("--source", "null", "--sink", bad), nil); kept != tap || err == nil || len(r.State().Counts) != 1 {
		t.Fatalf("a rerun that does not build: %v, kept %v", err, kept == tap)
	}
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	taken := fmt.Sprintf("tcp:host=127.0.0.1,port=%d", held.Addr().(*net.TCPAddr).Port)
	if kept, err := r.Start(specs("--source", "null", "--sink", taken), nil); kept != nil || err == nil || len(r.State().Counts) != 0 {
		t.Fatalf("a rerun that does not start: %v, %v", err, r.State())
	}
}

// A run's tap takes what the flow drops from its first entry, before a view
// says whether its point shows drops
func TestARunsTapTakesDropsFromItsStart(t *testing.T) {
	testLogger(t)
	r, specs := screenRunnerFor(t, "--quiet")
	tap, err := r.Start(specs("--source", "random:interval_ms=1", "--filter", "exclude:patterns=.", "--sink", "null"), nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case rec := <-tap.Records():
		if rec.Stage != "filters" {
			t.Fatalf("%+v", rec)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dropped entry reached the run's tap")
	}
}

// lw's log, written to the terminal, shows in the screen's lw stream instead;
// written elsewhere, it stays there
func TestLwsLogShowsOnTheScreen(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	stderr := os.Stderr
	os.Stderr = null
	elsewhere := screenLog(t)
	os.Stderr = stderr
	if elsewhere != nil {
		t.Fatal("an lw stream for a log written to a file")
	}
	onTerminal(t, &os.Stderr)
	log := screenLog(t)
	if log == nil {
		t.Fatal("no lw stream for a log on the terminal")
	}
	select {
	case rec := <-log.Records():
		if rec.Event.Entry.Source != "lw" || rec.Event.Entry.Message == "" {
			t.Fatalf("%+v", rec)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lw's log did not reach its stream")
	}
}

// screenLog is the lw stream of a run whose log writes info to stderr
func screenLog(t *testing.T) *core.Tap {
	t.Helper()
	was := logger
	logger = nil
	r, specs := screenRunnerFor(t, "--logging.output=stderr", "--logging.level=info")
	t.Cleanup(func() { r.close(); logger = was })
	if _, err := r.Start(specs("--source", "null", "--sink", "null"), nil); err != nil {
		t.Fatal(err)
	}
	return r.State().Log
}
