package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lixenwraith/logwisp/internal/authz"
	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/pipeline"
	"github.com/lixenwraith/logwisp/internal/service"
	"github.com/lixenwraith/logwisp/internal/sink/console"
	"github.com/lixenwraith/logwisp/internal/tui"

	"golang.org/x/term"
)

// The records a tap holds for the screen between ticks: a run's, lw's log's
const (
	runTapRecords = 1024
	logTapRecords = 256
)

// screenRunner runs lw --tui's pipelines while the screen owns the terminal.
// Start loads them as r would, through the file, environment and overrides,
// and replaces what runs as a reload does.
type screenRunner struct {
	load config.Args
	mu   sync.Mutex // svc, tap and log, which State reads from another goroutine
	svc  *service.Service
	tap  *core.Tap
	log  *core.Tap
}

func (r *screenRunner) Start(specs []config.Spec, ask tui.Ask) (*core.Tap, error) {
	cfg, err := r.config(specs)
	if err == nil {
		err = r.startLogger(cfg)
	}
	if err != nil {
		return r.tap, err
	}
	authz.SetAsker(ask)
	tap := core.NewTap(runTapRecords)
	tap.All.Store(true) // until the view's first draw says what its point shows
	if r.svc == nil {
		svc, err := bootstrapService(context.Background(), cfg, tap)
		if err != nil {
			return nil, placed(cfg, err)
		}
		if err := svc.Start(); err != nil {
			svc.Shutdown()
			return nil, placed(cfg, err)
		}
		r.set(svc, tap)
		return tap, nil
	}
	svc, _, _, err := handleReload(context.Background(), cfg, r.svc, nil, tap)
	switch {
	case errors.Is(err, errServiceStopped):
		r.set(nil, nil)
		return nil, placed(cfg, err)
	case err != nil:
		return r.tap, placed(cfg, err)
	}
	r.set(svc, tap)
	return tap, nil
}

// placed addresses a start error to the part it names, by the path the
// screen places a configuration problem by
func placed(cfg *config.Config, err error) error {
	part, ok := errors.AsType[*pipeline.PartError](err)
	if !ok {
		return err
	}
	pi := slices.IndexFunc(cfg.Pipelines, func(p config.PipelineConfig) bool { return p.Name == part.Pipeline })
	if pi < 0 {
		return err
	}
	return config.At(compose.Node{Role: part.Role, ID: part.ID}.Path(pi), err)
}

func (r *screenRunner) set(svc *service.Service, tap *core.Tap) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.svc, r.tap = svc, tap
}

func (r *screenRunner) Stop() {
	r.mu.Lock()
	svc := r.svc
	r.svc, r.tap = nil, nil
	r.mu.Unlock()
	if svc != nil {
		svc.Shutdown()
	}
}

func (r *screenRunner) State() tui.RunState {
	r.mu.Lock()
	svc, st := r.svc, tui.RunState{Log: r.log}
	r.mu.Unlock()
	if svc == nil {
		return st
	}
	select {
	case <-svc.Done():
		st.Ended = true
	default:
	}
	st.Counts = map[string]tui.Counts{}
	pipelines, _ := svc.GetGlobalStats()["pipelines"].(map[string]any)
	for name, v := range pipelines {
		p, _ := v.(map[string]any)
		flow, _ := p["flow"].(map[string]any)
		var c tui.Counts
		c.In, _ = flow["total_processed"].(uint64)
		c.Filtered, _ = flow["total_dropped"].(uint64)
		c.SinksDropped, _ = p["total_dropped_by_sink"].(uint64)
		st.Counts[name] = c
	}
	return st
}

// close ends view mode before lw runs on or exits: nothing runs, lw's log is
// shut down, and terminals answer passwords again
func (r *screenRunner) close() {
	r.Stop()
	authz.SetAsker(nil)
	shutdownLogger()
	logger = nil
}

// config is specs as they would run on screen: no status reporter, as the
// screen shows the counts, and the terminal's streams the screen's
func (r *screenRunner) config(specs []config.Spec) (*config.Config, error) {
	load := r.load
	load.Specs = specs
	m, err := config.Load(load)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	cfg, err := m.Snapshot()
	if err != nil {
		return nil, err
	}
	cfg.StatusReporter = false
	return cfg, onScreen(cfg)
}

// onScreen gives the screen the streams that are the terminal: a console sink
// writing to it runs as a null sink with its id (the tap shows what it would
// print; both make the pipeline wait, not drop), and a console source would
// read the screen's keys
func onScreen(cfg *config.Config) error {
	for i := range cfg.Pipelines {
		p := &cfg.Pipelines[i]
		for _, s := range p.PluginSources {
			if s.Type == "console" && term.IsTerminal(int(os.Stdin.Fd())) {
				return config.At(compose.Node{Role: "source", ID: s.ID}.Path(i),
					errors.New("console reads the keyboard this screen uses: pipe input in (cmd | lw -T), or run with r"))
			}
		}
		for j, s := range p.PluginSinks {
			target, _ := s.Config["target"].(string)
			if s.Type == "console" && term.IsTerminal(int(console.Stream(target).Fd())) {
				p.PluginSinks[j] = config.PluginSinkConfig{ID: s.ID, Type: "null"}
			}
		}
	}
	return nil
}

// startLogger starts lw's log on the first run. While its console is the
// terminal, its records and the logger's own diagnostics go to the screen's
// lw stream instead: the one place that routes lw's log on screen.
func (r *screenRunner) startLogger(cfg *config.Config) error {
	if logger != nil {
		return nil
	}
	if err := initializeLogger(cfg); err != nil {
		logger = nil
		return err
	}
	c := logger.GetConfig()
	streams := map[string][]*os.File{"stdout": {os.Stdout}, "stderr": {os.Stderr}, "split": {os.Stdout, os.Stderr}}[c.ConsoleTarget]
	if c.EnableConsole && slices.ContainsFunc(streams, func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }) {
		w := lwStream{core.NewTap(logTapRecords)}
		logger.SetConsoleWriter(w)
		logger.SetErrorHandler(func(msg string) { w.Write([]byte(msg)) })
		r.mu.Lock()
		r.log = w.tap
		r.mu.Unlock()
	}
	return logger.Start()
}

// lwStream offers each record lw's log writes as an entry of source "lw"
type lwStream struct{ tap *core.Tap }

func (w lwStream) Write(p []byte) (int, error) {
	now := time.Now()
	line := strings.TrimRight(string(p), "\r\n") // a copy: the logger reuses p
	level, _, _ := core.LevelWord(line, "")
	w.tap.Offer(core.Tapped{Source: "lw", Event: core.TransportEvent{Time: now,
		Entry: core.LogEntry{Time: now, Source: "lw", Level: level, Message: line, RawSize: int64(len(p))}}})
	return len(p), nil
}
