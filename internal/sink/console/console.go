package console

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/logline"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"

	"github.com/lixenwraith/color"
	"github.com/lixenwraith/log"
	"github.com/lixenwraith/terminal/inline"
	"golang.org/x/term"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSink("console", NewConsoleSinkPlugin); err != nil {
		panic(fmt.Sprintf("failed to register console sink: %v", err))
	}
}

// ConsoleSink writes formatted entries to stdout or stderr
type ConsoleSink struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Configuration
	config  *config.ConsoleSinkOptions
	escape  bool
	palette *palette // nil when color is off

	// Application
	input  chan core.TransportEvent
	output io.Writer
	logger *log.Logger // application logger
	batch  []byte      // the lines of one write, reused

	// Runtime
	done      chan struct{}
	exited    chan struct{}
	started   atomic.Bool
	stopOnce  sync.Once
	startTime time.Time

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  core.AtomicTime
}

// levelStyles and markStyles are ANSI 16, so the terminal's theme picks the
// shades and a text console renders them: cyan, not blue, reads on black;
// grey sets the stamp and punctuation back from the text, magenta the tag
var levelStyles = map[string]inline.Style{
	"ERROR": inline.FgANSI(color.ANSIRed).Bold(),
	"WARN":  inline.FgANSI(color.ANSIYellow),
	"INFO":  inline.FgANSI(color.ANSIGreen),
	"DEBUG": inline.FgANSI(color.ANSICyan),
	"TRACE": inline.FgANSI(color.ANSIBrightBlack),
}

var markStyles = [...]inline.Style{
	logline.MarkTime:  inline.FgANSI(color.ANSIBrightBlack),
	logline.MarkTag:   inline.FgANSI(color.ANSIMagenta),
	logline.MarkKey:   inline.FgANSI(color.ANSICyan),
	logline.MarkPunct: inline.FgANSI(color.ANSIBrightBlack),
}

// NewConsoleSinkPlugin creates a console sink through plugin factory
func NewConsoleSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts, err := config.Decode[config.ConsoleSinkOptions]("sink", "console", configMap)
	if err != nil {
		return nil, err
	}

	output := Stream(opts.Target)

	// inline decides auto: a terminal, NO_COLOR empty or unset, TERM not
	// dumb. Paint returns its text unchanged exactly when color is off.
	printer := inline.New(output)
	if opts.Color != "auto" {
		printer.SetColor(opts.Color == "always")
	}
	var pal *palette
	if printer.Paint("x", inline.Style{}) != "x" {
		pal = newPalette(printer)
	}

	// Create and return plugin instance
	cs := &ConsoleSink{
		id:      id,
		proxy:   proxy,
		config:  opts,
		escape:  opts.Escape == "always" || opts.Escape == "auto" && term.IsTerminal(int(output.Fd())),
		palette: pal,
		input:   make(chan core.TransportEvent, opts.BufferSize),
		output:  output,
		done:    make(chan struct{}),
		exited:  make(chan struct{}),
		logger:  logger,
	}

	// Create session for output
	cs.session = proxy.CreateSession(
		fmt.Sprintf("console:%s", opts.Target),
		map[string]any{
			"instance_id": id,
			"type":        "console",
			"target":      opts.Target,
		},
	)

	cs.logger.Info("msg", "Console sink initialized",
		"component", "console_sink",
		"instance_id", id,
		"target", opts.Target,
		"escape", cs.escape,
		"color", pal != nil,
	)

	return cs, nil
}

// Stream is the stream a console sink with target writes
func Stream(target string) *os.File {
	if target == "stderr" {
		return os.Stderr
	}
	return os.Stdout
}

// Capabilities returns supported capabilities
func (cs *ConsoleSink) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware, // Single output session
		core.CapBackpressure, // a slow reader slows the pipeline, as with any filter
	}
}

// Input returns the channel for sending transport events
func (cs *ConsoleSink) Input() chan<- core.TransportEvent {
	return cs.input
}

// Start begins the processing loop
func (cs *ConsoleSink) Start(ctx context.Context) error {
	cs.startTime = time.Now()
	cs.started.Store(true)
	go cs.processLoop(ctx)
	cs.logger.Info("msg", "Console sink started",
		"component", "console_sink",
		"target", cs.config.Target)
	return nil
}

// Stop writes what is queued, then returns
func (cs *ConsoleSink) Stop() {
	cs.logger.Info("msg", "Stopping console sink", "target", cs.config.Target)

	// Remove session
	if cs.session != nil {
		cs.proxy.RemoveSession(cs.session.ID)
	}

	cs.stopOnce.Do(func() { close(cs.done) })
	if cs.started.Load() {
		<-cs.exited
	}

	cs.logger.Info("msg", "Console sink stopped",
		"instance_id", cs.id,
		"target", cs.config.Target,
	)
}

// GetStats returns sink statistics
func (cs *ConsoleSink) GetStats() sink.SinkStats {
	lastProc := cs.lastProcessed.Load()

	return sink.SinkStats{
		ID:             cs.id,
		Type:           "console",
		TotalProcessed: cs.totalProcessed.Load(),
		StartTime:      cs.startTime,
		LastProcessed:  lastProc,
		Details: map[string]any{
			"target":      cs.config.Target,
			"buffer_size": cs.config.BufferSize,
			"escape":      cs.escape,
			"color":       cs.palette != nil,
		},
	}
}

// processLoop writes transport events until stopped, then what is queued
func (cs *ConsoleSink) processLoop(ctx context.Context) {
	defer close(cs.exited)
	for {
		select {
		case event := <-cs.input:
			cs.write(event)
		case <-ctx.Done():
			cs.drain()
			return
		case <-cs.done:
			cs.drain()
			return
		}
	}
}

func (cs *ConsoleSink) drain() {
	for {
		select {
		case event := <-cs.input:
			cs.write(event)
		default:
			return
		}
	}
}

// write writes the event with the lines queued behind it, a batch a write; a
// batch a write fails is lost, as its lines would be one by one
func (cs *ConsoleSink) write(event core.TransportEvent) {
	for more := true; more; {
		var n int
		cs.batch, n, event, more = sink.Batch(cs.batch, event, cs.input, cs.line)
		if _, err := cs.output.Write(cs.batch); err != nil {
			cs.logger.Error("msg", "Failed to write to console",
				"component", "console_sink",
				"target", cs.config.Target,
				"error", err)
			continue
		}
		cs.totalProcessed.Add(uint64(n))
		cs.lastProcessed.Store(time.Now())
	}
	cs.batch = sink.Kept(cs.batch)
}

// line appends the event's line as the console shows it: escaped on a
// terminal, painted when color is on
func (cs *ConsoleSink) line(dst []byte, event core.TransportEvent) []byte {
	payload := event.Payload
	if cs.escape {
		payload = logline.EscapeControls(payload)
	}
	if cs.palette != nil {
		return cs.palette.paint(dst, payload, event.Entry)
	}
	return append(dst, payload...)
}

// palette holds each style's opening and closing codes, rendered once
type palette struct {
	marks  [len(markStyles)][2]string
	levels map[string][2]string
}

func newPalette(p *inline.Printer) *palette {
	codes := func(st inline.Style) [2]string {
		open, end, _ := strings.Cut(p.Paint("\x00", st), "\x00")
		return [2]string{open, end}
	}
	pal := &palette{levels: make(map[string][2]string, len(levelStyles))}
	for kind, st := range markStyles {
		pal.marks[kind] = codes(st)
	}
	for level, st := range levelStyles {
		pal.levels[level] = codes(st)
	}
	return pal
}

// paint appends the line to out, coloring the parts logline marks, after
// escaping: the escape sequences are the sink's own
func (pal *palette) paint(out, payload []byte, e core.LogEntry) []byte {
	s := string(payload)
	at := 0
	logline.Marks(s, e, func(m logline.Mark) {
		c, ok := pal.marks[m.Kind], m.Kind != logline.MarkLevel
		if !ok {
			c, ok = pal.levels[m.Level]
		}
		if ok && m.Start >= at {
			out = append(append(out, s[at:m.Start]...), c[0]...)
			out = append(append(out, s[m.Start:m.End]...), c[1]...)
			at = m.End
		}
	})
	return append(out, s[at:]...)
}
