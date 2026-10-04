package console

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/sink"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
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
	config *config.ConsoleSinkOptions
	escape bool

	// Application
	input  chan core.TransportEvent
	output io.Writer
	logger *log.Logger // application logger

	// Runtime
	done      chan struct{}
	exited    chan struct{}
	started   atomic.Bool
	stopOnce  sync.Once
	startTime time.Time

	// Statistics
	totalProcessed atomic.Uint64
	lastProcessed  atomic.Value // time.Time
}

const (
	// Defaults
	DefaultConsoleTarget     = "stdout"
	DefaultConsoleBufferSize = 1000
	DefaultConsoleEscape     = "auto"
)

// NewConsoleSinkPlugin creates a console sink through plugin factory
func NewConsoleSinkPlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (sink.Sink, error) {
	opts := &config.ConsoleSinkOptions{Target: DefaultConsoleTarget, Escape: DefaultConsoleEscape}

	// Scan config map into struct
	if err := config.Scan(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := lconfig.OneOf("stdout", "stderr")(opts.Target); err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	if err := lconfig.OneOf("auto", "always", "never")(opts.Escape); err != nil {
		return nil, fmt.Errorf("escape: %w", err)
	}

	output := os.Stdout
	if opts.Target == "stderr" {
		output = os.Stderr
	}

	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultConsoleBufferSize
	}

	// Create and return plugin instance
	cs := &ConsoleSink{
		id:     id,
		proxy:  proxy,
		config: opts,
		escape: opts.Escape == "always" || opts.Escape == "auto" && term.IsTerminal(int(output.Fd())),
		input:  make(chan core.TransportEvent, opts.BufferSize),
		output: output,
		done:   make(chan struct{}),
		exited: make(chan struct{}),
		logger: logger,
	}
	cs.lastProcessed.Store(time.Time{})

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
	)

	return cs, nil
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
	lastProc, _ := cs.lastProcessed.Load().(time.Time)

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

func (cs *ConsoleSink) write(event core.TransportEvent) {
	payload := event.Payload
	if cs.escape {
		payload = escapeControls(payload)
	}
	if _, err := cs.output.Write(payload); err != nil {
		cs.logger.Error("msg", "Failed to write to console",
			"component", "console_sink",
			"target", cs.config.Target,
			"error", err)
		return
	}
	cs.totalProcessed.Add(1)
	cs.lastProcessed.Store(time.Now())
}

// escapeControls writes what a terminal would act on or reorder (C0 and C1
// controls but tab, DEL, bidi controls, line separators, invalid UTF-8) as
// <hex>, keeping the final newline: a log line cannot drive the terminal.
// Other invisible characters stay: emoji and Indic scripts need ZWJ.
func escapeControls(p []byte) []byte {
	body, newline := bytes.CutSuffix(p, []byte{'\n'})
	if printableASCII(body) {
		return p
	}
	out := make([]byte, 0, len(p)+16)
	for len(body) > 0 {
		r, n := utf8.DecodeRune(body)
		if !terminalControl(r, n) {
			out = append(out, body[:n]...)
		} else {
			out = append(out, '<')
			out = hex.AppendEncode(out, body[:n])
			out = append(out, '>')
		}
		body = body[n:]
	}
	if newline {
		out = append(out, '\n')
	}
	return out
}

func terminalControl(r rune, size int) bool {
	switch {
	case r == utf8.RuneError && size == 1:
		return true
	case r < 0x20:
		return r != '\t'
	case r >= 0x7f && r <= 0x9f, r == 0x061c, r == 0x200e, r == 0x200f,
		r >= 0x2028 && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\t' {
			return false
		}
	}
	return true
}
