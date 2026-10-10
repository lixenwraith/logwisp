// Package tui is lw --tui: pipelines composed on a full-screen canvas drawn as
// the website draws them, then run or written as a command line, environment
// or file. The pipelines are a compose.Composition; this package only draws
// them and turns keys into the engine's edits.
package tui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// Exit is how the user left
type Exit int

const (
	Quit  Exit = iota // nothing to do
	Start             // run Pipelines
	Print             // print Output
)

// Result is the user's choice on leaving
type Result struct {
	Exit      Exit
	Pipelines []config.PipelineConfig
	Output    string
}

// modes maps lw's color setting to terminal.New's argument: auto follows the
// terminal and NO_COLOR, always the terminal alone
var modes = map[string][]terminal.ColorMode{
	"always": {terminal.DetectColorMode()},
	"never":  {terminal.ColorModeNone},
}

// Run composes c on the terminal until the user leaves; an empty c opens the
// preset menu. color is lw's color setting.
func Run(c *compose.Composition, color string) (Result, error) {
	t := terminal.New(modes[color]...)
	if err := t.Init(); err != nil {
		return Result{}, err
	}
	defer t.Fini()
	if err := t.SetPasteMode(true); err != nil {
		return Result{}, err
	}
	a := newApp(c, looks[t.ColorMode()], fontFor(terminal.DetectColorMode()))
	w, h := t.Size()
	for !a.done {
		cells := make([]terminal.Cell, w*h)
		a.paint(cells, w, h)
		t.Flush(cells, w, h)
		switch ev := t.PollEvent(); ev.Type {
		case terminal.EventResize:
			w, h = ev.Width, ev.Height
		case terminal.EventClosed:
			return Result{}, errors.New("the terminal closed")
		default:
			a.handle(ev)
		}
	}
	return a.result, nil
}

// columns are a pipeline's parts, left to right
var columns = []struct{ title, role string }{{"SOURCES", "source"}, {"FLOW", "flow"}, {"SINKS", "sink"}}

const (
	sourcesCol = iota
	flowCol
	sinksCol
)

// app is the screen's state. draw and handle never touch the terminal, so
// tests drive them directly.
type app struct {
	comp    *compose.Composition
	look    look
	th      ui.Theme
	font    font
	tables  map[string][]config.Key
	pi      int    // the pipeline shown
	col     int    // the chosen column
	row     [3]int // the chosen node of each column
	scroll  int    // the canvas's first row
	inspect bool   // keys go to the inspector
	insp    inspector
	dialog  dialog // takes every key while open
	status  string // the last edit's refusal
	note    string // what the last action did
	problem error  // the composition's first problem
	changed bool
	done    bool
	result  Result
}

func newApp(c *compose.Composition, l look, f font) *app {
	a := &app{comp: c, look: l, th: l.Theme, font: f, tables: compose.NewSchema().Tables}
	a.th.Glyphs = f.Glyphs
	a.insp.open = map[string]bool{}
	if len(c.Pipelines) == 0 {
		a.dialog = a.presetMenu()
	}
	a.check()
	return a
}

func (a *app) pipeline() *config.PipelineConfig { return &a.comp.Pipelines[a.pi] }

// nodes are a column's nodes: sources and sinks by id, the flow's stages by key
func (a *app) nodes(col int) []compose.Node {
	if len(a.comp.Pipelines) == 0 {
		return nil
	}
	var out []compose.Node
	p := a.pipeline()
	switch col {
	case sourcesCol:
		for _, s := range p.PluginSources {
			out = append(out, compose.Node{Role: "source", ID: s.ID})
		}
	case flowCol:
		for _, s := range config.FlowStages() {
			out = append(out, compose.Node{Role: s.Key})
		}
	case sinksCol:
		for _, s := range p.PluginSinks {
			out = append(out, compose.Node{Role: "sink", ID: s.ID})
		}
	}
	return out
}

// node is the chosen node, false in an empty column
func (a *app) node() (compose.Node, bool) {
	nodes := a.nodes(a.col)
	if len(nodes) == 0 {
		a.row[a.col] = 0
		return compose.Node{}, false
	}
	a.row[a.col] = max(0, min(a.row[a.col], len(nodes)-1))
	return nodes[a.row[a.col]], true
}

// plugin is a source's or sink's catalogue row and options
func (a *app) plugin(n compose.Node) (config.Plugin, bool) {
	p := a.pipeline()
	typ := ""
	for _, s := range p.PluginSources {
		if n.Role == "source" && s.ID == n.ID {
			typ = s.Type
		}
	}
	for _, s := range p.PluginSinks {
		if n.Role == "sink" && s.ID == n.ID {
			typ = s.Type
		}
	}
	return config.LookupPlugin(n.Role, typ)
}

// keys are the options a node takes: a plugin's of its side, a stage's
func (a *app) keys(n compose.Node) []config.Key {
	if p, ok := a.plugin(n); ok {
		return sided(p.Keys(), p.Side)
	}
	for _, s := range config.FlowStages() {
		if s.Key == n.Role {
			return s.Keys
		}
	}
	return nil
}

// sided drops the keys of the other network side
func sided(keys []config.Key, side config.Side) []config.Key {
	name := map[config.Side]string{config.Listener: "listener", config.ChainListener: "listener", config.Dialer: "dialer"}[side]
	var out []config.Key
	for _, k := range keys {
		if k.Side == "" || k.Side == name {
			out = append(out, k)
		}
	}
	return out
}

// edit applies one engine edit: a refusal is the status, a change revalidates
func (a *app) edit(err error) bool {
	if err != nil {
		a.status = err.Error()
		return false
	}
	a.status, a.note, a.changed = "", "", true
	a.check()
	return true
}

func (a *app) check() { a.problem = a.comp.Validate() }

// handle routes an event: an open dialog takes all, then the inspector, then
// the canvas
func (a *app) handle(ev terminal.Event) {
	if ev.Type == terminal.EventKey || ev.Type == terminal.EventPaste {
		a.status, a.note = "", ""
	}
	switch {
	case a.dialog != nil:
		a.dialog.handle(a, ev)
	case ev.Type == terminal.EventPaste && a.insp.field != nil:
		a.insp.field.Paste(ev.Text)
	case ev.Type == terminal.EventPaste:
		a.paste(ev.Text)
	case ev.Type != terminal.EventKey:
	case !a.inspect:
		a.canvasKey(ev)
	case !a.inspectKey(ev):
		a.globalKey(ev)
	}
}

// is reports whether ev is a key or one of the runes
func is(ev terminal.Event, key terminal.Key, runes string) bool {
	return ev.Key == key && key != terminal.KeyNone || ev.Key == terminal.KeyRune && strings.ContainsRune(runes, ev.Rune)
}

func (a *app) canvasKey(ev terminal.Event) {
	n, ok := a.node()
	switch {
	case is(ev, terminal.KeyLeft, "h"):
		a.col = max(0, a.col-1)
	case is(ev, terminal.KeyRight, "l"):
		a.col = min(2, a.col+1)
	case is(ev, terminal.KeyTab, ""):
		a.col = (a.col + 1) % 3
	case is(ev, terminal.KeyUp, "k"):
		a.row[a.col] = max(0, a.row[a.col]-1)
	case is(ev, terminal.KeyDown, "j"):
		a.row[a.col]++
		a.node()
	case is(ev, terminal.KeyEnter, "") && ok:
		a.inspect, a.insp.cursor = true, 0
	case is(ev, terminal.KeyNone, "a"):
		a.dialog = a.addMenu()
	case is(ev, terminal.KeyNone, "d") && ok && n.Role == "filters":
		a.note = "choose a filter with " + a.font.enter + " to delete it"
	case is(ev, terminal.KeyNone, "d") && ok:
		a.edit(a.comp.Remove(a.pi, n))
	case is(ev, terminal.KeySpace, " ") && ok:
		a.switchStage(n)
	case is(ev, terminal.KeyNone, "JK"):
		a.note = "J and K move a filter: " + a.font.enter + " on filters, then on one"
	default:
		a.globalKey(ev)
	}
}

// globalKey takes the keys that work outside a text field anywhere
func (a *app) globalKey(ev terminal.Event) {
	switch n := len(a.comp.Pipelines); {
	case is(ev, terminal.KeyNone, "p"):
		a.dialog = a.presetMenu()
	case is(ev, terminal.KeyNone, "o"):
		a.dialog = a.outputMenu()
	case is(ev, terminal.KeyNone, "?"):
		a.dialog = help(a.font)
	case is(ev, terminal.KeyNone, "c"):
		a.showProblem()
	case is(ev, terminal.KeyNone, "]") && n > 0:
		a.pi, a.row, a.inspect = (a.pi+1)%n, [3]int{}, false
	case is(ev, terminal.KeyNone, "[") && n > 0:
		a.pi, a.row, a.inspect = (a.pi+n-1)%n, [3]int{}, false
	case is(ev, terminal.KeyCtrlC, "q"):
		a.quit()
	}
}

// switchStage turns a flow stage on with its defaults, or off; a stage with
// an enabled key switches that
func (a *app) switchStage(n compose.Node) {
	if n.Role == "source" || n.Role == "sink" || n.Role == "filters" {
		return
	}
	opts, on, err := a.comp.Options(a.pi, n)
	switch _, has := opts["enabled"]; {
	case err != nil:
		a.edit(err)
	case slicesHasKey(a.keys(n), "enabled"):
		a.edit(a.comp.Set(a.pi, n, "enabled", fmt.Sprint(!on || !has)))
	case on:
		a.edit(a.comp.Remove(a.pi, n))
	default:
		a.edit(a.comp.Unset(a.pi, n, a.keys(n)[0].Name))
	}
}

func slicesHasKey(keys []config.Key, name string) bool {
	for _, k := range keys {
		if k.Name == name {
			return true
		}
	}
	return false
}

// paste starts over from a pasted command line
func (a *app) paste(text string) {
	c, err := compose.FromCommandLine(text, config.HostIsDir)
	if err != nil {
		a.status = "paste: " + err.Error()
		return
	}
	replace := func(a *app) {
		a.comp, a.pi, a.row, a.inspect, a.changed = c, 0, [3]int{}, false, true
		a.note = fmt.Sprintf("pasted %d pipeline(s)", len(c.Pipelines))
		a.check()
	}
	if !a.changed {
		replace(a)
		return
	}
	a.dialog = &confirm{question: "Replace the pipelines with the pasted command line?", yes: replace}
}

func (a *app) quit() {
	if !a.changed {
		a.done = true
		return
	}
	a.dialog = &confirm{question: "Quit without running or printing the pipelines?", yes: func(a *app) { a.done = true }}
}

// showProblem chooses the part the first problem names and shows it whole
func (a *app) showProblem() {
	if a.problem == nil {
		a.note = "the pipelines are valid"
		return
	}
	if pi, n, key, ok := locate(a.problem); ok && pi < len(a.comp.Pipelines) {
		a.pi = pi
		a.choose(n)
		a.inspect = true
		a.insp.cursor = 0
		for i, l := range a.lines() {
			if l.node == n && l.key.Name == key {
				a.insp.cursor = i
			}
		}
	}
	a.dialog = &notice{title: "Problem", lines: ui.WrapText(a.problem.Error(), 60)}
}

// choose puts the canvas cursor on a node, a filter on the filters stage
func (a *app) choose(n compose.Node) {
	if n.Role == "filters" {
		a.insp.open[a.foldKey(compose.Node{Role: "filters"}, fmt.Sprint(n.Index))] = true
		n = compose.Node{Role: "filters"}
	}
	for col := range columns {
		for i, m := range a.nodes(col) {
			if m == n {
				a.col, a.row[col] = col, i
			}
		}
	}
}

// draw draws the screen: a title row, the canvas with the inspector beside
// it from 110 columns or below it, a status row, and any dialog over them
func (a *app) draw(r ui.Region) {
	r.FillStyle(a.th.Text)
	if len(a.comp.Pipelines) > 0 {
		a.pi = min(a.pi, len(a.comp.Pipelines)-1)
		a.node() // a delete can leave the row past its column's end
		p := a.pipeline()
		title := fmt.Sprintf("LogWisp  pipeline %s  %d of %d", p.Name, a.pi+1, len(a.comp.Pipelines))
		r.TextStyled(1, 0, ui.Truncate(title, r.W-2), a.th.Accent)
		body := r.Sub(0, 1, r.W, r.H-2)
		if r.W >= 110 {
			iw := min(60, r.W*2/5)
			a.drawCanvas(body.Sub(0, 0, r.W-iw-1, body.H))
			a.drawInspector(body.Sub(r.W-iw, 0, iw, body.H))
		} else {
			ch := min(a.layout(r.W).h, body.H-min(10, body.H/2))
			a.drawCanvas(body.Sub(0, 0, r.W, ch))
			a.drawInspector(body.Sub(0, ch+1, r.W, body.H-ch-1))
		}
	}
	a.drawStatus(r.Sub(0, r.H-1, r.W, 1))
	if a.dialog != nil {
		a.dialog.draw(a, r)
	}
}

// paint draws the screen into cells, each rune one the font's terminal shows
func (a *app) paint(cells []terminal.Cell, w, h int) {
	a.draw(ui.NewRegion(cells, w, 0, 0, w, h))
	for i, c := range cells {
		cells[i].Rune = a.font.fold(c.Rune)
	}
}

// drawStatus shows an edit's refusal, a note, or whether the pipelines are
// valid, and the keys
func (a *app) drawStatus(r ui.Region) {
	th, f := a.th, a.font
	text, style := f.valid+" valid", th.Accent
	switch {
	case a.status != "":
		text, style = a.status, th.Error
	case a.note != "":
		text, style = a.note, th.Muted
	case a.problem != nil:
		text, style = f.invalid+" "+a.problem.Error(), th.Error
	}
	keys := "a add  d delete  " + f.space + " on/off  J/K move  p preset  o output  ? help"
	if ui.RuneLen(keys)+24 > r.W {
		keys = "? help"
	}
	r.TextStyled(1, 0, ui.Truncate(text, r.W-ui.RuneLen(keys)-4), style)
	r.TextStyled(r.W-ui.RuneLen(keys)-1, 0, keys, th.Muted)
}
