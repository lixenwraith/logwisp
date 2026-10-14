// Package tui is lw --tui: pipelines composed on a full-screen canvas drawn as
// the website draws them, run in place with a live view of what their stages
// pass and drop, then left to run or written as a command line, environment
// or file. The pipelines are a compose.Composition; this package draws them,
// turns keys into the engine's edits and runs them through a Runner from cmd/lw.
package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

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
// preset menu. color is lw's color setting; runner runs the pipelines on t,
// and nothing runs once Run returns.
func Run(c *compose.Composition, color string, runner Runner) (Result, error) {
	t := terminal.New(modes[color]...)
	if err := t.Init(); err != nil {
		return Result{}, err
	}
	defer t.Fini()
	if err := t.SetPasteMode(true); err != nil {
		return Result{}, err
	}
	a := newApp(c, looks[t.ColorMode()], fontFor(terminal.DetectColorMode()))
	a.live = newRun(runner, func() { t.PostEvent(terminal.Event{Type: terminal.EventKey, Key: terminal.KeyNone}) })
	defer a.live.close()
	defer a.live.onSignals()()
	if runner != nil {
		go a.live.watch(time.Second)
	}
	w, h := t.Size()
	cells := make([]terminal.Cell, w*h)
	for !a.done {
		a.paint(cells, w, h)
		t.Flush(cells, w, h)
		switch ev := t.PollEvent(); ev.Type {
		case terminal.EventResize:
			w, h = ev.Width, ev.Height
			cells = make([]terminal.Cell, w*h)
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
	pi      int               // the pipeline shown
	col     int               // the chosen column
	row     [3]int            // the chosen node of each column
	scroll  ui.ViewportScroll // the canvas's rows
	bar     bool              // keys go to the pipeline bar
	inspect bool              // keys go to the inspector
	insp    inspector
	dialog  dialog // takes every key while open
	live    *run   // what t runs
	view    view   // what runs shows
	viewing bool   // keys go to the view
	status  string // the last edit's refusal
	note    string // what the last action did
	problem error  // the composition's problems, joined
	changed bool
	done    bool
	result  Result
}

func newApp(c *compose.Composition, l look, f font) *app {
	a := &app{comp: c, look: l, th: l.Theme, font: f, live: newRun(nil, func() {})}
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

// keys are the options a node takes: a plugin's, a stage's
func (a *app) keys(n compose.Node) []config.Key {
	if p, ok := a.plugin(n); ok {
		return p.Keys()
	}
	for _, s := range config.FlowStages() {
		if s.Key == n.Role {
			return s.Keys
		}
	}
	return nil
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

// handle routes an event: the tick first, which the input never sends (the
// terminal library swallows unknown keys), then an open dialog takes all,
// then the view, the inspector, the canvas; leaving, nothing more is taken
func (a *app) handle(ev terminal.Event) {
	switch {
	case ev.Type == terminal.EventKey && ev.Key == terminal.KeyNone:
		a.tick()
		return
	case a.live.leaving:
		return
	case ev.Type == terminal.EventKey || ev.Type == terminal.EventPaste:
		a.status, a.note = "", ""
	}
	if a.dialog == nil && !a.viewing {
		a.view.own = false // a key on the diagram gives the point back to its cursor
	}
	switch {
	case a.dialog != nil:
		a.dialog.handle(a, ev)
	case a.viewing:
		a.viewKey(ev)
	case ev.Type == terminal.EventPaste && a.insp.field != nil:
		a.insp.field.Paste(ev.Text)
	case ev.Type == terminal.EventPaste:
		a.paste(ev.Text)
	case ev.Type != terminal.EventKey:
	case a.bar:
		a.barKey(ev)
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
	case is(ev, terminal.KeyUp, "k") && a.row[a.col] == 0:
		a.bar = true
	case is(ev, terminal.KeyUp, "k"):
		a.row[a.col]--
	case is(ev, terminal.KeyDown, "j"):
		a.row[a.col]++
		a.node()
	case is(ev, terminal.KeyEnter, "") && (!ok || n.Role == "filters" && len(a.pipeline().Flow.Filters) == 0):
		a.dialog = a.addMenu() // an empty column, or no filters, as a
	case is(ev, terminal.KeyEnter, ""):
		a.inspectFirst(n)
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
		a.dialog = help(a.font, a.viewing)
	case is(ev, terminal.KeyNone, "!"):
		a.showProblem()
	case is(ev, terminal.KeyNone, "c"):
		a.changeType()
	case is(ev, terminal.KeyNone, "r"):
		a.run()
	case is(ev, terminal.KeyNone, "t"):
		a.tap()
	case is(ev, terminal.KeyNone, "]") && n > 0:
		a.pi, a.row, a.inspect = (a.pi+1)%n, [3]int{}, false
	case is(ev, terminal.KeyNone, "[") && n > 0:
		a.pi, a.row, a.inspect = (a.pi+n-1)%n, [3]int{}, false
	case is(ev, terminal.KeyCtrlC, "q"):
		a.quit()
	}
}

// barKey takes the keys on the pipeline bar: switch, add, rename, delete
func (a *app) barKey(ev terminal.Event) {
	n := len(a.comp.Pipelines)
	switch p := a.pipeline(); {
	case is(ev, terminal.KeyLeft, "h["):
		a.pi, a.row = (a.pi+n-1)%n, [3]int{}
	case is(ev, terminal.KeyRight, "l]"):
		a.pi, a.row = (a.pi+1)%n, [3]int{}
	case is(ev, terminal.KeyDown, "j") || is(ev, terminal.KeyEscape, ""):
		a.bar = false
	case is(ev, terminal.KeyNone, "a"):
		a.dialog = a.pipelineMenu("Add a pipeline", (*app).append)
	case is(ev, terminal.KeyEnter, ""):
		f := &form{title: "Rename pipeline " + p.Name, params: []config.PresetParam{{Name: "name", Required: true, Help: "a name no other pipeline has"}},
			apply: func(a *app, v map[string]string) error {
				err := a.comp.RenamePipeline(a.pi, v["name"])
				if err == nil {
					a.edit(nil)
				}
				return err
			}}
		f.fill(map[string]string{"name": p.Name})
		a.dialog = f
	case is(ev, terminal.KeyNone, "d"):
		remove := func(a *app) {
			a.edit(a.comp.RemovePipeline(a.pi))
			a.pi, a.row, a.insp.open = max(0, a.pi-1), [3]int{}, map[string]bool{} // folds are keyed by index
			if len(a.comp.Pipelines) == 0 {
				a.bar, a.dialog = false, a.presetMenu()
			}
		}
		if len(p.PluginSources)+len(p.PluginSinks) == 0 {
			remove(a)
			return
		}
		a.dialog = &confirm{question: "Delete pipeline " + p.Name + "?", yes: remove}
	default:
		a.globalKey(ev)
	}
}

// changeType offers a source or sink the other types of its role; a filter
// or the format changes type on its type row
func (a *app) changeType() {
	n, ok := a.node()
	if l := a.lines(); a.inspect && ok && len(l) > 0 {
		n = l[min(a.insp.cursor, len(l)-1)].node
	}
	switch {
	case !ok || n.Role == "filters" && !a.inspect:
		a.note = "c changes the type of a source, sink, filter or format"
	case n.Role == "source" || n.Role == "sink":
		a.dialog = a.typeMenu(n)
	case n.Role == "filters" && n.Index < len(a.pipeline().Flow.Filters), n.Role == "format":
		a.choose(n)
		a.inspectAt(func(l line) bool { return l.node == n && l.key.Name == "type" })
	default:
		a.note = "c changes the type of a source, sink, filter or format"
	}
}

// run leaves to start the pipelines, once they are valid
func (a *app) run() {
	if a.problem != nil {
		a.status = "not valid yet: ! shows the problem"
		return
	}
	a.leave(Result{Exit: Start, Pipelines: a.comp.Pipelines})
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

// paste starts over from a pasted command line, asking first when there are
// edited pipelines to lose
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
	if !a.changed || len(a.comp.Pipelines) == 0 {
		replace(a)
		return
	}
	a.dialog = &confirm{question: "Replace the pipelines with the pasted command line?", yes: replace}
}

func (a *app) quit() {
	leave := func(a *app) { a.leave(Result{}) }
	switch {
	case a.live.active():
		a.dialog = &confirm{question: "Stop the pipelines and quit?", yes: leave}
	case a.changed:
		a.dialog = &confirm{question: "Quit without running or printing the pipelines?", yes: leave}
	default:
		leave(a)
	}
}

// showProblem chooses the part the first problem names and shows them all
func (a *app) showProblem() {
	if a.problem == nil {
		a.note = "the pipelines are valid"
		return
	}
	if pi, n, key, _, ok := compose.Locate(compose.Problems(a.problem)[0]); ok && pi < len(a.comp.Pipelines) {
		a.pi = pi
		a.choose(n)
		a.inspectAt(func(l line) bool { return l.node == n && l.key.Name == key })
	}
	a.dialog = textNotice("Problem", a.problem.Error())
}

// inspectFirst opens the inspector on a node's first required key, or on a
// filter's group
func (a *app) inspectFirst(n compose.Node) {
	a.inspectAt(func(l line) bool { return l.node == n && (l.key.Required || l.key.Name == "") })
}

// inspectAt opens the inspector, which takes the keys from the bar, on the
// first line at holds for, or on its top
func (a *app) inspectAt(at func(line) bool) {
	a.inspect, a.bar = true, false
	a.insp.cursor = max(0, slices.IndexFunc(a.lines(), at))
}

// choose puts the canvas cursor on a node, a filter on the filters stage
func (a *app) choose(n compose.Node) {
	if n.Role == "filters" {
		a.insp.open[a.foldKey(n, "")] = true
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

// draw draws the screen: a title row, the diagram, a status row, and any
// dialog over them. Once something ran, the live view takes the rows under
// the diagram from 40 rows, unless the inspector below it is in use, and the
// whole screen under that while it takes the keys.
func (a *app) draw(r ui.Region) {
	r.FillStyle(a.th.Text)
	status, style := a.bottom(r.W)
	if len(a.comp.Pipelines) > 0 {
		a.pi = min(a.pi, len(a.comp.Pipelines)-1)
		a.node() // a delete can leave the row past its column's end
		a.drawBar(r.Sub(0, 0, r.W, 1))
		body, l := r.Sub(0, 1, r.W, r.H-1-len(status)), a.layout(r.W)
		a.view.sync(a.point(), a.live.tap)
		switch watched := a.viewing || a.live.tap != nil || len(a.view.rows) > 0; {
		case watched && r.H >= splitMin && (!a.inspect || l.inspector > 0):
			top := l.h
			if a.inspect {
				top = max(top, body.H/2)
			}
			top = min(top, body.H*2/3)
			a.drawDiagram(body.Sub(0, 0, r.W, top), l, false)
			a.drawView(body.Sub(0, top, r.W, body.H-top))
		case a.viewing:
			a.drawView(body)
		default:
			a.drawDiagram(body, l, true)
		}
	}
	for i, row := range status {
		r.TextStyled(1, r.H-len(status)+i, row, style)
	}
	if a.status == "" && a.note == "" && a.problem == nil {
		x := 4 + ui.RuneLen(status[0])
		r.TextStyled(x, r.H-1, a.hints(r.W-x-1), a.th.Muted)
	}
	if p := a.view.prompt; a.viewing && p != nil {
		row := r.Sub(0, r.H-1, r.W, 1)
		row.FillStyle(a.th.Text)
		row.TextStyled(1, 0, "/", a.th.Accent)
		row.Sub(3, 0, r.W-4, 1).TextInput(p, "a pattern: lower case ignores case; empty shows all", true, a.th)
	}
	if a.dialog != nil {
		a.dialog.draw(a, r)
	}
}

// drawDiagram draws the canvas with the inspector beside it from 110
// columns, else, with below, under it
func (a *app) drawDiagram(r ui.Region, l layout, below bool) {
	switch {
	case l.inspector > 0:
		a.drawCanvas(r.Sub(0, 0, l.w, r.H), l)
		a.drawInspector(r.Sub(r.W-l.inspector, 0, l.inspector, r.H))
	case !below:
		a.drawCanvas(r, l)
	default:
		ch := min(l.h, r.H-min(10, r.H/2))
		a.drawCanvas(r.Sub(0, 0, r.W, ch), l)
		a.drawInspector(r.Sub(0, ch+1, r.W, r.H-ch-1))
	}
}

// drawBar draws the title row: the pipelines by name, the one shown marked,
// or it and its place when they do not fit; with the keys, the bar's verbs
// after them
func (a *app) drawBar(r ui.Region) {
	th, f := a.th, a.font
	full, hint := r, ""
	if a.bar {
		r.TextStyled(0, 0, string(f.Focus), th.Accent)
		if r.W >= 60 {
			hint = "a add  " + f.enter + " rename  d delete"
			r = r.Sub(0, 0, r.W-ui.RuneLen(hint)-2, 1)
		}
	}
	r.TextStyled(2, 0, "LogWisp", th.Accent)
	names, w := a.comp.Pipelines, 11
	for _, p := range names {
		w += ui.RuneLen(p.Name) + 4
	}
	if w > r.W {
		names = names[a.pi : a.pi+1]
	}
	x := 11
	for _, p := range names {
		mark, style := f.Off, th.Muted
		if p.Name == a.pipeline().Name {
			mark, style = f.On, th.Text
			if a.bar {
				style = th.Text.On(th.Selected)
			}
		}
		label := ui.Truncate(string(mark)+" "+p.Name, max(0, r.W-x))
		r.TextStyled(x, 0, label, style)
		x += ui.RuneLen(label) + 2
	}
	if len(names) < len(a.comp.Pipelines) {
		place := fmt.Sprintf("%d/%d", a.pi+1, len(a.comp.Pipelines))
		r.TextStyled(x, 0, place, th.Muted)
		x += ui.RuneLen(place) + 2
	}
	if mark, style := a.runMark(); mark != "" {
		mark = ui.Truncate(mark, max(0, r.W-x))
		r.TextStyled(x, 0, mark, style)
		x += ui.RuneLen(mark) + 2
	}
	full.TextStyled(min(x+1, full.W-ui.RuneLen(hint)-1), 0, hint, th.Muted)
}

// paint draws the screen into cells, each rune one the font's terminal shows
func (a *app) paint(cells []terminal.Cell, w, h int) {
	a.draw(ui.NewRegion(cells, w, 0, 0, w, h))
	for i, c := range cells {
		cells[i].Rune = a.font.fold(c.Rune)
	}
}

// bottom is the status rows, wrapped to three at most: an edit's refusal, a
// note, the first problem by its part and how many follow, or the keys while
// all is valid
func (a *app) bottom(w int) ([]string, ui.Style) {
	th, f := a.th, a.font
	text, style := "", th.Error
	switch {
	case a.status != "":
		text = a.status
	case a.note != "":
		text, style = a.note, th.Muted
	case a.problem != nil:
		problems := compose.Problems(a.problem)
		pi, n, key, msg, _ := compose.Locate(problems[0])
		if where := a.where(pi, n, key); where != "" {
			msg = where + ": " + msg
		}
		if len(problems) > 1 {
			msg += fmt.Sprintf(" (%d more: ! shows them)", len(problems)-1)
		}
		text = f.invalid + " " + msg
	default:
		return []string{f.valid + " valid"}, th.Accent
	}
	return clip(ui.WrapText(text, w-2), 3), style
}

// hints are the status row's keys in w columns, the view's while it takes
// them, shown after the status while nothing else needs the row
func (a *app) hints(w int) string {
	keys := "a add  d delete  " + a.font.space + " on/off  t tap  p preset  o output  ? help"
	if a.viewing {
		keys = "/ filter  0-5 level  v mode  s point  " + a.font.enter + " detail  t back  ? help"
	}
	if ui.RuneLen(keys) > w {
		keys = "? help"
	}
	return keys
}

// clip keeps n lines, the last cut short when more follow
func clip(lines []string, n int) []string {
	if len(lines) > n {
		if n < 1 {
			return nil
		}
		lines = lines[:n]
		lines[n-1] = ui.Truncate(lines[n-1]+"…", ui.RuneLen(lines[n-1]))
	}
	return lines
}
