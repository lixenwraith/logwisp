package tui

import (
	"fmt"
	"strings"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// dialog is a box over the screen that takes every event while open
type dialog interface {
	draw(a *app, r ui.Region)
	handle(a *app, ev terminal.Event)
}

// frame draws a dialog's box around an inside w by h, centered in r and
// clipped to it, with its title, and returns the inside; sized to what it
// holds, it ends on its last line
func (a *app) frame(r ui.Region, w, h int, title string) ui.Region {
	return ui.Center(r, min(w+4, r.W), min(h+2, r.H)).Frame(title, a.th)
}

// inside is a dialog's widest inside on a screen w wide; one narrower than
// stacked puts labels and keys above what they name
func inside(w int) int { return max(1, min(72, w-4)) }

const stacked = 32

// chooser picks one option from a filtered list
type chooser struct {
	title string
	list  *ui.OptionListState
	pick  func(a *app, i int)       // the option chosen, by its index in the list
	back  func(a *app)              // on Esc, after the chooser closes
	paste func(a *app, text string) // a paste, in place of filtering; nil filters
}

func (c *chooser) draw(a *app, r ui.Region) {
	w := inside(r.W)
	a.frame(r, w, c.list.Rows(w), c.title).OptionList(c.list, a.th)
}

func (c *chooser) handle(a *app, ev terminal.Event) {
	switch {
	case ev.Type == terminal.EventPaste && c.paste != nil:
		c.paste(a, ev.Text)
	case ev.Type == terminal.EventPaste:
		c.list.Paste(ev.Text)
	case ev.Type != terminal.EventKey:
	case is(ev, terminal.KeyEscape, ""):
		a.dialog = nil
		if c.back != nil {
			c.back(a)
		}
	case is(ev, terminal.KeyEnter, ""):
		if i, ok := c.list.Chosen(); ok {
			a.dialog = nil
			c.pick(a, i)
		}
	case ev.Key == terminal.KeyRune && c.list.Menu:
		if i, ok := c.list.Pick(ev.Rune); ok {
			a.dialog = nil
			c.pick(a, i)
		}
	default:
		c.list.HandleKey(ev.Key, ev.Rune, ev.Modifiers)
	}
}

// filterHints describe the filter types the flow column adds
var filterHints = map[string]string{"include": "pass only entries that match", "exclude": "drop entries that match"}

// addMenu adds to the chosen column: a source or sink from the catalogue, or
// a filter, which opens it in the inspector
func (a *app) addMenu() dialog {
	role := columns[a.col].role
	var options []ui.Option
	if role == "flow" {
		role = "filters"
		for _, typ := range []string{"include", "exclude"} {
			options = append(options, ui.Option{Name: typ, Hint: filterHints[typ]})
		}
	}
	for _, p := range config.Plugins() {
		if p.Role == role {
			options = append(options, ui.Option{Name: p.Type, Hint: p.Summary})
		}
	}
	return &chooser{title: "Add a " + strings.TrimSuffix(role, "s"), list: ui.NewOptionListState(options),
		pick: func(a *app, i int) {
			n, err := a.comp.Add(a.pi, role, options[i].Name)
			if !a.edit(err) {
				return
			}
			a.choose(n)
			a.inspectFirst(n)
		}}
}

// typeMenu changes a source's or sink's type, in its place
func (a *app) typeMenu(n compose.Node) dialog {
	p, _ := a.plugin(n)
	var options []ui.Option
	for _, q := range config.Plugins() {
		if q.Role == n.Role && q.Type != p.Type {
			options = append(options, ui.Option{Name: q.Type, Hint: q.Summary})
		}
	}
	return &chooser{title: "Change " + p.Type, list: ui.NewOptionListState(options), pick: func(a *app, i int) {
		m, err := a.comp.Retype(a.pi, n, options[i].Name)
		if a.edit(err) {
			a.choose(m)
			a.inspectFirst(m)
		}
	}}
}

// enumMenu sets an enum key to the option chosen, the cursor on its value
func (a *app) enumMenu(l line, cur any) dialog {
	var options []ui.Option
	for _, e := range l.key.Enum {
		hint := ""
		if e == l.key.Default {
			hint = "the default"
		}
		options = append(options, ui.Option{Name: e, Hint: hint})
	}
	list := ui.NewOptionListState(options)
	list.Cursor = max(0, choice(l.key, cur))
	return &chooser{title: label(l), list: list, pick: func(a *app, i int) {
		a.edit(a.comp.Set(a.pi, l.node, l.key.Name, options[i].Name))
	}}
}

// presetMenu replaces the pipeline shown from a preset, or the pipelines
// from a pasted command line; on a bare start, Esc starts empty
func (a *app) presetMenu() dialog {
	title := "Start from a preset, or paste an lw command line"
	if len(a.comp.Pipelines) > 0 {
		title = "Replace pipeline " + a.pipeline().Name + " with a preset"
	}
	menu := a.pipelineMenu(title, (*app).use)
	menu.paste = func(a *app, text string) {
		a.dialog = nil
		if a.paste(text); len(a.comp.Pipelines) == 0 {
			a.dialog = menu // refused: the status says why
		}
	}
	menu.back = func(a *app) {
		if len(a.comp.Pipelines) == 0 {
			a.use(empty())
		}
	}
	return menu
}

// pipelineMenu offers the presets and an empty pipeline, which place puts
// on screen
func (a *app) pipelineMenu(title string, place func(a *app, p config.PipelineConfig)) *chooser {
	presets := config.Presets()
	var options []ui.Option
	for _, p := range presets {
		options = append(options, ui.Option{Name: p.Name, Hint: p.Summary})
	}
	options = append(options, ui.Option{Name: "empty", Hint: "no sources or sinks: add your own"})
	menu := &chooser{title: title, list: ui.NewOptionListState(options)}
	menu.pick = func(a *app, i int) {
		if i == len(presets) {
			place(a, empty())
			return
		}
		p := presets[i]
		f := &form{title: "preset " + p.Name, summary: p.Summary, params: p.Params, back: func(a *app) { a.dialog = menu },
			apply: func(a *app, values map[string]string) error {
				c, err := compose.FromPreset(p.Name, values, config.HostIsDir)
				if err == nil {
					place(a, c.Pipelines[0])
				}
				return err
			}}
		if f.fill(nil); len(p.Params) == 0 {
			f.submit(a)
			return
		}
		a.dialog = f
	}
	return menu
}

func empty() config.PipelineConfig {
	return config.PipelineConfig{Name: "default", Flow: &config.FlowConfig{}}
}

// use puts a pipeline in place of the one shown, under its name, asking
// first when that one has sources or sinks; the first pipeline keeps its own,
// and its parts are work quit asks about
func (a *app) use(p config.PipelineConfig) {
	if len(a.comp.Pipelines) == 0 {
		a.comp.Pipelines, a.changed = []config.PipelineConfig{p}, len(p.PluginSources)+len(p.PluginSinks) > 0
		a.check()
		return
	}
	old := a.pipeline()
	p.Name = old.Name
	replace := func(a *app) {
		a.comp.Pipelines[a.pi], a.row, a.inspect, a.changed = p, [3]int{}, false, true
		a.check()
	}
	if len(old.PluginSources)+len(old.PluginSinks) == 0 {
		replace(a)
		return
	}
	a.dialog = &confirm{question: "Replace pipeline " + old.Name + "?", yes: replace}
}

// append adds a pipeline after the others, under its name or the first free
// one after it, and shows it
func (a *app) append(p config.PipelineConfig) {
	var names []string
	for _, q := range a.comp.Pipelines {
		names = append(names, q.Name)
	}
	p.Name = config.FreeID(p.Name, names)
	a.comp.Pipelines = append(a.comp.Pipelines, p)
	a.pi, a.row, a.bar, a.changed = len(a.comp.Pipelines)-1, [3]int{}, false, true
	a.check()
}

// form takes a few keys, their defaults as placeholders, then applies them;
// a refusal stays in the form
type form struct {
	title, summary string
	params         []config.PresetParam
	fields         []*ui.TextFieldState
	focus          ui.Focus
	scroll         ui.ViewportScroll // the fields' rows
	err            string
	apply          func(a *app, values map[string]string) error
	back           func(a *app) // on Esc, after the form closes
}

// fill gives the fields their first values
func (f *form) fill(values map[string]string) {
	f.focus, f.fields = ui.Focus{Len: len(f.params)}, nil
	for _, p := range f.params {
		f.fields = append(f.fields, ui.NewTextFieldState(values[p.Name]))
	}
}

// draw lays the form out at the screen's width: the summary, the fields,
// their labels beside them or, when stacked, above, then the focused
// field's help or the refusal, in rows kept for the longest of them
func (f *form) draw(a *app, r ui.Region) {
	th, w := a.th, inside(r.W)
	labelW, tall := 0, 2
	if w >= stacked {
		for _, p := range f.params {
			labelW = max(labelW, ui.RuneLen(p.Name)+2)
		}
		tall = 1
	}
	summary, noteRows := wrap(f.summary, w, 2), len(wrap(f.err, w, 3))
	for _, p := range f.params {
		noteRows = max(noteRows, len(wrap(p.Help, w, 3)))
	}
	top, bottom := len(summary)+min(1, len(summary)), noteRows+min(1, noteRows)
	in := a.frame(r, w, top+len(f.fields)*tall+bottom, f.title)
	for i, l := range summary {
		in.TextStyled(0, i, l, th.Muted)
	}
	view := in.Sub(0, top, in.W, max(1, in.H-top-bottom))
	f.scroll.SetDimensions(len(f.fields)*tall, view.H)
	f.scroll.EnsureRange(f.focus.Index*tall, tall)
	view.Window(len(f.fields)*tall, &f.scroll, th.Text, func(all ui.Region) {
		for i, p := range f.params {
			v, _ := all.Field(i*tall, labelW, ui.Field{Label: p.Name, Required: p.Required}, i == f.focus.Index, th)
			v.TextInput(f.fields[i], p.Default, i == f.focus.Index, th)
		}
	})
	note, style := f.params[f.focus.Index].Help, th.Muted
	if f.err != "" {
		note, style = f.err, th.Error
	}
	lines := wrap(note, in.W, noteRows) // on the last rows, the box ending on text
	for i, l := range lines {
		in.TextStyled(0, in.H-len(lines)+i, l, style)
	}
}

// wrap is s wrapped to w, at most n lines, the last cut with '…'; none when
// s is empty
func wrap(s string, w, n int) []string {
	if s == "" {
		return nil
	}
	return clip(ui.WrapText(s, w), n)
}

func (f *form) handle(a *app, ev terminal.Event) {
	field := f.fields[f.focus.Index]
	switch {
	case ev.Type == terminal.EventPaste:
		field.Paste(ev.Text)
	case ev.Type != terminal.EventKey:
	case is(ev, terminal.KeyEscape, ""):
		a.dialog = nil
		if f.back != nil {
			f.back(a)
		}
	case is(ev, terminal.KeyEnter, ""):
		f.submit(a)
	case is(ev, terminal.KeyUp, ""):
		f.focus.Index = max(0, f.focus.Index-1)
	case is(ev, terminal.KeyDown, ""):
		f.focus.Index = min(f.focus.Len-1, f.focus.Index+1)
	case f.focus.HandleKey(ev.Key, ev.Modifiers):
	default:
		field.HandleKey(ev.Key, ev.Rune, ev.Modifiers)
	}
}

// submit applies the values typed, closing the form unless they are refused
func (f *form) submit(a *app) {
	values := map[string]string{}
	for i, p := range f.params {
		if v := f.fields[i].Value(); v != "" {
			values[p.Name] = v
		}
	}
	a.dialog = nil
	if err := f.apply(a, values); err != nil {
		f.err, a.dialog = err.Error(), f
	}
}

// outputMenu is what o offers: run, or print one of the forms
func (a *app) outputMenu() dialog {
	forms := compose.Forms()
	options := []ui.Option{{Name: "run", Key: 'r', Hint: "start the pipelines now, with lw's other settings"}}
	for _, f := range forms {
		options = append(options, ui.Option{Name: f.Name, Key: rune(f.Name[0]), Hint: "print " + f.Hint})
	}
	list := ui.NewOptionListState(options)
	list.Menu = true
	return &chooser{title: "Output, once the screen closes", list: list,
		pick: func(a *app, i int) {
			if i == 0 {
				a.run()
				return
			}
			text, err := forms[i-1].Write(a.comp)
			if err != nil {
				a.status = err.Error()
				return
			}
			a.result, a.done = Result{Exit: Print, Output: text}, true
		}}
}

// notice shows text, wrapped to the screen, until a key other than one
// that scrolls it
type notice struct {
	title string
	body  func(w int) []string // the lines at a width
	view  ui.ViewportScroll
}

// textNotice is a notice of plain text, its paragraphs split at '\n'
func textNotice(title, body string) *notice {
	return &notice{title: title, body: func(w int) []string { return ui.WrapText(body, w) }}
}

func (n *notice) draw(a *app, r ui.Region) {
	lines, w := n.body(inside(r.W)), ui.RuneLen(n.title)+2
	for _, l := range lines {
		w = max(w, ui.RuneLen(l))
	}
	in := a.frame(r, min(w, inside(r.W)), len(lines), n.title)
	rows := in.H
	if len(lines) > in.H { // the last row says where the view is
		rows = max(1, in.H-1)
	}
	n.view.SetDimensions(len(lines), rows)
	for y := range min(rows, len(lines)-n.view.Offset) {
		in.TextStyled(0, y, lines[n.view.Offset+y], a.th.Text)
	}
	if rows < in.H {
		where := fmt.Sprintf("j k: %d-%d of %d", n.view.Offset+1, n.view.Offset+rows, len(lines))
		in.TextStyled(0, rows, ui.Truncate(where, in.W), a.th.Muted)
	}
}

func (n *notice) handle(a *app, ev terminal.Event) {
	switch {
	case ev.Type != terminal.EventKey:
	case is(ev, terminal.KeyUp, "k"):
		n.view.ScrollBy(-1)
	case is(ev, terminal.KeyDown, "j"):
		n.view.ScrollBy(1)
	case is(ev, terminal.KeyPageUp, ""):
		n.view.PageUp()
	case is(ev, terminal.KeyPageDown, ""):
		n.view.PageDown()
	default:
		a.dialog = nil
	}
}

// confirm asks a yes or no question: y or n answers, as does Enter on the
// answer the arrows chose; Esc is no
type confirm struct {
	question string
	yes      func(a *app)
	state    ui.ConfirmState
}

func (c *confirm) draw(a *app, r ui.Region) {
	lines := ui.WrapText(c.question, inside(r.W))
	w := 12 // the answers
	for _, l := range lines {
		w = max(w, ui.RuneLen(l))
	}
	in := a.frame(r, w, len(lines)+1, "Confirm")
	for i, l := range lines {
		in.TextStyled(0, i, l, a.th.Text)
	}
	in.Radio(0, in.H-1, []string{"yes", "no"}, map[bool]int{true: 0, false: 1}[c.state.FocusYes], a.th)
}

func (c *confirm) handle(a *app, ev terminal.Event) {
	if ev.Type != terminal.EventKey || !c.state.HandleKey(ev.Key, ev.Rune) {
		return
	}
	if a.dialog = nil; c.state.Result == ui.ConfirmYes {
		c.yes(a)
	}
}

// help lists the keys, each beside its description or, narrow, above it
func help(f font) dialog {
	keys := [][2]string{
		{"arrows, hjkl", "move; up from the top row to the pipeline bar"},
		{f.enter, "inspect a part; edit a value; open a list; add"},
		{"tab", "next value"},
		{"esc", "back"},
		{"a", "add a source, sink or filter; on the bar, a pipeline"},
		{"c", "change a source's or sink's type"},
		{"d", "delete it; a value back to its default"},
		{f.space, "a flow stage or a switch on or off"},
		{"J K", "move a filter down or up"},
		{"[ ]", "previous or next pipeline"},
		{"p", "start over from a preset"},
		{"r", "run the pipelines"},
		{"o", "run, or print a command line, environment or file"},
		{"!", "the first problem"},
		{"paste", "an lw command line replaces the pipelines"},
		{"q", "quit"},
	}
	return &notice{title: "Keys", body: func(w int) []string {
		var lines []string
		for _, k := range keys {
			if w < stacked {
				lines = append(lines, k[0])
				for _, l := range ui.WrapText(k[1], w-2) {
					lines = append(lines, "  "+l)
				}
				continue
			}
			key := k[0]
			for _, l := range ui.WrapText(k[1], w-14) {
				lines, key = append(lines, ui.PadRight(key, 14)+l), ""
			}
		}
		return lines
	}}
}
