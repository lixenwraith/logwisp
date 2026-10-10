package tui

import (
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

// frame draws a dialog's box, w by h at most, centered in r with its title,
// and returns the inside
func (a *app) frame(r ui.Region, w, h int, title string) ui.Region {
	b := ui.Center(r, min(w, r.W), min(h, r.H))
	b.FillStyle(a.th.Text)
	wire := a.font.wire
	across := strings.Repeat(string(wire[10]), max(0, b.W-2))
	b.TextStyled(0, 0, string(wire[6])+across+string(wire[12]), a.th.Border)
	b.TextStyled(0, b.H-1, string(wire[3])+across+string(wire[9]), a.th.Border)
	for y := 1; y < b.H-1; y++ {
		b.TextStyled(0, y, string(wire[5]), a.th.Border)
		b.TextStyled(b.W-1, y, string(wire[5]), a.th.Border)
	}
	b.TextStyled(2, 0, " "+ui.Truncate(title, b.W-6)+" ", a.th.Accent)
	return b.Sub(2, 1, b.W-4, b.H-2)
}

// chooser picks one option from a filtered list
type chooser struct {
	title string
	list  *ui.OptionListState
	pick  func(a *app, i int)       // the option chosen, by its index in the list
	back  func(a *app)              // on Esc, after the chooser closes
	paste func(a *app, text string) // a paste, in place of filtering; nil filters
}

func (c *chooser) draw(a *app, r ui.Region) {
	in := a.frame(r, 76, len(c.list.Options)+4, c.title)
	in.OptionList(c.list, a.th)
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
			a.inspect, a.insp.cursor = true, 0
			for j, l := range a.lines() {
				if l.group != "" && l.node == n {
					a.insp.cursor = j
				}
			}
		}}
}

// presetMenu starts the pipeline over from a preset, or the pipelines from a
// pasted command line; on a bare start, Esc starts empty
func (a *app) presetMenu() dialog {
	presets := config.Presets()
	var options []ui.Option
	for _, p := range presets {
		options = append(options, ui.Option{Name: p.Name, Hint: p.Summary})
	}
	options = append(options, ui.Option{Name: "empty", Hint: "no sources or sinks: add your own"})
	title := "Start from a preset, or paste an lw command line"
	if len(a.comp.Pipelines) > 0 {
		title = "Replace pipeline " + a.pipeline().Name + " with a preset"
	}
	empty := func(a *app) {
		a.use(config.PipelineConfig{Name: "default", Flow: &config.FlowConfig{}})
	}
	menu := &chooser{title: title, list: ui.NewOptionListState(options)}
	menu.paste = func(a *app, text string) {
		a.dialog = nil
		if a.paste(text); len(a.comp.Pipelines) == 0 {
			a.dialog = menu // refused: the status says why
		}
	}
	menu.pick = func(a *app, i int) {
		switch {
		case i == len(presets):
			empty(a)
		case len(presets[i].Params) == 0:
			(&presetForm{preset: presets[i]}).apply(a)
		default:
			a.dialog = newPresetForm(presets[i])
		}
	}
	menu.back = func(a *app) {
		if len(a.comp.Pipelines) == 0 {
			empty(a)
		}
	}
	return menu
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

// presetForm takes a preset's keys, its defaults as placeholders
type presetForm struct {
	preset config.Preset
	fields []*ui.TextFieldState
	focus  ui.Focus
	scroll int // the first field shown
	err    string
}

func newPresetForm(p config.Preset) *presetForm {
	f := &presetForm{preset: p, focus: ui.Focus{Len: len(p.Params)}}
	for range p.Params {
		f.fields = append(f.fields, ui.NewTextFieldState(""))
	}
	return f
}

func (f *presetForm) draw(a *app, r ui.Region) {
	th := a.th
	in := a.frame(r, 76, len(f.fields)+6, "preset "+f.preset.Name)
	in.TextStyled(0, 0, ui.Truncate(f.preset.Summary, in.W), th.Muted)
	rows := max(1, in.H-3) // between the summary and the note
	f.scroll = max(0, min(f.scroll, f.focus.Index, len(f.fields)-rows), f.focus.Index-rows+1)
	for i := f.scroll; i < len(f.fields) && i-f.scroll < rows; i++ {
		p := f.preset.Params[i]
		v, _ := in.Field(2+i-f.scroll, 14, ui.Field{Label: p.Name, Required: p.Required}, i == f.focus.Index, th)
		v.TextInput(f.fields[i], p.Default, i == f.focus.Index, th)
	}
	note, style := f.preset.Params[f.focus.Index].Help, th.Muted
	if f.err != "" {
		note, style = f.err, th.Error
	}
	in.TextStyled(0, in.H-1, ui.Truncate(note, in.W), style)
}

func (f *presetForm) handle(a *app, ev terminal.Event) {
	field := f.fields[f.focus.Index]
	switch {
	case ev.Type == terminal.EventPaste:
		field.Paste(ev.Text)
	case ev.Type != terminal.EventKey:
	case is(ev, terminal.KeyEscape, ""):
		a.dialog = a.presetMenu()
	case is(ev, terminal.KeyEnter, ""):
		f.apply(a)
	case is(ev, terminal.KeyUp, ""):
		f.focus.Index = max(0, f.focus.Index-1)
	case is(ev, terminal.KeyDown, ""):
		f.focus.Index = min(f.focus.Len-1, f.focus.Index+1)
	case f.focus.HandleKey(ev.Key, ev.Modifiers):
	default:
		field.HandleKey(ev.Key, ev.Rune, ev.Modifiers)
	}
}

// apply builds the preset's pipeline, on this host: a path is a directory
// when one is there
func (f *presetForm) apply(a *app) {
	values := map[string]string{}
	for i, p := range f.preset.Params {
		if v := f.fields[i].Value(); v != "" {
			values[p.Name] = v
		}
	}
	c, err := compose.FromPreset(f.preset.Name, values, config.HostIsDir)
	if err != nil {
		f.err = err.Error()
		return
	}
	a.dialog = nil
	a.use(c.Pipelines[0])
}

// outputMenu is what o offers: run, or print one of the forms
func (a *app) outputMenu() dialog {
	forms := compose.Forms()
	options := []ui.Option{{Name: "run", Hint: "start the pipelines now, with lw's other settings"}}
	for _, f := range forms {
		options = append(options, ui.Option{Name: f.Name, Hint: "print " + f.Hint})
	}
	return &chooser{title: "Output, once the screen closes", list: ui.NewOptionListState(options),
		pick: func(a *app, i int) {
			if i == 0 {
				if a.problem != nil {
					a.status = "not valid yet: c shows the problem"
					return
				}
				a.result, a.done = Result{Exit: Start, Pipelines: a.comp.Pipelines}, true
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

// notice shows lines until any key
type notice struct {
	title string
	lines []string
}

func (n *notice) draw(a *app, r ui.Region) {
	w, lines := ui.RuneLen(n.title)+8, fit(n.lines, r.W)
	for _, l := range lines {
		w = max(w, ui.RuneLen(l)+6)
	}
	in := a.frame(r, w, len(lines)+4, n.title)
	for i, l := range lines {
		in.TextStyled(0, 1+i, l, a.th.Text)
	}
}

// fit wraps lines to a dialog's inside on a screen w wide
func fit(lines []string, w int) []string {
	var out []string
	for _, l := range lines {
		out = append(out, ui.WrapText(l, max(1, w-6))...)
	}
	return out
}

func (n *notice) handle(a *app, ev terminal.Event) {
	if ev.Type == terminal.EventKey {
		a.dialog = nil
	}
}

// confirm asks a yes or no question
type confirm struct {
	question string
	yes      func(a *app)
}

func (c *confirm) draw(a *app, r ui.Region) {
	lines := fit([]string{c.question}, r.W)
	w := 0
	for _, l := range lines {
		w = max(w, ui.RuneLen(l)+6)
	}
	in := a.frame(r, w, len(lines)+5, "Confirm")
	for i, l := range lines {
		in.TextStyled(0, 1+i, l, a.th.Text)
	}
	in.TextStyled(0, 1+len(lines), "y yes   n no", a.th.Muted)
}

func (c *confirm) handle(a *app, ev terminal.Event) {
	switch {
	case is(ev, terminal.KeyNone, "yY"):
		a.dialog = nil
		c.yes(a)
	case is(ev, terminal.KeyEscape, "nNq"):
		a.dialog = nil
	}
}

// help lists the keys
func help(f font) dialog {
	keys := [][2]string{
		{"arrows, hjkl", "move"},
		{f.enter, "inspect the chosen part; edit a value"},
		{"tab", "next value"},
		{"esc", "back"},
		{"a", "add a source, sink or filter"},
		{"d", "delete it; a value back to its default"},
		{f.space, "a flow stage or a switch on or off"},
		{"J K", "move a filter down or up"},
		{"[ ]", "previous or next pipeline"},
		{"p", "start over from a preset"},
		{"o", "run, or print a command line, environment or file"},
		{"c", "the first problem"},
		{"paste", "an lw command line replaces the pipelines"},
		{"q", "quit"},
	}
	n := &notice{title: "Keys"}
	for _, k := range keys {
		n.lines = append(n.lines, ui.PadRight(k[0], 14)+k[1])
	}
	return n
}
