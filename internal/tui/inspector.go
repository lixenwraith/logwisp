package tui

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// inspector lists the chosen node's keys a row each; tables, lists and
// filters fold
type inspector struct {
	cursor, scroll int
	open           map[string]bool    // unfolded groups, by foldKey
	field          *ui.TextFieldState // the value being typed, nil while none
}

// line is one inspector row: a key, a group that folds, or a list's element
type line struct {
	node  compose.Node
	key   config.Key // its Name is the dotted path in the node's options
	depth int
	group string // a group's title, "" for a value
	item  int    // a list element's index, the list's length on the row that adds one; -1 elsewhere
}

func (a *app) foldKey(n compose.Node, path string) string {
	return fmt.Sprintf("%d/%s/%s/%d/%s", a.pi, n.Role, n.ID, n.Index, path)
}

// lines are the chosen node's rows; the filters stage lists each filter
func (a *app) lines() []line {
	n, ok := a.node()
	if !ok {
		return nil
	}
	if n.Role != "filters" {
		return a.keyLines(nil, n, a.keys(n), "", 0)
	}
	var out []line
	for i, f := range a.pipeline().Flow.Filters {
		fn := compose.Node{Role: "filters", Index: i}
		out = append(out, line{node: fn, group: fmt.Sprintf("%d %s", i+1, f.Type), item: -1})
		if a.insp.open[a.foldKey(n, strconv.Itoa(i))] {
			out = a.keyLines(out, fn, a.keys(n), "", 1)
		}
	}
	return out
}

func (a *app) keyLines(out []line, n compose.Node, keys []config.Key, prefix string, depth int) []line {
	for _, k := range keys {
		name := k.Name
		k.Name = prefix + k.Name
		switch k.Kind {
		case "table":
			out = append(out, line{node: n, key: k, depth: depth, group: name, item: -1})
			if a.insp.open[a.foldKey(n, k.Name)] {
				p, _ := a.plugin(n)
				out = a.keyLines(out, n, sided(a.tables[name], p.Side), k.Name+".", depth+1)
			}
		case "list":
			out = append(out, line{node: n, key: k, depth: depth, group: name, item: -1})
			if a.insp.open[a.foldKey(n, k.Name)] {
				items := a.items(n, k.Name)
				for i := range len(items) + 1 {
					out = append(out, line{node: n, key: k, depth: depth + 1, item: i})
				}
			}
		default:
			out = append(out, line{node: n, key: k, depth: depth, item: -1})
		}
	}
	return out
}

// value is a key's value at its dotted path, nil while unset
func (a *app) value(n compose.Node, path string) any {
	opts, _, _ := a.comp.Options(a.pi, n)
	var v any = opts
	for _, part := range strings.Split(path, ".") {
		m, _ := v.(map[string]any)
		v = m[part]
	}
	return v
}

func (a *app) items(n compose.Node, path string) []string {
	var out []string
	list, _ := a.value(n, path).([]any)
	for _, v := range list {
		out = append(out, show(v))
	}
	return out
}

// placeholder says what an unset key means: its default, what zero means, or
// the kind of value it takes
func placeholder(k config.Key) string {
	if k.Zero != "" {
		return "(" + k.Zero + ")"
	}
	return cmp.Or(k.Default, k.Hint)
}

func (a *app) drawInspector(r ui.Region) {
	th, f := a.th, a.font
	n, ok := a.node()
	title := "nothing chosen"
	if ok {
		title = a.nodeTitle(n)
	}
	hint := f.enter + " inspect"
	if a.inspect {
		hint = f.enter + " edit  esc back"
	}
	r.TextStyled(0, 0, strings.Repeat(string(f.rule), r.W), th.Border)
	r.TextStyled(2, 0, " "+ui.Truncate(title, r.W-ui.RuneLen(hint)-10)+" ", th.Text)
	r.TextStyled(r.W-ui.RuneLen(hint)-3, 0, " "+hint+" ", th.Muted)
	lines := a.lines()
	switch {
	case !ok:
		r.TextStyled(2, 2, "a adds a "+columns[a.col].role, th.Muted)
		return
	case len(lines) == 0 && n.Role == "filters":
		r.TextStyled(2, 2, "no filters: a adds one", th.Muted)
		return
	case len(lines) == 0:
		r.TextStyled(2, 2, "no options", th.Muted)
		return
	}
	a.insp.cursor = max(0, min(a.insp.cursor, len(lines)-1))
	rows := r.H - 2
	cols, perCol := 1, rows
	if half := (len(lines) + 1) / 2; r.W >= 80 && half <= rows {
		cols, perCol = 2, half
	}
	if cols == 1 {
		a.insp.scroll = max(0, min(a.insp.scroll, a.insp.cursor, len(lines)-rows))
		a.insp.scroll = max(a.insp.scroll, a.insp.cursor-rows+1)
	} else {
		a.insp.scroll = 0
	}
	colW, labelW := r.W/cols, 0
	for _, l := range lines {
		labelW = max(labelW, 2*l.depth+ui.RuneLen(label(l))+2)
	}
	labelW = min(labelW, colW/2)
	for i := a.insp.scroll; i < len(lines) && i-a.insp.scroll < perCol*cols; i++ {
		at := i - a.insp.scroll
		row := r.Sub(at/perCol*colW, 1+at%perCol, colW-1, 1)
		a.drawLine(row, lines[i], labelW, a.inspect && i == a.insp.cursor)
	}
	if a.inspect && rows > 0 {
		help, style := a.help(lines[a.insp.cursor])
		r.TextStyled(2, r.H-1, ui.Truncate(help, r.W-4), style)
	}
}

func (a *app) nodeTitle(n compose.Node) string {
	switch n.Role {
	case "source", "sink":
		p, _ := a.plugin(n)
		return p.Type + " · " + n.Role + " · id " + n.ID
	case "filters":
		return fmt.Sprintf("filters · flow · %d", len(a.pipeline().Flow.Filters))
	}
	return n.Role + " · flow"
}

// help is the focused row's problem, or its key's help and default
func (a *app) help(l line) (string, ui.Style) {
	if a.problem != nil {
		if pi, n, key, ok := locate(a.problem); ok && pi == a.pi && n == l.node && key == l.key.Name {
			return a.problem.Error(), a.th.Error
		}
	}
	if l.group != "" && l.key.Name == "" {
		return "J and K move this filter; d deletes it", a.th.Muted
	}
	help := l.key.Help
	if d := placeholder(l.key); d != "" && l.group == "" {
		help += "; unset: " + d
	}
	return help, a.th.Muted
}

// label is a row's name: its key's last part, or a list element's number
func label(l line) string {
	if l.item >= 0 {
		return strconv.Itoa(l.item + 1)
	}
	return l.key.Name[strings.LastIndex(l.key.Name, ".")+1:]
}

func (a *app) drawLine(r ui.Region, l line, labelW int, focused bool) {
	th := a.th
	r = r.Sub(2*l.depth, 0, r.W-2*l.depth, 1)
	k := l.key
	if l.group != "" {
		open := a.insp.open[a.foldKey(l.node, k.Name)]
		if k.Name == "" {
			open = a.insp.open[a.foldKey(compose.Node{Role: "filters"}, strconv.Itoa(l.node.Index))]
		}
		r.Group(0, l.group, a.groupSummary(l), open, focused, th)
		return
	}
	v, _ := r.Field(0, labelW-2*l.depth, ui.Field{Label: label(l), Required: k.Required && l.item < 0}, focused, th)
	items := a.items(l.node, k.Name)
	cur := a.value(l.node, k.Name)
	switch {
	case focused && a.insp.field != nil:
		v.TextInput(a.insp.field, placeholder(k), true, th)
	case l.item == len(items):
		v.TextStyled(0, 0, "+ add", th.Muted)
	case l.item >= 0:
		v.TextStyled(0, 0, ui.Truncate(items[l.item], v.W), th.Text)
	case len(k.Enum) > 0:
		v.Choice(0, 0, k.Enum, choice(k, cur), th)
	case k.Kind == "bool":
		v.Toggle(0, 0, cur == true || cur == nil && k.Default == "true", th)
	case cur == nil:
		v.TextStyled(0, 0, ui.Truncate(placeholder(k), v.W), th.Muted)
	default:
		v.TextStyled(0, 0, ui.Truncate(show(cur), v.W), th.Text)
	}
}

// choice is the index of an enum key's value, or of its default while unset
func choice(k config.Key, cur any) int {
	want := cmp.Or(fmt.Sprint(cmp.Or(cur, any(""))), k.Default)
	for i, e := range k.Enum {
		if e == want {
			return i
		}
	}
	return -1
}

// groupSummary is what a folded group holds: a list's values, a table's set
// keys, a filter's logic and patterns
func (a *app) groupSummary(l line) string {
	if l.key.Name == "" {
		f := a.pipeline().Flow.Filters[l.node.Index]
		return string(f.Logic) + "  " + strings.Join(f.Patterns, " ")
	}
	switch v := a.value(l.node, l.key.Name).(type) {
	case []any:
		return show(v)
	case map[string]any:
		var out []string
		for _, k := range a.tables[l.group] {
			if s, ok := v[k.Name]; ok {
				out = append(out, k.Name+" "+show(s))
			}
		}
		return strings.Join(out, "  ")
	}
	return ""
}

// inspectKey handles a key in the inspector, false for one it leaves to
// the global keys
func (a *app) inspectKey(ev terminal.Event) bool {
	lines := a.lines()
	if a.insp.field != nil && len(lines) > 0 {
		a.typeKey(ev, lines[min(a.insp.cursor, len(lines)-1)])
		return true
	}
	if is(ev, terminal.KeyEscape, "") {
		a.inspect = false
		return true
	}
	if is(ev, terminal.KeyNone, "a") {
		a.dialog = a.addMenu()
		return true
	}
	if len(lines) == 0 {
		return false
	}
	a.insp.cursor = max(0, min(a.insp.cursor, len(lines)-1))
	l := lines[a.insp.cursor]
	k := l.key
	cur := a.value(l.node, k.Name)
	focus := ui.Focus{Index: a.insp.cursor, Len: len(lines)}
	toggle := is(ev, terminal.KeyEnter, " ") || is(ev, terminal.KeySpace, "")
	switch {
	case focus.HandleKey(ev.Key, ev.Modifiers):
		a.insp.cursor = focus.Index
	case is(ev, terminal.KeyUp, "k"):
		a.insp.cursor = max(0, a.insp.cursor-1)
	case is(ev, terminal.KeyDown, "j"):
		a.insp.cursor = min(len(lines)-1, a.insp.cursor+1)
	case l.group != "" && (toggle || is(ev, terminal.KeyRight, "l") || is(ev, terminal.KeyLeft, "h")):
		fold := a.foldKey(l.node, k.Name)
		if k.Name == "" {
			fold = a.foldKey(compose.Node{Role: "filters"}, strconv.Itoa(l.node.Index))
		}
		a.insp.open[fold] = toggle && !a.insp.open[fold] || is(ev, terminal.KeyRight, "l")
	case l.group != "" && l.key.Name == "" && is(ev, terminal.KeyNone, "JK"):
		a.moveFilter(l.node.Index, map[rune]int{'J': 1, 'K': -1}[ev.Rune])
	case is(ev, terminal.KeyNone, "d"):
		a.clear(l)
	case len(k.Enum) > 0 && l.item < 0 && (toggle || is(ev, terminal.KeyLeft, "h") || is(ev, terminal.KeyRight, "l")):
		i := choice(k, cur)
		switch next, moved := ui.StepChoice(ev.Key, ev.Rune, i, len(k.Enum)); {
		case moved:
			i = next
		case !toggle:
			return true // an arrow at either end
		default:
			i = (i + 1) % len(k.Enum)
		}
		a.edit(a.comp.Set(a.pi, l.node, k.Name, k.Enum[i]))
	case k.Kind == "bool" && l.item < 0 && toggle:
		on := cur == true || cur == nil && k.Default == "true"
		a.edit(a.comp.Set(a.pi, l.node, k.Name, strconv.FormatBool(!on)))
	case is(ev, terminal.KeyEnter, ""):
		text := show(cmp.Or(cur, any("")))
		if items := a.items(l.node, k.Name); l.item >= 0 {
			text = ""
			if l.item < len(items) {
				text = items[l.item]
			}
		}
		a.insp.field = ui.NewTextFieldState(text)
		a.insp.field.Accept = map[string]func(rune) bool{"integer": ui.AcceptInteger, "number": ui.AcceptNumber}[k.Kind]
	default:
		return false
	}
	return true
}

// typeKey edits the value being typed: Enter sets it, Tab sets it and moves
// on, Esc drops it
func (a *app) typeKey(ev terminal.Event, l line) {
	switch {
	case is(ev, terminal.KeyEscape, ""):
		a.insp.field = nil
	case is(ev, terminal.KeyEnter, "") || is(ev, terminal.KeyTab, "") || is(ev, terminal.KeyBacktab, ""):
		value := a.insp.field.Value()
		if a.commit(l, value) {
			a.insp.field = nil
			if l.item >= 0 && l.item == len(a.items(l.node, l.key.Name))-1 && value != "" {
				a.insp.cursor++ // stays on the row that adds one
			}
			focus := ui.Focus{Index: a.insp.cursor, Len: len(a.lines())}
			if focus.HandleKey(ev.Key, ev.Modifiers) {
				a.insp.cursor = focus.Index
			}
		}
	default:
		a.insp.field.HandleKey(ev.Key, ev.Rune, ev.Modifiers)
	}
}

// commit sets a typed value: empty unsets a key or drops a list element
func (a *app) commit(l line, value string) bool {
	k := l.key
	if l.item < 0 {
		if value == "" {
			return a.edit(a.comp.Unset(a.pi, l.node, k.Name))
		}
		return a.edit(a.comp.Set(a.pi, l.node, k.Name, value))
	}
	items := a.items(l.node, k.Name)
	switch {
	case l.item == len(items) && value == "":
		return true
	case l.item == len(items):
		items = append(items, value)
	case value == "":
		items = append(items[:l.item], items[l.item+1:]...)
	default:
		items[l.item] = value
	}
	if len(items) == 0 {
		return a.edit(a.comp.Unset(a.pi, l.node, k.Name))
	}
	return a.edit(a.comp.Set(a.pi, l.node, k.Name, items...))
}

// clear deletes what a row holds: a filter, a list element, or a key's
// value, which returns to its default
func (a *app) clear(l line) {
	switch {
	case l.group != "" && l.key.Name == "":
		a.edit(a.comp.Remove(a.pi, l.node))
	case l.item >= 0:
		a.commit(l, "")
	default:
		a.edit(a.comp.Unset(a.pi, l.node, l.key.Name))
	}
}

// moveFilter moves a filter by one, its fold and the cursor with it
func (a *app) moveFilter(i, by int) {
	stage := compose.Node{Role: "filters"}
	if i+by < 0 || i+by >= len(a.pipeline().Flow.Filters) || !a.edit(a.comp.MoveFilter(a.pi, i, i+by)) {
		return // nothing moves past either end, as j and k stop there
	}
	from, to := a.foldKey(stage, strconv.Itoa(i)), a.foldKey(stage, strconv.Itoa(i+by))
	a.insp.open[from], a.insp.open[to] = a.insp.open[to], a.insp.open[from]
	for j, l := range a.lines() {
		if l.group != "" && l.key.Name == "" && l.node.Index == i+by {
			a.insp.cursor = j
		}
	}
}
