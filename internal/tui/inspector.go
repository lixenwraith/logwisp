package tui

import (
	"cmp"
	"fmt"
	"maps"
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

// line is one inspector row: a key, a group that folds, a list's element, or
// the row that adds an element or a filter
type line struct {
	node  compose.Node
	key   config.Key // its Name is the dotted path in the node's options, "" on a filter's rows
	depth int
	group string // a group's title, "" for a value
	item  int    // a list element's index, the list's length on the row adding to it; -1 elsewhere
	add   bool   // the row that adds an element or a filter
}

// foldKey names a group's fold; a filter's folds share its prefix, path ""
// its own
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
	filters := a.pipeline().Flow.Filters
	for i, f := range filters {
		fn := compose.Node{Role: "filters", Index: i}
		out = append(out, line{node: fn, group: fmt.Sprintf("%d %s", i+1, filled(f).Type), item: -1})
		if a.insp.open[a.foldKey(fn, "")] {
			out = a.keyLines(out, fn, a.keys(n), "", 1)
		}
	}
	return append(out, line{node: compose.Node{Role: "filters", Index: len(filters)}, item: -1, add: true})
}

// filled is a filter as it runs: an unset type or logic its default
func filled(f config.FilterConfig) config.FilterConfig {
	config.Fill(&f)
	return f
}

func (a *app) keyLines(out []line, n compose.Node, keys []config.Key, prefix string, depth int) []line {
	for _, k := range keys {
		name := k.Name
		k.Name = prefix + k.Name
		switch k.Kind {
		case "table":
			out = append(out, line{node: n, key: k, depth: depth, group: name, item: -1})
			if a.insp.open[a.foldKey(n, k.Name)] {
				out = a.keyLines(out, n, k.Keys, k.Name+".", depth+1)
			}
		case "list":
			out = append(out, line{node: n, key: k, depth: depth, group: name, item: -1})
			if a.insp.open[a.foldKey(n, k.Name)] {
				items := a.items(n, k.Name)
				for i := range len(items) + 1 {
					out = append(out, line{node: n, key: k, depth: depth + 1, item: i, add: i == len(items)})
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
	if k.Zero != "" && k.Default == "" {
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
	r.Rule(0, title, hint, th)
	lines := a.lines()
	switch {
	case !ok:
		r.TextStyled(2, 2, "a adds a "+columns[a.col].role, th.Muted)
		return
	case len(lines) == 0:
		r.TextStyled(2, 2, "no options", th.Muted)
		return
	}
	a.insp.cursor = max(0, min(a.insp.cursor, len(lines)-1))
	var help []string
	style := th.Muted
	if a.inspect {
		var text string
		text, style = a.help(lines[a.insp.cursor])
		help = clip(ui.WrapText(text, r.W-4), 2)
	}
	rows := r.H - 1 - len(help)
	cols, perCol, second := 1, rows, 0
	if r.W >= 80 {
		second = split(lines, rows)
	}
	a.insp.scroll = ui.AdjustScroll(a.insp.cursor, ui.ClampScroll(a.insp.scroll, rows, len(lines)), rows, len(lines))
	if second > 0 {
		cols, perCol, a.insp.scroll = 2, max(second, len(lines)-second), 0
	}
	colW, labelW := r.W/cols, 0
	for _, l := range lines {
		labelW = max(labelW, 2*l.depth+ui.RuneLen(label(l))+2)
	}
	labelW = min(labelW, colW/2)
	for i := a.insp.scroll; i < len(lines); i++ {
		x, y := 0, i-a.insp.scroll
		if second > 0 && i >= second {
			x, y = colW, i-second
		}
		if y >= rows {
			break
		}
		a.drawLine(r.Sub(x, 1+y, colW-1, 1), lines[i], labelW, a.inspect && i == a.insp.cursor)
	}
	under := min(r.H-len(help), 2+min(perCol, len(lines)-a.insp.scroll)) // two rows under the last key
	for i, h := range help {
		r.TextStyled(2, under+i, h, style)
	}
}

// split is the first row of a second column, the shorter the taller column
// the better, 0 for one: a column holds rows at most and starts on a top row,
// not inside an unfolded group nor on the row adding to what precedes it
func split(lines []line, rows int) int {
	best, tall := 0, rows
	for i := 1; i < len(lines); i++ {
		if h := max(i, len(lines)-i); lines[i].depth == 0 && !lines[i].add && h <= tall {
			best, tall = i, h
		}
	}
	return best
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

// help is the focused row's first problem, or its key's help and what
// unset means, or what d or Enter does on a list's row
func (a *app) help(l line) (string, ui.Style) {
	for _, p := range compose.Problems(a.problem) {
		if pi, n, key, text, ok := compose.Locate(p); ok && pi == a.pi && n == l.node && key == l.key.Name {
			return text, a.th.Error
		}
	}
	help := l.key.Help
	switch d := placeholder(l.key); {
	case l.group != "" && l.key.Name == "":
		help = "J and K move this filter; c changes its type; d deletes it"
	case l.add && l.key.Name == "":
		help = "adds a filter: include passes only the entries that match, exclude drops them"
	case l.add:
		help += "; " + a.font.enter + " adds one"
	case l.item >= 0:
		help += "; d deletes it"
	case (l.key.Default != "" || l.key.Zero != "") && l.group == "": // a hint is a kind, not what unset means
		help += "; unset: " + d
	}
	return help, a.th.Muted
}

// label is a row's name: its key's last part, or a list element's number,
// which the row adding one shows while one is typed
func label(l line) string {
	if l.item >= 0 && l.key.Name != "" {
		return strconv.Itoa(l.item + 1)
	}
	return l.key.Name[strings.LastIndex(l.key.Name, ".")+1:]
}

func (a *app) drawLine(r ui.Region, l line, labelW int, focused bool) {
	th := a.th
	r = r.Sub(2*l.depth, 0, r.W-2*l.depth, 1)
	k := l.key
	typing := focused && a.insp.field != nil
	switch {
	case l.group != "":
		r.Group(0, l.group, a.groupSummary(l), a.insp.open[a.foldKey(l.node, k.Name)], focused, th)
		return
	case l.add && !typing: // where its list's labels or the filters' titles start, no number
		text, style := "+ add", th.Muted
		if k.Name == "" {
			text += " filter"
		}
		if focused {
			style = th.Text
			r.TextStyled(0, 0, string(th.Glyphs.Focus), th.Accent)
		}
		r.TextStyled(2, 0, text, style)
		return
	}
	v, _ := r.Field(0, labelW-2*l.depth, ui.Field{Label: label(l), Required: k.Required && l.item < 0}, focused, th)
	items := a.items(l.node, k.Name)
	cur := a.value(l.node, k.Name)
	switch {
	case typing:
		v.TextInput(a.insp.field, placeholder(k), true, th)
	case l.item >= 0:
		v.TextStyled(0, 0, ui.Truncate(items[l.item], v.W), th.Text)
	case len(k.Enum) > 0:
		v.Radio(0, 0, k.Enum, choice(k, cur), th)
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
		f := filled(a.pipeline().Flow.Filters[l.node.Index])
		return string(f.Logic) + "  " + strings.Join(f.Patterns, " ")
	}
	switch v := a.value(l.node, l.key.Name).(type) {
	case []any:
		return show(v)
	case map[string]any:
		var out []string
		for _, k := range l.key.Keys {
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
	enter, space := is(ev, terminal.KeyEnter, ""), is(ev, terminal.KeySpace, " ")
	left, right := is(ev, terminal.KeyLeft, "h"), is(ev, terminal.KeyRight, "l")
	switch {
	case focus.HandleKey(ev.Key, ev.Modifiers):
		a.insp.cursor = focus.Index
	case is(ev, terminal.KeyUp, "k"):
		a.insp.cursor = max(0, a.insp.cursor-1)
	case is(ev, terminal.KeyDown, "j"):
		a.insp.cursor = min(len(lines)-1, a.insp.cursor+1)
	case l.add && k.Name == "" && enter:
		a.dialog = a.addMenu()
	case l.group != "" && (enter || space || left || right):
		fold := a.foldKey(l.node, k.Name)
		a.insp.open[fold] = (enter || space) && !a.insp.open[fold] || right
	case l.group != "" && k.Name == "" && is(ev, terminal.KeyNone, "JK"):
		a.moveFilter(l.node.Index, map[rune]int{'J': 1, 'K': -1}[ev.Rune])
	case is(ev, terminal.KeyNone, "d"):
		a.clear(l)
	case len(k.Enum) > 0 && l.item < 0 && enter:
		a.dialog = a.enumMenu(l, cur)
	case len(k.Enum) > 0 && l.item < 0 && (space || left || right):
		i := choice(k, cur)
		switch next, moved := ui.StepChoice(ev.Key, ev.Rune, i, len(k.Enum)); {
		case moved:
			i = next
		case !space:
			return true // an arrow at either end
		default:
			i = (i + 1) % len(k.Enum)
		}
		a.edit(a.comp.Set(a.pi, l.node, k.Name, k.Enum[i]))
	case k.Kind == "bool" && l.item < 0 && (enter || space || left || right):
		on := cur == true || cur == nil && k.Default == "true"
		a.edit(a.comp.Set(a.pi, l.node, k.Name, strconv.FormatBool(right || !left && !on)))
	case enter:
		text := show(cmp.Or(cur, any("")))
		if l.item >= 0 {
			text = ""
			if !l.add {
				text = a.items(l.node, k.Name)[l.item]
			}
		}
		a.insp.field = ui.NewTextFieldState(text)
		a.insp.field.Accept = map[string]func(rune) bool{"integer": ui.AcceptInteger, "number": ui.AcceptNumber}[k.Kind]
	default:
		return false
	}
	return true
}

// typeKey edits the value being typed: Enter sets it, Tab and the arrows up
// and down set it and move on, Esc drops it
func (a *app) typeKey(ev terminal.Event, l line) {
	up, down := is(ev, terminal.KeyUp, ""), is(ev, terminal.KeyDown, "")
	switch {
	case is(ev, terminal.KeyEscape, ""):
		a.insp.field = nil
	case is(ev, terminal.KeyEnter, "") || is(ev, terminal.KeyTab, "") || is(ev, terminal.KeyBacktab, "") || up || down:
		value := a.insp.field.Value()
		if a.commit(l, value) {
			a.insp.field = nil
			if l.add && value != "" {
				a.insp.cursor++ // stays on the row that adds one
			}
			focus := ui.Focus{Index: a.insp.cursor, Len: len(a.lines())}
			switch {
			case up:
				a.insp.cursor = max(0, a.insp.cursor-1)
			case down:
				a.insp.cursor = min(focus.Len-1, a.insp.cursor+1)
			case focus.HandleKey(ev.Key, ev.Modifiers):
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
	case l.add && value == "":
		return true
	case l.add:
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
	case l.add:
	case l.group != "" && l.key.Name == "":
		a.edit(a.comp.Remove(a.pi, l.node))
	case l.item >= 0:
		a.commit(l, "")
	default:
		a.edit(a.comp.Unset(a.pi, l.node, l.key.Name))
	}
}

// moveFilter moves a filter by one, its folds and the cursor with it
func (a *app) moveFilter(i, by int) {
	if i+by < 0 || i+by >= len(a.pipeline().Flow.Filters) || !a.edit(a.comp.MoveFilter(a.pi, i, i+by)) {
		return // nothing moves past either end, as j and k stop there
	}
	from, to := a.foldKey(compose.Node{Role: "filters", Index: i}, ""), a.foldKey(compose.Node{Role: "filters", Index: i + by}, "")
	moved := map[string]bool{}
	for k, open := range a.insp.open {
		switch {
		case strings.HasPrefix(k, from):
			moved[to+k[len(from):]] = open
		case strings.HasPrefix(k, to):
			moved[from+k[len(to):]] = open
		default:
			continue
		}
		delete(a.insp.open, k)
	}
	maps.Copy(a.insp.open, moved)
	for j, l := range a.lines() {
		if l.group != "" && l.key.Name == "" && l.node.Index == i+by {
			a.insp.cursor = j
		}
	}
}
