package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"

	ui "github.com/lixenwraith/terminal/tui"
)

const (
	gutter    = 4   // columns of wire a side when the content does not fit
	wideMin   = 64  // the narrowest canvas with the parts side by side
	besideMin = 110 // the narrowest screen with the inspector beside the canvas
	listMax   = 4   // option rows a source or sink lists beside the inspector
)

// Widths beside the inspector: columns sized to their content within these,
// and wires taking the slack up to wireMax a side
const (
	sideMin, sideMax = 24, 40
	boxMin, boxMax   = 18, 44
	wireMax          = 16
	inspMin, inspMax = 60, 100 // the inspector beside the canvas
)

// spot is where a node draws: its first row, the columns it may use, its
// rows, the column its head's text ends at (a source's wire starts past it),
// and its text under or beside its name
type spot struct {
	x, y, w, h, end int
	text            []string
}

// layout places the screen's parts: the inspector beside the canvas from 110
// columns, below it under that; on the canvas, a pipeline's parts side by
// side with wires from 64 columns, stacked below that. Beside the inspector
// the parts take their content's widths, centred; below it, a fixed split.
type layout struct {
	wide        bool
	w, h        int // the canvas's
	inspector   int // the inspector's width beside the canvas, 0 below it
	title       [3]spot
	nodes       [3][]spot // a column's nodes, or its one empty slot
	box         spot      // the flow box's top left and width
	boxH        int
	entry, exit int // the rows wires enter and leave the flow box
	wire        int // columns between a side column and the flow box
}

// layout lays out a screen w wide; each node's text is read once, and sizes
// the columns
func (a *app) layout(w int) layout {
	l := layout{w: w}
	beside := w >= besideMin
	side, box := sideMin, boxMin
	for _, col := range []int{sourcesCol, sinksCol} {
		for _, n := range a.nodes(col) {
			p, _ := a.plugin(n)
			s := spot{end: 2 + ui.RuneLen(p.Type)}
			if beside {
				s.text = a.optionRows(n)
			} else {
				s.text = []string{a.summary(n)}
			}
			if verb := ways[p.Side]; verb != "" {
				s.end += 2 + ui.RuneLen(verb)
			}
			s.h = 1 + len(s.text)
			side = max(side, s.end+3)
			for _, t := range s.text {
				side = max(side, 3+ui.RuneLen(t))
			}
			l.nodes[col] = append(l.nodes[col], s)
		}
		if len(l.nodes[col]) == 0 {
			l.nodes[col] = []spot{{h: 2}}
		}
	}
	var stages []spot
	for _, n := range a.nodes(flowCol) {
		text := a.summary(n)
		if !a.on(n) {
			text = "off"
		}
		box = max(box, 7+ui.RuneLen(n.Role)+ui.RuneLen(text))
		stages = append(stages, spot{h: 1, text: []string{text}})
	}
	if beside {
		want := 2*min(side, sideMax) + min(box, boxMax) + 2*wireMax + 4 // with a margin
		l.inspector = max(min(inspMin, w*2/5), min(inspMax, w-want-1))
		l.w = w - l.inspector - 1
	}
	l.boxH = max(1, len(stages)) + 2
	if l.w >= wideMin {
		l.wide = true
		side, box = min(side, sideMax), min(box, boxMax)
		l.wire = min(wireMax, (l.w-2*side-box)/2)
		if !beside || l.wire < gutter {
			box = max(boxMin, min(30, (l.w-2*gutter)/3))
			side, l.wire = (l.w-box-2*gutter)/2, gutter
		}
		x0 := (l.w - 2*side - box - 2*l.wire) / 2
		xs := [3]int{x0, x0 + side + l.wire, x0 + side + 2*l.wire + box}
		ws := [3]int{side, box, side}
		for col := range columns {
			l.title[col] = spot{x: xs[col], w: ws[col]}
		}
		l.box = spot{x: xs[flowCol], y: 1, w: box}
		l.h = 1 + l.boxH
		for _, col := range []int{sourcesCol, sinksCol} {
			y := 1
			for i := range l.nodes[col] {
				s := &l.nodes[col][i]
				s.x, s.y, s.w = xs[col], y, ws[col]
				y += s.h + 1
			}
			l.h = max(l.h, y-1)
		}
		l.entry = l.box.y + 1 + (l.boxH-3)/2
		l.exit = l.entry
	} else {
		y := 0
		for col := range columns {
			l.title[col] = spot{y: y, w: l.w}
			y++
			if col == flowCol {
				l.box = spot{y: y, w: l.w}
				y += l.boxH
			} else {
				for i := range l.nodes[col] {
					s := &l.nodes[col][i]
					s.y, s.w = y, l.w
					y += s.h + 1
				}
				y--
			}
			if col != sinksCol {
				y++ // the arrow down to the next part
			}
		}
		l.h = y
	}
	for i, s := range stages {
		s.x, s.y, s.w = l.box.x+2, l.box.y+1+i, l.box.w-4
		l.nodes[flowCol] = append(l.nodes[flowCol], s)
	}
	return l
}

// drawCanvas draws the pipeline, scrolled to keep the chosen node in view
func (a *app) drawCanvas(r ui.Region, l layout) {
	chosen := l.nodes[a.col][min(a.row[a.col], len(l.nodes[a.col])-1)]
	a.scroll.SetDimensions(l.h, r.H)
	a.scroll.EnsureRange(chosen.y, chosen.h)
	r.Window(l.h, &a.scroll, a.th.Text, func(full ui.Region) { a.drawParts(full, l) })
}

func (a *app) drawParts(r ui.Region, l layout) {
	th, f := a.th, a.font
	tints := [3]ui.Style{a.look.Source, a.look.Flow, a.look.Sink}
	for col, c := range columns {
		t := l.title[col]
		r.TextStyled(t.x, t.y, string(f.dot)+" "+c.title, tints[col].On(th.Text))
	}
	a.drawBox(r, l)
	g := ui.NewWires(r.W, l.h)
	for _, col := range []int{sourcesCol, sinksCol} {
		nodes := a.nodes(col)
		for i, s := range l.nodes[col] {
			chosen := a.col == col && a.row[col] == i
			if len(nodes) == 0 {
				a.drawEmpty(r, s, columns[col].role, chosen)
				continue
			}
			head := s.w // a source's leader starts past its text, where its bar ends
			if l.wide && col == sourcesCol {
				head = min(s.w, s.end+1)
			}
			a.drawNode(r, s, head, nodes[i], tints[col], chosen)
		}
		if l.wide && len(nodes) > 0 {
			join(g, l, col)
		}
	}
	if !l.wide {
		for _, col := range []int{sourcesCol, flowCol} {
			r.TextStyled(2, l.title[col+1].y-1, string(f.down), th.Border)
		}
		return
	}
	r.DrawWires(g, f.Line, th.Border)
	if len(a.nodes(sourcesCol)) > 0 {
		r.TextStyled(l.box.x-1, l.entry, string(f.arrow), th.Border)
	}
	if len(a.nodes(sinksCol)) > 0 {
		for _, s := range l.nodes[sinksCol] {
			r.TextStyled(s.x-1, s.y, string(f.arrow), th.Border)
		}
	}
}

// join wires a column's nodes to a trunk midway along the wire, and the
// trunk to the flow box's side: a source's wire starts past its text
func join(g ui.Wires, l layout, col int) {
	ys := []int{l.entry}
	if col == sinksCol {
		ys[0] = l.exit
	}
	for _, s := range l.nodes[col] {
		ys = append(ys, s.y)
	}
	if col == sourcesCol {
		trunk := l.box.x - 1 - l.wire/2
		for _, s := range l.nodes[col] {
			g.H(s.y, s.x+min(s.end+1, s.w), trunk)
		}
		g.V(trunk, slices.Min(ys), slices.Max(ys))
		g.H(l.entry, trunk, l.box.x-1)
		return
	}
	right := l.box.x + l.box.w
	trunk := right + 1 + (l.wire-1)/2
	g.H(l.exit, right, trunk)
	g.V(trunk, slices.Min(ys), slices.Max(ys))
	for _, s := range l.nodes[col] {
		g.H(s.y, trunk, s.x-1)
	}
}

// drawNode draws a source or sink: a tinted bar, its type and whether it
// listens or dials, then its text. The chosen node is a bar across its rows,
// head wide on the first, whose tint block keeps its color; a node a problem
// names has its tint in the error style.
func (a *app) drawNode(r ui.Region, s spot, head int, n compose.Node, tint ui.Style, chosen bool) {
	th := a.th
	bg, bar := th.Text, a.font.bar
	if chosen {
		bg, bar = th.Text.On(th.Selected), a.font.barOn
	}
	if a.faulty(n) {
		tint = th.Error
	}
	p, _ := a.plugin(n)
	verb, room := ways[p.Side], s.w-3
	if verb != "" {
		room -= 2 + ui.RuneLen(verb)
	}
	for dy := range s.h {
		w := s.w
		if dy == 0 {
			w = head
		}
		row := r.Sub(s.x, s.y+dy, w, 1)
		row.FillStyle(bg)
		row.TextStyled(0, 0, string(bar), tint.On(th.Text))
		if dy > 0 {
			row.TextStyled(2, 0, ui.Truncate(s.text[dy-1], row.W-3), th.Muted.On(bg))
			continue
		}
		typ := ui.Truncate(p.Type, room)
		row.TextStyled(2, 0, typ, th.Text.On(bg))
		row.TextStyled(4+ui.RuneLen(typ), 0, verb, th.Muted.On(bg))
	}
}

// ways say whether a source or sink listens or dials, by its side
var ways = map[config.Side]string{config.Listener: "listens", config.ChainListener: "listens", config.Dialer: "dials"}

func (a *app) drawEmpty(r ui.Region, s spot, role string, chosen bool) {
	mark, style := " ", a.th.Muted
	if chosen {
		mark, style = string(a.th.Glyphs.Pointer), a.th.Muted.On(a.th.Selected)
	}
	row := r.Sub(s.x, s.y, s.w-1, 1)
	if chosen {
		row.FillStyle(a.th.Text.On(a.th.Selected))
	}
	row.TextStyled(0, 0, mark+" a adds a "+role, style)
}

// drawBox draws the flow box, its stages in the order entries pass them; a
// stage that is off is dimmed with the Off glyph
func (a *app) drawBox(r ui.Region, l layout) {
	th, f := a.th, a.font
	b := l.box
	r.Sub(b.x, b.y, b.w, l.boxH).BoxStyle(f.box, th.Border)
	for i, n := range a.nodes(flowCol) {
		s := l.nodes[flowCol][i]
		chosen := a.col == flowCol && a.row[flowCol] == i
		bg := th.Text
		if chosen {
			bg = th.Text.On(th.Selected)
		}
		row := r.Sub(s.x, s.y, s.w, 1)
		row.FillStyle(bg)
		mark, tint, text, under := f.bar, a.look.Flow, th.Text, th.Text // a block keeps its tint on the bar
		if chosen {
			mark = f.barOn
		}
		if !a.on(n) {
			mark, tint, text, under = f.Off, th.Muted, th.Muted, bg
			if chosen {
				mark = th.Glyphs.Pointer
			}
		}
		if a.faulty(n) {
			tint = th.Error
		}
		row.TextStyled(0, 0, string(mark), tint.On(under))
		row.TextStyled(2, 0, n.Role, text.On(bg))
		x := 3 + ui.RuneLen(n.Role)
		row.TextStyled(x, 0, ui.Truncate(s.text[0], row.W-x), th.Muted.On(bg))
	}
}

// on reports whether a node is on: a flow stage that is off has no options,
// or an enabled key that is false
func (a *app) on(n compose.Node) bool {
	if n.Role == "filters" {
		return len(a.pipeline().Flow.Filters) > 0
	}
	opts, on, _ := a.comp.Options(a.pi, n)
	if slicesHasKey(a.keys(n), "enabled") {
		return on && opts["enabled"] == true
	}
	return on
}

// summary is a node's options in a line: the values set, a table or a switch
// by its name; the filters as +include and -exclude patterns
func (a *app) summary(n compose.Node) string {
	if n.Role == "filters" {
		var out []string
		for _, f := range a.pipeline().Flow.Filters {
			sign := map[config.FilterType]string{"include": "+", "exclude": "-"}[f.Type]
			out = append(out, sign+strings.Join(f.Patterns, "|"))
		}
		return strings.Join(out, " ")
	}
	var out []string
	for _, s := range a.settings(n) {
		out = append(out, cmp.Or(s.value, s.key))
	}
	return strings.Join(out, "  ")
}

// optionRows are a source's or sink's options set, a row each with the
// values aligned, at most listMax; "defaults" when none is set
func (a *app) optionRows(n compose.Node) []string {
	set := a.settings(n)
	if len(set) == 0 {
		return []string{"defaults"}
	}
	set = set[:min(len(set), listMax)]
	keyW := 0
	for _, s := range set {
		keyW = max(keyW, ui.RuneLen(s.key))
	}
	var out []string
	for _, s := range set {
		row := s.key
		if s.value != "" {
			row = ui.PadRight(s.key, keyW) + "  " + s.value
		}
		out = append(out, row)
	}
	return out
}

// setting is an option set: its key, and its value as shown, none for a
// table or a switch
type setting struct{ key, value string }

// settings are a node's options set, in its keys' order
func (a *app) settings(n compose.Node) []setting {
	opts, _, _ := a.comp.Options(a.pi, n)
	var out []setting
	for _, k := range a.keys(n) {
		v, ok := opts[k.Name]
		switch {
		case !ok || k.Name == "enabled" || v == false:
		case k.Kind == "table":
			if t, _ := v.(map[string]any); t["enabled"] != false {
				out = append(out, setting{key: k.Name})
			}
		case v == true:
			out = append(out, setting{key: k.Name})
		default:
			out = append(out, setting{k.Name, show(v)})
		}
	}
	return out
}

// show writes a value as a form does: a list joined by commas
func show(v any) string {
	switch v := v.(type) {
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, show(e))
		}
		return strings.Join(out, ",")
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// faulty reports whether a problem names this node, or a filter when n is
// the filters stage
func (a *app) faulty(n compose.Node) bool {
	for _, p := range compose.Problems(a.problem) {
		if pi, m, _, _, ok := compose.Locate(p); ok && pi == a.pi && m.Role == n.Role && m.ID == n.ID {
			return true
		}
	}
	return false
}

// where names a problem's part as the screen shows it: its pipeline when
// another is shown, the part, and its key
func (a *app) where(pi int, n compose.Node, key string) string {
	var out []string
	if pi != a.pi && pi < len(a.comp.Pipelines) {
		out = append(out, "pipeline "+a.comp.Pipelines[pi].Name)
	}
	switch n.Role {
	case "":
	case "source", "sink":
		out = append(out, n.Role+" "+n.ID)
	case "filters":
		out = append(out, fmt.Sprintf("filter %d", n.Index+1))
	default:
		out = append(out, n.Role)
	}
	if key != "" {
		out = append(out, key)
	}
	return strings.Join(out, " · ")
}
