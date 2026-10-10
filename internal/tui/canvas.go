package tui

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"

	ui "github.com/lixenwraith/terminal/tui"
)

const (
	pitch   = 3  // rows a source or sink takes, its gap included
	gutter  = 4  // columns of wire on either side of the flow box
	wideMin = 64 // the narrowest canvas with the parts side by side
)

// spot is where a node draws: its first row and the columns it may use
type spot struct{ x, y, w int }

// layout places a pipeline's parts: side by side with wires from 64 columns,
// stacked below that
type layout struct {
	wide        bool
	h           int
	title       [3]spot
	nodes       [3][]spot // a column's nodes, or its one empty slot
	box         spot      // the flow box's top left and width
	boxH        int
	entry, exit int // the rows wires enter and leave the flow box
}

func (a *app) layout(w int) layout {
	var l layout
	counts := [3]int{}
	for col := range columns {
		counts[col] = max(1, len(a.nodes(col)))
	}
	stages := counts[flowCol]
	l.boxH = stages + 2
	if w >= wideMin {
		l.wide = true
		boxW := max(18, min(30, (w-2*gutter)/3))
		sideW := (w - boxW - 2*gutter) / 2
		xs := [3]int{0, sideW + gutter, sideW + 2*gutter + boxW}
		ws := [3]int{sideW, boxW, w - xs[sinksCol]}
		for col := range columns {
			l.title[col] = spot{xs[col], 0, ws[col]}
		}
		l.box = spot{xs[flowCol], 1, boxW}
		for _, col := range []int{sourcesCol, sinksCol} {
			for i := range counts[col] {
				l.nodes[col] = append(l.nodes[col], spot{xs[col], 1 + i*pitch, ws[col]})
			}
		}
		l.entry = l.box.y + 1 + (stages-1)/2
		l.exit = l.entry
		l.h = 1 + max(counts[sourcesCol]*pitch-1, l.boxH, counts[sinksCol]*pitch-1)
	} else {
		y := 0
		for col := range columns {
			l.title[col] = spot{0, y, w}
			y++
			if col == flowCol {
				l.box = spot{0, y, w}
				y += l.boxH
			} else {
				for range counts[col] {
					l.nodes[col] = append(l.nodes[col], spot{0, y, w})
					y += pitch
				}
				y--
			}
			if col != sinksCol {
				y++ // the arrow down to the next part
			}
		}
		l.h = y
	}
	for i := range stages {
		l.nodes[flowCol] = append(l.nodes[flowCol], spot{l.box.x + 2, l.box.y + 1 + i, l.box.w - 4})
	}
	return l
}

// drawCanvas draws the pipeline, scrolled to keep the chosen node in view
func (a *app) drawCanvas(r ui.Region) {
	l := a.layout(r.W)
	chosen := l.nodes[a.col][min(a.row[a.col], len(l.nodes[a.col])-1)]
	a.scroll.SetDimensions(l.h, r.H)
	a.scroll.EnsureRange(chosen.y, 2-a.col%2)
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
			a.drawNode(r, s, nodes[i], tints[col], chosen)
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
		r.TextStyled(l.box.x+l.box.w+1, l.exit, string(f.arrow), th.Border)
	}
}

// join wires a column's nodes to a trunk beside the flow box, and the trunk
// to the box's side
func join(g ui.Wires, l layout, col int) {
	ys := []int{l.entry}
	if col == sinksCol {
		ys[0] = l.exit
	}
	for _, s := range l.nodes[col] {
		ys = append(ys, s.y)
	}
	if col == sourcesCol {
		trunk := l.box.x - gutter + 1
		for _, s := range l.nodes[col] {
			g.H(s.y, trunk-1, trunk)
		}
		g.V(trunk, slices.Min(ys), slices.Max(ys))
		g.H(l.entry, trunk, l.box.x-1)
		return
	}
	right := l.box.x + l.box.w
	trunk := right + 2
	g.H(l.exit, right, trunk)
	g.V(trunk, slices.Min(ys), slices.Max(ys))
	for _, s := range l.nodes[col] {
		g.H(s.y, trunk, s.x-1)
	}
}

// drawNode draws a source or sink: a tinted bar, its type and whether it
// listens or dials, then a summary of its options. The chosen node's bar is
// solid; a node the first problem names has its bar in the error style.
func (a *app) drawNode(r ui.Region, s spot, n compose.Node, tint ui.Style, chosen bool) {
	th := a.th
	bg, bar := th.Text, a.font.bar
	if chosen {
		bg, bar = th.Text.On(th.Selected), a.font.barOn
	}
	if a.faulty(n) {
		tint = th.Error
	}
	p, _ := a.plugin(n)
	way := map[config.Side]string{config.Listener: "listens", config.ChainListener: "listens", config.Dialer: "dials"}[p.Side]
	for dy, text := range []string{p.Type, a.summary(n)} {
		row := r.Sub(s.x, s.y+dy, s.w, 1)
		row.FillStyle(bg)
		row.TextStyled(0, 0, string(bar), tint.On(bg))
		style := th.Muted.On(bg)
		if dy == 0 {
			style = th.Text.On(bg)
			row.TextStyled(row.W-ui.RuneLen(way), 0, way, th.Muted.On(bg))
		}
		row.TextStyled(2, 0, ui.Truncate(text, row.W-ui.RuneLen(way)-3), style)
	}
}

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
		mark, tint, text := f.bar, a.look.Flow, th.Text
		if chosen {
			mark = f.barOn
		}
		summary := a.summary(n)
		if !a.on(n) {
			mark, tint, text, summary = f.Off, th.Muted, th.Muted, "off"
			if chosen {
				mark = th.Glyphs.Pointer
			}
		}
		if a.faulty(n) {
			tint = th.Error
		}
		row.TextStyled(0, 0, string(mark), tint.On(bg))
		row.TextStyled(2, 0, n.Role, text.On(bg))
		x := 3 + ui.RuneLen(n.Role)
		row.TextStyled(x, 0, ui.Truncate(summary, row.W-x), th.Muted.On(bg))
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

// summary is a node's options in a line: the values set, a table by its
// name, a switch by its key; the filters as +include and -exclude patterns
func (a *app) summary(n compose.Node) string {
	if n.Role == "filters" {
		var out []string
		for _, f := range a.pipeline().Flow.Filters {
			sign := map[config.FilterType]string{"include": "+", "exclude": "-"}[f.Type]
			out = append(out, sign+strings.Join(f.Patterns, "|"))
		}
		return strings.Join(out, " ")
	}
	opts, _, _ := a.comp.Options(a.pi, n)
	var out []string
	for _, k := range a.keys(n) {
		v, ok := opts[k.Name]
		switch {
		case !ok || k.Name == "enabled" || v == false:
		case k.Kind == "table":
			if t, _ := v.(map[string]any); t["enabled"] != false {
				out = append(out, k.Name)
			}
		case v == true:
			out = append(out, k.Name)
		default:
			out = append(out, show(v))
		}
	}
	return strings.Join(out, "  ")
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

// problemPath reads the part a validation error names: its pipeline, node and
// key, as config's key paths write them
var problemPath = regexp.MustCompile(`^pipelines?\[(\d+)\](?:\.(plugin_sources|plugin_sinks)\[([^\]]*)\](?:\.config\.?([\w.]*))?|\.flow\.(\w+)(?:\[(\d+)\])?\.?([\w.]*))?`)

// locate reads a problem's part, and its text past the path
func locate(err error) (pi int, n compose.Node, key, text string, ok bool) {
	at := problemPath.FindStringSubmatchIndex(err.Error())
	if at == nil {
		return 0, n, "", err.Error(), false
	}
	m := problemPath.FindStringSubmatch(err.Error())
	text = strings.TrimPrefix(err.Error()[at[1]:], ": ")
	pi, _ = strconv.Atoi(m[1])
	switch {
	case m[2] != "":
		n = compose.Node{Role: map[string]string{"plugin_sources": "source", "plugin_sinks": "sink"}[m[2]], ID: m[3]}
		key = m[4]
	case m[5] != "":
		n = compose.Node{Role: m[5]}
		if m[6] != "" {
			n.Index, _ = strconv.Atoi(m[6])
		}
		key = m[7]
	}
	return pi, n, key, text, true
}

// faulty reports whether the first problem names this node, or a filter
// when n is the filters stage
func (a *app) faulty(n compose.Node) bool {
	if a.problem == nil {
		return false
	}
	pi, m, _, _, ok := locate(a.problem)
	return ok && pi == a.pi && m.Role == n.Role && m.ID == n.ID
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
