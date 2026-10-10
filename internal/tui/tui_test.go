package tui

import (
	"slices"
	"strings"
	"testing"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/config"

	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// press sends keys: a string's runes, a terminal.Key, or a pasted []byte
func press(a *app, in ...any) {
	for _, k := range in {
		switch k := k.(type) {
		case string:
			for _, r := range k {
				a.handle(terminal.Event{Type: terminal.EventKey, Key: terminal.KeyRune, Rune: r})
			}
		case terminal.Key:
			a.handle(terminal.Event{Type: terminal.EventKey, Key: k})
		case []byte:
			a.handle(terminal.Event{Type: terminal.EventPaste, Text: string(k)})
		}
	}
}

// render paints the screen as Run does and returns its cells
func render(a *app, w, h int) []terminal.Cell {
	cells := make([]terminal.Cell, w*h)
	a.paint(cells, w, h)
	return cells
}

func text(cells []terminal.Cell, w int) []string {
	var rows []string
	for y := range len(cells) / w {
		var b strings.Builder
		for _, c := range cells[y*w : (y+1)*w] {
			b.WriteRune(max(c.Rune, ' '))
		}
		rows = append(rows, b.String())
	}
	return rows
}

// pipeline builds a composition of one pipeline from typed parts
func pipeline(t *testing.T, sources, sinks []string) *compose.Composition {
	t.Helper()
	c := &compose.Composition{}
	if err := c.AddPipeline("p"); err != nil {
		t.Fatal(err)
	}
	for role, types := range map[string][]string{"source": sources, "sink": sinks} {
		for _, typ := range types {
			if _, err := c.Add(0, role, typ); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

func mono(c *compose.Composition) *app { return newApp(c, looks[terminal.ColorModeNone], unicodeFont) }

// focusKey puts the inspector's cursor on a key's row
func focusKey(t *testing.T, a *app, name string) line {
	t.Helper()
	for i, l := range a.lines() {
		if l.key.Name == name && l.item < 0 {
			a.insp.cursor = i
			return l
		}
	}
	t.Fatalf("no row %s", name)
	return line{}
}

// Each wire glyph's arms meet the cells beside it, whatever the count of
// sources and sinks and the width, and every source and sink is wired to
// the flow box's arrow
func TestWiresJoinWhereTheyMeet(t *testing.T) {
	arms := map[rune]uint8{'│': 5, '─': 10, '└': 3, '┌': 6, '├': 7, '┘': 9, '┴': 11, '┐': 12, '┤': 13, '┬': 14, '┼': 15, '►': 10}
	steps := map[uint8][2]int{1: {0, -1}, 2: {1, 0}, 4: {0, 1}, 8: {-1, 0}}
	opposite := map[uint8]uint8{1: 4, 2: 8, 4: 1, 8: 2}
	for n := range 16 {
		sources, sinks := slices.Repeat([]string{"null"}, n%4), slices.Repeat([]string{"null"}, n/4)
		for _, w := range []int{64, 80, 109, 130} {
			a := mono(pipeline(t, sources, sinks))
			l := a.layout(w)
			cells := make([]terminal.Cell, w*l.h)
			a.drawCanvas(ui.NewRegion(cells, w, 0, 0, w, l.h))
			glyph := func(x, y int) rune {
				if x < 0 || x >= w || y < 0 || y >= l.h {
					return ' '
				}
				return cells[y*w+x].Rune
			}
			reached := map[[2]int]bool{}
			var walk func(x, y int)
			walk = func(x, y int) {
				m, wire := arms[glyph(x, y)]
				if !wire || reached[[2]int{x, y}] {
					return
				}
				reached[[2]int{x, y}] = true
				for arm, d := range steps {
					if m&arm == 0 {
						continue
					}
					next, ok := arms[glyph(x+d[0], y+d[1])]
					if !ok && glyph(x, y) != '─' && glyph(x, y) != '►' {
						t.Errorf("%d sources, %d sinks, %d columns: %q at %d,%d points at %q", len(sources), len(sinks), w, glyph(x, y), x, y, glyph(x+d[0], y+d[1]))
					}
					if ok && next&opposite[arm] == 0 {
						t.Errorf("%d sources, %d sinks, %d columns: %q at %d,%d meets %q", len(sources), len(sinks), w, glyph(x, y), x, y, glyph(x+d[0], y+d[1]))
					}
					walk(x+d[0], y+d[1])
				}
			}
			walk(l.box.x-1, l.entry)
			walk(l.box.x+l.box.w+1, l.exit)
			for i := range sources {
				if s := l.nodes[sourcesCol][i]; !reached[[2]int{s.x + s.w, s.y}] {
					t.Errorf("%d sources, %d sinks, %d columns: source %d not wired", len(sources), len(sinks), w, i)
				}
			}
			for i := range sinks {
				if s := l.nodes[sinksCol][i]; !reached[[2]int{s.x - 1, s.y}] {
					t.Errorf("%d sources, %d sinks, %d columns: sink %d not wired", len(sources), len(sinks), w, i)
				}
			}
		}
	}
}

// The parts stack under 64 columns; from 64 they sit side by side with the
// inspector below, and from 110 the inspector sits beside them
func TestLayoutFollowsTheWidth(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	for w, want := range map[int]string{63: "stacked", 64: "below", 109: "below", 110: "beside"} {
		rows := text(render(a, w, 40), w)
		at := func(s string) (int, int) {
			for y, r := range rows {
				if x := strings.Index(r, s); x >= 0 {
					return ui.RuneLen(r[:x]), y
				}
			}
			return -1, -1
		}
		_, sourcesY := at("● SOURCES")
		_, flowY := at("● FLOW")
		ruleX, ruleY := at("── null · source")
		got := "below"
		switch {
		case flowY > sourcesY:
			got = "stacked"
		case ruleX > 0 && ruleY == 1:
			got = "beside"
		case ruleX != 0 || ruleY <= flowY:
			got = "lost"
		}
		if got != want {
			t.Errorf("%d columns: %s, want %s\n%s", w, got, want, strings.Join(rows, "\n"))
		}
	}
}

// Without color, the chosen part still changes a glyph: a source's or a
// sink's bar, a stage's on or off mark, an empty column's slot
func TestSelectionChangesAGlyph(t *testing.T) {
	for _, f := range []font{unicodeFont, cp437Font, asciiFont} {
		c := pipeline(t, []string{"null"}, nil)
		if err := c.Set(0, compose.Node{Role: "format"}, "type", "txt"); err != nil {
			t.Fatal(err)
		}
		a := newApp(c, looks[terminal.ColorModeNone], f)
		l := a.layout(80)
		at := func(col, row int) rune {
			cells := make([]terminal.Cell, 80*l.h)
			a.drawCanvas(ui.NewRegion(cells, 80, 0, 0, 80, l.h))
			s := l.nodes[col][row]
			return cells[s.y*80+s.x].Rune
		}
		for _, n := range [][2]int{{sourcesCol, 0}, {flowCol, 0}, {flowCol, 2}, {sinksCol, 0}} {
			a.col, a.row = (n[0]+1)%3, [3]int{}
			off := at(n[0], n[1])
			a.col, a.row[n[0]] = n[0], n[1]
			if on := at(n[0], n[1]); on == off {
				t.Errorf("%c: column %d row %d draws %q either way", f.bar, n[0], n[1], on)
			}
		}
	}
}

// The inspector types a value and sets it, typed by the key's kind, and Tab
// or Up moves on; empty or d returns it to its default; arrows step a choice,
// setting nothing past either end, and set a switch; Enter opens a choice's
// options, at its value, and Space flips a switch
func TestInspectorSetsKeys(t *testing.T) {
	a := mono(pipeline(t, []string{"file"}, []string{"null"}))
	press(a, terminal.KeyEnter)
	file := compose.Node{Role: "source", ID: "file"}
	opts := func() map[string]any {
		o, _, _ := a.comp.Options(0, file)
		return o
	}
	focusKey(t, a, "from")
	if press(a, terminal.KeyRight); opts()["from"] != nil || a.changed {
		t.Fatalf("Right past the default's end set %v", opts()["from"])
	}
	focusKey(t, a, "directory")
	at := a.insp.cursor
	if press(a, terminal.KeyEnter, "/srv/a b", terminal.KeyTab); a.insp.cursor != at+1 {
		t.Fatalf("Tab left the cursor on row %d", a.insp.cursor)
	}
	focusKey(t, a, "check_interval_ms")
	press(a, terminal.KeyEnter, "1x5", terminal.KeyEnter)
	focusKey(t, a, "from")
	press(a, terminal.KeyLeft)
	focusKey(t, a, "raw")
	if press(a, " ", terminal.KeyLeft, terminal.KeyLeft); opts()["raw"] != false {
		t.Fatalf("Left left raw %v", opts()["raw"])
	}
	press(a, terminal.KeyRight, terminal.KeyRight)
	focusKey(t, a, "pattern")
	at = a.insp.cursor
	if press(a, terminal.KeyEnter, "x", terminal.KeyUp); a.insp.cursor != at-1 || opts()["pattern"] != "x" {
		t.Fatalf("Up left the cursor on row %d, pattern %v", a.insp.cursor, opts()["pattern"])
	}
	focusKey(t, a, "from")
	if press(a, terminal.KeyEnter); a.dialog.(*chooser).list.Cursor != 0 {
		t.Fatalf("the options open off the value: %+v", a.dialog)
	}
	if press(a, terminal.KeyDown, terminal.KeyEscape); opts()["from"] != "start" {
		t.Fatalf("Esc set %v", opts()["from"])
	}
	press(a, terminal.KeyEnter, terminal.KeyDown, terminal.KeyEnter)
	if o := opts(); o["directory"] != "/srv/a b" || o["check_interval_ms"] != int64(15) || o["from"] != "end" || o["raw"] != true {
		t.Fatalf("%v", o)
	}
	focusKey(t, a, "directory")
	press(a, terminal.KeyEnter, terminal.KeyCtrlU, terminal.KeyEnter)
	focusKey(t, a, "raw")
	press(a, "d")
	if o := opts(); o["directory"] != nil || o["raw"] != nil {
		t.Fatalf("%v", o)
	}
}

// A list's elements are its rows: one is added, edited or dropped whole, a
// comma in it included
func TestListElementsAreRows(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	press(a, terminal.KeyRight, "a", "exc", terminal.KeyEnter)
	if len(a.pipeline().Flow.Filters) != 1 {
		t.Fatalf("filters %+v", a.pipeline().Flow.Filters)
	}
	focusKey(t, a, "patterns")
	press(a, terminal.KeyEnter, terminal.KeyDown)
	press(a, terminal.KeyEnter, "a{1,3}", terminal.KeyEnter, terminal.KeyEnter, "c", terminal.KeyEnter)
	press(a, terminal.KeyUp, terminal.KeyUp, terminal.KeyEnter, terminal.KeyCtrlU, "x", terminal.KeyEnter)
	if got := a.pipeline().Flow.Filters[0].Patterns; !slices.Equal(got, []string{"x", "c"}) {
		t.Fatalf("%q", got)
	}
	press(a, terminal.KeyDown, "d")
	if got := a.pipeline().Flow.Filters[0].Patterns; !slices.Equal(got, []string{"x"}) {
		t.Fatalf("%q", got)
	}
}

// Space turns a flow stage on with its defaults and off again; a stage with
// an enabled key switches that
func TestSpaceSwitchesAStage(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	a.col = flowCol
	rate, beat := compose.Node{Role: "rate_limit"}, compose.Node{Role: "heartbeat"}
	var got []bool
	for _, n := range []compose.Node{rate, rate, beat, beat} {
		a.choose(n)
		press(a, " ")
		got = append(got, a.on(n))
	}
	if !slices.Equal(got, []bool{true, false, true, false}) {
		t.Fatalf("%v", got)
	}
	if _, on, _ := a.comp.Options(0, beat); !on {
		t.Fatal("heartbeat switched off by dropping its options")
	}
}

// J and K move a filter, its fold and the cursor with it, and stop at
// either end as j and k do
func TestFiltersMoveWithTheirFold(t *testing.T) {
	c := pipeline(t, []string{"null"}, []string{"null"})
	for _, typ := range []string{"include", "exclude"} {
		if _, err := c.Add(0, "filters", typ); err != nil {
			t.Fatal(err)
		}
	}
	a := mono(c)
	a.choose(compose.Node{Role: "filters", Index: 0})
	press(a, terminal.KeyEnter, "J", "J")
	types := []config.FilterType{a.pipeline().Flow.Filters[0].Type, a.pipeline().Flow.Filters[1].Type}
	l := a.lines()[a.insp.cursor]
	if !slices.Equal(types, []config.FilterType{"exclude", "include"}) || l.node.Index != 1 || !a.insp.open[a.foldKey(compose.Node{Role: "filters"}, "1")] || a.status != "" {
		t.Fatalf("types %v, cursor on %+v, open %v, status %q", types, l, a.insp.open, a.status)
	}
}

// o leaves with the form its letter picks, printed as the engine writes it,
// or with the pipelines to run, as r does; a composition that does not
// validate stays
func TestOutputLeavesWithTheForm(t *testing.T) {
	c := pipeline(t, []string{"null"}, []string{"null"})
	line, err := c.CommandLine()
	if err != nil {
		t.Fatal(err)
	}
	a := mono(c)
	press(a, "o", "c")
	if !a.done || a.result.Exit != Print || a.result.Output != line {
		t.Fatalf("%+v", a.result)
	}
	a = mono(pipeline(t, []string{"null"}, []string{"null"}))
	press(a, "o", terminal.KeyEnter)
	if !a.done || a.result.Exit != Start || len(a.result.Pipelines) != 1 {
		t.Fatalf("%+v", a.result)
	}
	a = mono(pipeline(t, []string{"null"}, []string{"null"}))
	press(a, "r")
	if !a.done || a.result.Exit != Start || len(a.result.Pipelines) != 1 {
		t.Fatalf("r: %+v", a.result)
	}
	a = mono(pipeline(t, []string{"file"}, []string{"null"}))
	press(a, "o", terminal.KeyEnter, "r")
	if a.done || a.status == "" {
		t.Fatalf("ran an invalid composition: %+v", a.result)
	}
}

// With nothing to start from the preset menu opens: Esc starts empty, a
// preset asks its keys and is work q asks about; p later replaces the
// pipeline, under its name, once confirmed
func TestPresetsStartThePipeline(t *testing.T) {
	a := mono(&compose.Composition{})
	press(a, terminal.KeyEscape)
	if a.dialog != nil || len(a.comp.Pipelines) != 1 || len(a.pipeline().PluginSources) != 0 {
		t.Fatalf("Esc: %+v", a.comp.Pipelines)
	}
	if press(a, "q"); !a.done {
		t.Fatal("q asked about an empty start")
	}
	a = mono(&compose.Composition{})
	press(a, "tail", terminal.KeyEnter, "/var/log/", terminal.KeyEnter)
	if a.dialog != nil || a.pipeline().Name != "tail" || a.pipeline().PluginSources[0].Type != "file" {
		t.Fatalf("tail: %+v", a.comp.Pipelines)
	}
	if press(a, "q"); a.done {
		t.Fatal("q dropped the preset without asking")
	}
	press(a, "n")
	press(a, "p", "pipe", terminal.KeyEnter, terminal.KeyEnter)
	if _, asks := a.dialog.(*confirm); !asks {
		t.Fatalf("replaced without asking: %T", a.dialog)
	}
	press(a, "y")
	if a.pipeline().Name != "tail" || a.pipeline().PluginSources[0].Type != "console" {
		t.Fatalf("pipe: %+v", a.comp.Pipelines)
	}
}

// A pasted command line replaces the pipelines, from the preset menu too,
// asking first once they were edited and while some remain; one that names
// none is refused
func TestPasteReplacesThePipelines(t *testing.T) {
	a := mono(&compose.Composition{})
	if press(a, []byte("lw\n")); a.status == "" {
		t.Fatalf("took a paste without pipelines: %+v", a.comp.Pipelines)
	}
	if _, menu := a.dialog.(*chooser); !menu {
		t.Fatalf("a refused paste closed the preset menu: %T", a.dialog)
	}
	press(a, []byte("lw --pipeline x --source null --sink null\r\n"))
	if a.dialog != nil || len(a.comp.Pipelines) != 1 || a.pipeline().Name != "x" {
		t.Fatalf("%T %+v", a.dialog, a.comp.Pipelines)
	}
	press(a, terminal.KeyRight, terminal.KeyDown, terminal.KeyDown, " ", []byte("lw --pipeline y --source null --sink null"), "n")
	if a.pipeline().Name != "x" {
		t.Fatalf("replaced edited pipelines without asking: %+v", a.comp.Pipelines)
	}
	a = mono(pipeline(t, []string{"null"}, []string{"null"}))
	press(a, "k", "d", "y", []byte("lw --pipeline z --source null --sink null"))
	if a.dialog != nil || len(a.comp.Pipelines) != 1 || a.pipeline().Name != "z" {
		t.Fatalf("a paste after the last pipeline was deleted: %T %+v", a.dialog, a.comp.Pipelines)
	}
}

// The first problem marks the part it names, and ! moves there, to the key
func TestProblemNamesItsPart(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null", "tcp"}))
	sink := compose.Node{Role: "sink", ID: "tcp"}
	if !a.faulty(sink) || a.faulty(compose.Node{Role: "source", ID: "null"}) || a.faulty(compose.Node{Role: "sink", ID: "null"}) {
		t.Fatalf("problem %v", a.problem)
	}
	press(a, "!")
	n, _ := a.node()
	if l := a.lines()[a.insp.cursor]; n != sink || !a.inspect || l.key.Name != "port" {
		t.Fatalf("on %+v, row %+v", n, l)
	}
}

// ! and c on the pipeline bar open the inspector, which then takes the keys:
// Enter edits the key it shows, not the pipeline's name
func TestTheInspectorTakesTheKeysFromTheBar(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"tcp"}))
	press(a, "k", "!", terminal.KeyEscape, terminal.KeyEnter)
	if a.bar || a.insp.field == nil {
		t.Fatalf("Enter after ! on the bar: bar %v, %T", a.bar, a.dialog)
	}
	a = mono(pipeline(t, []string{"null"}, []string{"null"}))
	press(a, "k", "c", terminal.KeyEnter, terminal.KeyEnter)
	if a.bar || !a.inspect || a.dialog != nil {
		t.Fatalf("Enter after c on the bar: bar %v, %T", a.bar, a.dialog)
	}
}

// 16 colors and none keep the terminal's own background; more paint the site's
func TestOnlyFullColorPaintsTheBackground(t *testing.T) {
	for mode, l := range looks {
		own := l.Text.Attr&terminal.AttrBgDefault != 0
		if own != (mode == terminal.ColorMode16 || mode == terminal.ColorModeNone) || !own && l.Text.Bg != siteBg {
			t.Errorf("mode %v: %+v", mode, l.Text)
		}
	}
}

// ASCII outside a UTF-8 locale, CP437 on a text console, else Unicode
func TestFontFollowsTheLocale(t *testing.T) {
	for _, c := range []struct {
		lang string
		mode terminal.ColorMode
		want rune
	}{{"C", terminal.ColorMode256, '|'}, {"en_US.UTF-8", terminal.ColorMode16, cp437Font.dot}, {"", terminal.ColorMode256, '▌'}} {
		t.Setenv("LC_ALL", "")
		t.Setenv("LC_CTYPE", "")
		t.Setenv("LANG", c.lang)
		if f := fontFor(c.mode); f.bar != c.want && f.dot != c.want {
			t.Errorf("LANG=%q, mode %v: %c", c.lang, c.mode, f.bar)
		}
	}
}

// The chosen row stays on a part of its column: after the last one is
// deleted, and down an empty column
func TestTheChosenRowStaysInItsColumn(t *testing.T) {
	a := mono(pipeline(t, nil, []string{"null", "null"}))
	a.col, a.row[sinksCol] = sinksCol, 1
	press(a, "d")
	if screen := strings.Join(text(render(a, 80, 24), 80), "\n"); !strings.Contains(screen, string(a.font.barOn)+" null") {
		t.Fatalf("after d, the sink left is not chosen:\n%s", screen)
	}
	a.col = sourcesCol
	press(a, "j", "j")
	if screen := strings.Join(text(render(a, 80, 24), 80), "\n"); !strings.Contains(screen, string(a.th.Glyphs.Pointer)+" a adds a source") {
		t.Fatalf("down an empty column, its slot is not chosen:\n%s", screen)
	}
}

// A font draws only what its terminal shows: ASCII alone outside UTF-8, no
// ellipsis on a text console, though the library truncates with one
func TestAFontDrawsOnlyWhatItsTerminalShows(t *testing.T) {
	for _, c := range []struct {
		f              font
		ellipsis, past bool
	}{{unicodeFont, true, true}, {cp437Font, false, true}, {asciiFont, false, false}} {
		comp := pipeline(t, []string{"null"}, []string{"null"})
		comp.Pipelines[0].Name = strings.Repeat("é", 100)
		var drawn []rune
		for _, cell := range render(newApp(comp, looks[terminal.ColorModeNone], c.f), 80, 24) {
			drawn = append(drawn, cell.Rune)
		}
		ellipsis, past := slices.Contains(drawn, '…'), slices.ContainsFunc(drawn, func(r rune) bool { return r > 0x7f })
		if ellipsis != c.ellipsis || past != c.past {
			t.Errorf("%c: ellipsis %v, past ASCII %v", c.f.bar, ellipsis, past)
		}
	}
}

// A preset form scrolls to its focused field on a short screen
func TestPresetFormShowsTheFocusedField(t *testing.T) {
	presets := config.Presets()
	p := slices.MaxFunc(presets, func(x, y config.Preset) int { return len(x.Params) - len(y.Params) })
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	f := &form{title: p.Name, params: p.Params}
	f.fill(nil)
	a.dialog = f
	press(a, terminal.KeyBacktab)
	last := p.Params[len(p.Params)-1].Name
	if screen := strings.Join(text(render(a, 80, 12), 80), "\n"); !strings.Contains(screen, last) {
		t.Fatalf("%s: focused %s not shown:\n%s", p.Name, last, screen)
	}
}

// presetForm is a preset's form, open on a
func presetForm(a *app, name string) *form {
	presets := config.Presets()
	p := presets[slices.IndexFunc(presets, func(p config.Preset) bool { return p.Name == name })]
	f := &form{title: "preset " + p.Name, summary: p.Summary, params: p.Params}
	f.fill(nil)
	a.dialog = f
	return f
}

// A preset form is usable at 25 columns: labels stack above their values,
// which take the row, so typed text shows whole
func TestPresetFormFitsANarrowScreen(t *testing.T) {
	a := mono(pipeline(t, nil, nil))
	presetForm(a, "serve")
	press(a, terminal.KeyTab, terminal.KeyTab, terminal.KeyTab, "127.0.0.1:9000")
	if screen := strings.Join(text(render(a, 25, 20), 25), "\n"); !strings.Contains(screen, "listen") || !strings.Contains(screen, "127.0.0.1:9000") {
		t.Fatalf("listen and its value not whole at 25 columns:\n%s", screen)
	}
}

// A dialog is sized to what it holds: its first and last rows inside the
// box have text, a form without a summary included
func TestDialogsHaveNoBlankEdgeRows(t *testing.T) {
	var a *app
	for name, open := range map[string]func(){
		"add":     func() { press(a, "a") },
		"presets": func() { press(a, "p") },
		"output":  func() { press(a, "o") },
		"confirm": func() { press(a, "q") },
		"help":    func() { press(a, "?") },
		"problem": func() { press(a, "!") },
		"rename":  func() { press(a, terminal.KeyUp, terminal.KeyEnter) },
		"form":    func() { presetForm(a, "serve") },
	} {
		a = mono(pipeline(t, nil, nil))
		a.changed, a.dialog = true, nil
		open()
		rows := text(render(a, 80, 40), 80)
		bottom := slices.IndexFunc(rows, func(r string) bool { return strings.Contains(r, "└") })
		top := slices.IndexFunc(rows, func(r string) bool { return strings.Contains(r, "┌") })
		if a.dialog == nil || top < 0 || bottom < top+2 {
			t.Errorf("%s: no dialog:\n%s", name, strings.Join(rows, "\n"))
			continue
		}
		edge := []rune(rows[bottom])
		left, right := slices.Index(edge, '└'), slices.Index(edge, '┘')
		for _, y := range []int{top + 1, bottom - 1} {
			if inside := strings.Trim(string([]rune(rows[y])[left:right]), " │"); inside == "" {
				t.Errorf("%s: row %d blank:\n%s", name, y, strings.Join(rows[top:bottom+1], "\n"))
			}
		}
	}
}

// A question is answered by y or n, or by Enter on the answer the arrows
// chose; no is chosen first
func TestConfirmAnswersOnEnter(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	a.changed = true
	if press(a, "q", terminal.KeyEnter); a.done || a.dialog != nil {
		t.Fatalf("Enter on no: done %v, dialog %T", a.done, a.dialog)
	}
	if press(a, "q", terminal.KeyLeft, terminal.KeyEnter); !a.done {
		t.Fatal("Enter on yes did not quit")
	}
}

// The canvas scrolls to keep the chosen part in view, its bar solid
func TestCanvasKeepsTheChosenInView(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, slices.Repeat([]string{"null"}, 8)))
	a.col, a.row[sinksCol] = sinksCol, 7
	if screen := strings.Join(text(render(a, 80, 24), 80), "\n"); !strings.ContainsRune(screen, a.font.barOn) {
		t.Fatalf("the eighth sink is out of view:\n%s", screen)
	}
}

// A notice taller than the screen scrolls with j and k and says where it is
func TestNoticeScrolls(t *testing.T) {
	a := mono(pipeline(t, nil, nil))
	press(a, "?")
	screen := func() string { return strings.Join(text(render(a, 25, 20), 25), "\n") }
	if s := screen(); strings.Contains(s, "quit") || !strings.Contains(s, "j k: 1-") {
		t.Fatalf("help at 25 columns:\n%s", s)
	}
	if press(a, strings.Repeat("j", 60)); a.dialog == nil || !strings.Contains(screen(), "quit") {
		t.Fatalf("scrolled to the end:\n%s", screen())
	}
}

// A dialog's text wraps to a narrow screen
func TestDialogsWrapToTheScreen(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	a.changed = true
	for _, open := range []any{"q", "?"} {
		a.dialog = nil
		press(a, open)
		if screen := strings.Join(text(render(a, 40, 30), 40), " "); !strings.Contains(screen, "pipelines?") && open == "q" ||
			!strings.Contains(screen, "environment") && open == "?" {
			t.Errorf("%s at 40 columns:\n%s", open, strings.Join(text(render(a, 40, 30), 40), "\n"))
		}
	}
}

// The inspector opens on a part's first required key, after a adds it or
// Enter chooses it
func TestInspectorOpensOnTheFirstRequiredKey(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"tcp_chain"}))
	a.col = sinksCol
	press(a, terminal.KeyEnter)
	at := func() string { return a.lines()[a.insp.cursor].key.Name }
	if got := at(); got != "host" {
		t.Fatalf("Enter on tcp_chain: %s", got)
	}
	press(a, terminal.KeyEscape, "a", "http", terminal.KeyEnter)
	if got := at(); got != "port" {
		t.Fatalf("a adding http: %s", got)
	}
}

// The status shows the first problem whole, by its part and key, not by its
// path, on as many rows as it takes
func TestTheProblemShowsWhole(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"http"}))
	sink := compose.Node{Role: "sink", ID: "http"}
	for key, value := range map[string]string{"port": "8080", "viewer_page": "true"} {
		if err := a.comp.Set(0, sink, key, value); err != nil {
			t.Fatal(err)
		}
	}
	a.check()
	for _, w := range []int{60, 87, 146} {
		screen := strings.Join(text(render(a, w, 30), w), "\n")
		if !strings.Contains(screen, "sink http · viewer_page: only") || !strings.Contains(screen, "at /") || strings.Contains(screen, "pipelines[0]") {
			t.Errorf("%d columns:\n%s", w, screen)
		}
	}
}

// Enter on a row that adds acts as a does: an empty column's slot, the
// filters stage with none, the inspector's last filter row
func TestEnterOnAnAddRowAdds(t *testing.T) {
	a := mono(pipeline(t, nil, []string{"null"}))
	if press(a, terminal.KeyEnter); a.dialog == nil {
		t.Fatal("Enter on the empty sources column")
	}
	press(a, "null", terminal.KeyEnter, terminal.KeyEscape, terminal.KeyRight, terminal.KeyDown, terminal.KeyEnter, "exc", terminal.KeyEnter)
	if f := a.pipeline().Flow.Filters; len(f) != 1 || f[0].Type != "exclude" {
		t.Fatalf("Enter on filters: %+v", f)
	}
	lines := a.lines()
	a.insp.cursor = len(lines) - 1
	press(a, terminal.KeyEnter, terminal.KeyEnter)
	if f := a.pipeline().Flow.Filters; len(f) != 2 {
		t.Fatalf("Enter on the add row: %+v", f)
	}
}

// c changes a source's or sink's type in its place and opens it; on a filter
// or the format it goes to the type row
func TestChangeTypeKeepsThePlace(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null", "file"}))
	a.col = sinksCol
	press(a, "c", "tcp", terminal.KeyEnter)
	sinks := a.pipeline().PluginSinks
	if sinks[0].Type != "tcp" || sinks[0].ID != "tcp" || sinks[1].Type != "file" || !a.inspect || a.lines()[a.insp.cursor].key.Name != "port" {
		t.Fatalf("%+v, cursor on %+v", sinks, a.lines()[a.insp.cursor])
	}
	press(a, terminal.KeyEscape)
	a.choose(compose.Node{Role: "format"})
	if press(a, "c"); !a.inspect || a.lines()[a.insp.cursor].key.Name != "type" {
		t.Fatalf("c on format: %+v", a.lines()[a.insp.cursor])
	}
}

// The pipeline bar, above the parts, switches pipelines, adds one under a free
// name, renames one under a name no other has, and deletes one, asking first
// when it has parts
func TestThePipelineBarAddsRenamesDeletes(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	press(a, "k", "a", "empty", terminal.KeyEnter, "k", "a", "empty", terminal.KeyEnter)
	names := func() (out []string) {
		for _, p := range a.comp.Pipelines {
			out = append(out, p.Name)
		}
		return out
	}
	if got := names(); !slices.Equal(got, []string{"p", "default", "default_2"}) || a.pi != 2 {
		t.Fatalf("added %q, showing %d", got, a.pi)
	}
	press(a, "k", terminal.KeyEnter, terminal.KeyCtrlU, "p", terminal.KeyEnter)
	if _, open := a.dialog.(*form); !open {
		t.Fatalf("renamed to a name another has: %q", names())
	}
	press(a, terminal.KeyCtrlU, "x", terminal.KeyEnter, "h", "h", "d")
	if got := names(); !slices.Equal(got, []string{"p", "default", "x"}) || a.dialog == nil {
		t.Fatalf("deleted without asking: %q", got)
	}
	press(a, "y", "l", "d")
	if got := names(); !slices.Equal(got, []string{"default"}) || a.dialog != nil {
		t.Fatalf("%q %T", got, a.dialog)
	}
}
