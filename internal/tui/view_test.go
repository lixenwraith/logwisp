package tui

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/lixenwraith/logwisp/internal/compose"
	"github.com/lixenwraith/logwisp/internal/core"

	"github.com/lixenwraith/terminal"
	ui "github.com/lixenwraith/terminal/tui"
)

// tapped is an entry from a pipeline's source as its flow left it: dropped at
// stage and index, or passed with its payload when stage is ""
func tapped(pipe, source, stage string, index int, msg string) core.Tapped {
	r := core.Tapped{Pipeline: pipe, Source: source, Stage: stage, Index: index,
		Event: core.TransportEvent{Entry: core.LogEntry{Time: time.Unix(1, 0), Source: source, Message: msg}}}
	if stage == "" {
		r.Event.Payload = []byte(msg + "\n")
	}
	return r
}

// watching is a screen on c in look whose view takes the keys, drawn once so
// its rows are built for where the canvas cursor is
func watching(c *compose.Composition, l look) *app {
	a := newApp(c, l, unicodeFont)
	a.viewing = true
	render(a, 80, 24)
	return a
}

// shown is the messages of the rows the view shows
func shown(a *app) []string {
	var out []string
	for _, seq := range a.view.shown {
		out = append(out, a.view.rows[seq-a.view.rows[0].seq].Message)
	}
	return out
}

// cursorRow is the screen row the view's pointer is on
func cursorRow(rows []string) (int, string) {
	for y, r := range rows {
		if strings.HasPrefix(r, string(unicodeFont.Glyphs.Pointer)) {
			return y, r
		}
	}
	return -1, ""
}

// The view follows the newest row; a move up pauses it on its row while rows
// arrive, and G, or moving down onto the newest, follows again
func TestTheViewFollowsUntilMovedUp(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	add := func(from, to int) {
		for i := from; i < to; i++ {
			a.view.take(tapped("p", "null", "", 0, fmt.Sprintf("row %03d", i)))
		}
	}
	at := func() string {
		_, r := cursorRow(text(render(a, 80, 24), 80))
		return r
	}
	if add(0, 50); !strings.Contains(at(), "row 049") {
		t.Fatalf("following: %q", at())
	}
	press(a, "k")
	if add(50, 60); !strings.Contains(at(), "row 048") || !strings.Contains(text(render(a, 80, 24), 80)[1], "paused · 11 newer") {
		t.Fatalf("paused: %q\n%s", at(), text(render(a, 80, 24), 80)[1])
	}
	if press(a, "G"); !strings.Contains(at(), "row 059") {
		t.Fatalf("G: %q", at())
	}
	press(a, "k", "j")
	if add(60, 61); !strings.Contains(at(), "row 060") {
		t.Fatalf("down onto the newest: %q", at())
	}
}

// The rows hold no more than ringBytes, the oldest going first; a paused
// cursor keeps its row, or takes the oldest kept when its own went
func TestTheRowsKeepWithinTheirBytes(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	big := strings.Repeat("x", 1<<20)
	for i := range 20 {
		a.view.take(tapped("p", "null", "", 0, fmt.Sprintf("%02d %s", i, big)))
	}
	render(a, 80, 24)
	press(a, "k", "k")
	focused := a.view.focused().Message[:2]
	for i := 20; i < 25; i++ {
		a.view.take(tapped("p", "null", "", 0, fmt.Sprintf("%02d %s", i, big)))
	}
	if got := a.view.focused().Message[:2]; a.view.bytes > ringBytes || got != focused {
		t.Fatalf("%d bytes held; cursor on %s, was on %s", a.view.bytes, got, focused)
	}
	for i := 25; i < 55; i++ {
		a.view.take(tapped("p", "null", "", 0, fmt.Sprintf("%02d %s", i, big)))
	}
	if got, oldest := a.view.focused().Message[:2], a.view.rows[0].Message[:2]; a.view.bytes > ringBytes || got != oldest || oldest == "00" {
		t.Fatalf("%d bytes held; cursor on %s, the oldest kept %s", a.view.bytes, got, oldest)
	}
}

// A pattern shows only the rows matching it; setting or clearing it keeps
// the focused row on its screen row, the rows around it back on clearing,
// whether the view was paused or following
func TestAFilterChangeKeepsTheFocusedRowInPlace(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	for i := range 300 {
		msg := fmt.Sprintf("row %03d", i)
		if i%3 == 2 {
			msg += " needle"
		}
		a.view.take(tapped("p", "null", "", 0, msg))
	}
	screen := func() []string { return text(render(a, 80, 24), 80) }
	press(a, "g")
	screen()
	press(a, strings.Repeat("j", 150))
	screen()
	press(a, strings.Repeat("k", 10))
	y, r := cursorRow(screen())
	if !strings.Contains(r, "row 140 needle") {
		t.Fatalf("on %q", r)
	}
	press(a, "/", "needle", terminal.KeyEnter)
	rows := screen()
	if y2, r2 := cursorRow(rows); y2 != y || r2 != r || strings.Contains(strings.Join(rows, "\n"), "row 139") {
		t.Fatalf("with the pattern, on row %d %q, was %d\n%s", y2, r2, y, strings.Join(rows, "\n"))
	}
	press(a, "/", terminal.KeyCtrlU, terminal.KeyEnter)
	rows = screen()
	if y2, r2 := cursorRow(rows); y2 != y || r2 != r || !strings.Contains(rows[y2-1], "row 139") || !strings.Contains(rows[y2+1], "row 141") {
		t.Fatalf("cleared, on row %d %q, was %d\n%s", y2, r2, y, strings.Join(rows, "\n"))
	}
	following := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	for i := range 40 {
		msg := fmt.Sprintf("row %03d", i)
		if i == 10 {
			msg += " needle"
		}
		following.view.take(tapped("p", "null", "", 0, msg))
	}
	press(following, "/", "needle", terminal.KeyEnter)
	render(following, 80, 24)
	press(following, "/", terminal.KeyCtrlU, terminal.KeyEnter)
	if render(following, 80, 24); following.view.focused().Message != "row 010 needle" || !following.view.paused {
		t.Fatalf("cleared while following, on %q", following.view.focused().Message)
	}
}

// A row keeps copies of its text, none of the entry's, and its size counts
// every string it keeps, so the ring's bound holds for any line
func TestARowCountsAllItHolds(t *testing.T) {
	long := strings.Repeat("y", 4096)
	rec := tapped("p", "null", "", 0, `{"msg":"`+long+`","sub":"`+long+`","k":"`+long+`","t":"2026-10-10T12:00:00Z"}`)
	rec.Event.Entry.Level = long
	var v view
	size := v.take(rec)
	r := v.rows[0]
	held := rowBytes + len(r.Stamp) + len(r.Level) + len(r.Tag) + len(r.Message) + len(r.Layout) + len(r.fields) + len(r.payload)
	strs := []string{r.Stamp, r.Level, r.Tag, r.Message, r.Layout}
	for _, f := range r.Fields {
		held += int(unsafe.Sizeof(f)) + len(f.Key) + len(f.Value)
		strs = append(strs, f.Key, f.Value)
	}
	if size < held || v.bytes != size {
		t.Fatalf("size %d, ring %d, for %d held", size, v.bytes, held)
	}
	for _, s := range strs {
		for _, from := range []string{rec.Event.Entry.Message, rec.Event.Entry.Level} {
			if p, start := uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(unsafe.Pointer(unsafe.StringData(from))); s != "" && p >= start && p < start+uintptr(len(from)) {
				t.Fatalf("%.20q is the entry's", s)
			}
		}
	}
}

// The canvas cursor picks the point and v the verdicts at it: a source's
// entries, what reaches a stage or a filter, passes it or it drops, the
// heartbeats, what the sinks got and what the flow dropped on the way; lw's
// own log shows from info up at every point, and whole at its own
func TestThePointAndModePickTheRows(t *testing.T) {
	c := pipeline(t, []string{"null", "null"}, []string{"null"})
	for _, typ := range []string{"include", "exclude"} {
		if _, err := c.Add(0, "filters", typ); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.AddPipeline("q"); err != nil {
		t.Fatal(err)
	}
	s1, s2 := c.Pipelines[0].PluginSources[0].ID, c.Pipelines[0].PluginSources[1].ID
	a := watching(c, looks[terminal.ColorModeNone])
	lw := func(level, msg string) core.Tapped {
		r := tapped("", "lw", "", 0, msg)
		r.Event.Entry.Level = level
		return r
	}
	for _, r := range []core.Tapped{
		tapped("p", s1, "", 0, "a"), tapped("p", s2, "", 0, "b"), tapped("p", s1, "rate_limit", 0, "c"),
		tapped("p", s1, "filters", 0, "d"), tapped("p", s2, "filters", 1, "e"), tapped("p", s1, "format", 0, "f"),
		tapped("p", "", "", 0, "g"), tapped("q", s1, "", 0, "h"), lw("INFO", "i"), lw("DEBUG", "j"),
	} {
		a.view.take(r)
	}
	for _, c := range []struct {
		pi   int
		at   compose.Node
		mode int
		want string
		own  bool
	}{
		{0, compose.Node{Role: "sink", ID: "null"}, modeAll, "abgi", false},
		{0, compose.Node{Role: "sink", ID: "null"}, modePassed, "abgi", false},
		{0, compose.Node{Role: "sink", ID: "null"}, modeDropped, "cdefi", false},
		{0, compose.Node{Role: "source", ID: s1}, modeAll, "acdfi", false},
		{0, compose.Node{Role: "source", ID: s1}, modePassed, "ai", false},
		{0, compose.Node{Role: "source", ID: s1}, modeDropped, "cdfi", false},
		{0, compose.Node{Role: "rate_limit"}, modeAll, "abcdefi", false},
		{0, compose.Node{Role: "rate_limit"}, modePassed, "abdefi", false},
		{0, compose.Node{Role: "rate_limit"}, modeDropped, "ci", false},
		{0, compose.Node{Role: "filters"}, modeAll, "abdefi", false},
		{0, compose.Node{Role: "filters"}, modePassed, "abfi", false},
		{0, compose.Node{Role: "filters"}, modeDropped, "dei", false},
		{0, compose.Node{Role: "filters", Index: 1}, modeAll, "abefi", false},
		{0, compose.Node{Role: "filters", Index: 1}, modeDropped, "ei", false},
		{0, compose.Node{Role: "format"}, modeDropped, "fi", false},
		{0, compose.Node{Role: "heartbeat"}, modeAll, "gi", false},
		{0, compose.Node{Role: "heartbeat"}, modeDropped, "i", false},
		{1, compose.Node{}, modeAll, "hi", false},
		{0, compose.Node{Role: "filters"}, modeDropped, "ij", true},
	} {
		a.pi, a.inspect, a.view.mode, a.col, a.view.own = c.pi, false, c.mode, sinksCol, c.own
		a.choose(c.at)
		if c.at.Role == "filters" && c.at.Index > 0 {
			a.inspectAt(func(l line) bool { return l.node == c.at })
		}
		render(a, 80, 24)
		if got := strings.Join(shown(a), ""); got != c.want {
			t.Errorf("at %+v in pipeline %d, %s: %q, want %q", c.at, c.pi, verdicts[c.mode], got, c.want)
		}
	}
}

// The tap takes the entries the flow dropped only while the view's point and
// mode show some
func TestTheTapTakesDropsOnlyWhileShown(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	a.live.tap = core.NewTap(1)
	for _, c := range []struct {
		at   compose.Node
		mode int
		all  bool
	}{
		{compose.Node{Role: "sink", ID: "null"}, modeAll, false},
		{compose.Node{Role: "sink", ID: "null"}, modeDropped, true},
		{compose.Node{Role: "source", ID: "null"}, modePassed, false},
		{compose.Node{Role: "source", ID: "null"}, modeAll, true},
		{compose.Node{Role: "filters"}, modePassed, true},
	} {
		a.view.mode = c.mode
		a.choose(c.at)
		if render(a, 80, 24); a.live.tap.All.Load() != c.all {
			t.Errorf("at %+v, %s: the tap takes drops %v", c.at, verdicts[c.mode], !c.all)
		}
	}
}

// A digit is a level floor: rows under it hide, and those without a level;
// 0 shows them all
func TestTheLevelFloorHidesRowsUnderIt(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR", ""} {
		r := tapped("p", "null", "", 0, "at "+l)
		r.Event.Entry.Level = l
		a.view.take(r)
	}
	for _, c := range []struct{ key, want string }{{"4", "at WARN|at ERROR"}, {"2", "at DEBUG|at INFO|at WARN|at ERROR"}, {"0", "at DEBUG|at INFO|at WARN|at ERROR|at "}} {
		press(a, c.key)
		if render(a, 80, 24); strings.Join(shown(a), "|") != c.want {
			t.Errorf("%s: %q", c.key, shown(a))
		}
	}
}

// A pattern in lower case ignores case, one with an upper-case letter keeps
// it, in substrings and regular expressions alike
func TestPatternsAreSmartCase(t *testing.T) {
	for _, c := range []struct {
		pattern, text string
		match         bool
	}{
		{"disk", "DISK full", true}, {"Disk", "disk full", false}, {"Disk", "Disk full", true},
		{"d.sk", "DISK full", true}, {"D.sk", "disk full", false}, {"é", "CAFÉ", true}, {"x", "DISK", false},
	} {
		if p, err := newPattern(c.pattern); err != nil || p.match(c.text) != c.match {
			t.Errorf("%q in %q: %v, %v", c.pattern, c.text, !c.match, err)
		}
	}
	if _, err := newPattern("("); err == nil {
		t.Error("( compiled")
	}
}

// From 40 rows the view sits under the diagram, whichever takes the keys;
// shorter, it takes the screen while it takes the keys, t going back
func TestTheViewSitsUnderTheDiagramWhenTall(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	a.view.take(tapped("p", "null", "", 0, "hello"))
	layout := func(h int) string {
		screen := strings.Join(text(render(a, 80, h), 80), "\n")
		diagram, view := strings.Index(screen, "● SOURCES"), strings.Index(screen, "hello")
		switch {
		case diagram >= 0 && view > diagram:
			return "split"
		case view >= 0 && diagram < 0:
			return "view"
		case diagram >= 0 && view < 0:
			return "diagram"
		}
		return screen
	}
	if got := layout(40); got != "split" {
		t.Errorf("40 rows: %s", got)
	}
	if got := layout(39); got != "view" {
		t.Errorf("39 rows: %s", got)
	}
	press(a, "t")
	if got := layout(39); got != "diagram" {
		t.Errorf("39 rows, back: %s", got)
	}
	if got := layout(40); got != "split" {
		t.Errorf("40 rows, back: %s", got)
	}
}

// Enter shows the focused row's detail beside the rows from 160 columns,
// under them below that
func TestTheDetailSitsBesideFrom160(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	a.view.take(tapped("p", "null", "", 0, "hello"))
	press(a, terminal.KeyEnter)
	for w, beside := range map[int]bool{160: true, 159: false} {
		rows := text(render(a, w, 30), w)
		y := slices.IndexFunc(rows, func(r string) bool { return strings.Contains(r, "─ detail ─") })
		if got := y == 2 && strings.Contains(rows[2], "hello"); got != beside {
			t.Errorf("%d columns: beside %v, detail on row %d\n%s", w, got, y, strings.Join(rows, "\n"))
		}
	}
}

// The detail shows the entry whole: its verdict, the layout logline found,
// its fields, and the payload as the sinks receive it
func TestTheDetailShowsTheEntryWhole(t *testing.T) {
	c := pipeline(t, []string{"null"}, []string{"null"})
	if _, err := c.Add(0, "filters", "exclude"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(0, compose.Node{Role: "filters"}, "patterns", "slow"); err != nil {
		t.Fatal(err)
	}
	a := watching(c, looks[terminal.ColorModeNone])
	line := `{"time":"2026-10-10T12:00:00Z","level":"WARN","sub":"fsm","fields":{"msg":"transition","state":"idle"}}`
	a.view.take(tapped("p", "null", "", 0, line))
	press(a, terminal.KeyEnter)
	screen := strings.Join(text(render(a, 170, 30), 170), "\n")
	for _, want := range []string{"verdict  passed every stage", "layout   json, message in fields.msg", "state    idle", "as sinks receive it", line[:50]} {
		if !strings.Contains(screen, want) {
			t.Errorf("no %q\n%s", want, screen)
		}
	}
	a.view.take(tapped("p", "null", "filters", 0, "slow tick"))
	if screen := strings.Join(text(render(a, 170, 30), 170), "\n"); !strings.Contains(screen, "dropped by filter 1, exclude slow") || strings.Contains(screen, "as sinks receive it") {
		t.Errorf("a dropped row\n%s", screen)
	}
}

// A row draws one cell per rune: a wide, combining or control rune is the
// font's placeholder and a line break its mark, which the detail writes as
// escapes and a break
func TestRowsDrawOneCellPerRune(t *testing.T) {
	msg := "a\u4f60\u0301\x1b[2Jb\tc\nd"
	for _, f := range []font{unicodeFont, cp437Font, asciiFont} {
		a := newApp(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone], f)
		a.viewing = true
		render(a, 80, 24)
		a.view.take(tapped("p", "null", "", 0, msg))
		odd, br := string(f.fold(f.odd)), string(f.fold(f.newline))
		want := "a" + odd + odd + odd + "[2Jb c" + br + "d"
		if row := text(render(a, 80, 24), 80)[2]; !strings.Contains(row, want) {
			t.Errorf("%c: %q, want %q", f.bar, row, want)
		}
	}
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	a.view.take(tapped("p", "null", "", 0, msg))
	press(a, terminal.KeyEnter)
	if screen := strings.Join(text(render(a, 80, 30), 80), "\n"); !strings.Contains(screen, `message  a\u4F60\u0301\u001B[2Jb\u0009c`+strings.Repeat(" ", 10)) {
		t.Errorf("the detail\n%s", screen)
	}
}

// A narrow view drops the time, then the level's name, the tag and the
// level, and never draws one over the message
func TestANarrowViewDropsColumns(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	r := tapped("p", "null", "", 0, "hello world")
	r.Event.Entry.Level, r.Event.Entry.Source = "WARN", "app.log"
	a.view.take(r)
	stamp := time.Unix(1, 0).Format("15:04:05")
	for _, c := range []struct {
		w    int
		want string
	}{{100, stamp + ".000 WARN  app.log hello world"}, {60, stamp + ".000 W app.log hello world"},
		{45, stamp + " W hello world"}, {30, "▸  W hello world"}, {20, "▸  hello world"}} {
		if row := text(render(a, c.w, 24), c.w)[2]; !strings.Contains(row, c.want) {
			t.Errorf("%d columns: %q, want %q", c.w, row, c.want)
		}
	}
}

// A row's level shows in its level's color; a level lw does not name, in the
// text's
func TestALevelShowsInItsColor(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeTrueColor])
	for _, level := range []string{"WARN", "AUDIT"} {
		r := tapped("p", "null", "", 0, "hello")
		r.Event.Entry.Level = level
		a.view.take(r)
	}
	cells := render(a, 100, 24)
	for y, c := range []struct {
		level string
		want  ui.Style
	}{{"WARN", a.look.Levels["WARN"]}, {"AUDIT", a.th.Text}} {
		row := []rune(text(cells, 100)[2+y])
		x := slices.Index(row, rune(c.level[0]))
		if got := cells[(2+y)*100+x]; x < 0 || got.Fg != c.want.Fg {
			t.Errorf("%s at %d is %+v, want %+v", c.level, x, got, c.want)
		}
	}
}

// The cursor row is one bar: without color every cell takes one style, so a
// console draws no split bar; in color each keeps its role on the bar's
// background
func TestTheViewsCursorRowIsOneBar(t *testing.T) {
	for _, mode := range []terminal.ColorMode{terminal.ColorModeNone, terminal.ColorMode16, terminal.ColorModeTrueColor} {
		a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[mode])
		r := tapped("p", "null", "filters", 0, "hello world")
		r.Event.Entry.Level, r.Event.Entry.Fields = "ERROR", json.RawMessage(`{"k":1}`)
		a.view.take(r)
		a.view.mode = modeDropped
		a.choose(compose.Node{Role: "sink", ID: "null"})
		cells := render(a, 100, 24)
		row, bar := cells[2*100:3*100], a.th.Text.On(a.th.Selected)
		for x, c := range row {
			one := c.Fg == bar.Fg && c.Bg == bar.Bg && c.Attrs == bar.Attr
			if mode == terminal.ColorModeNone && !one || c.Bg != bar.Bg || c.Attrs&terminal.AttrBgColor != bar.Attr&terminal.AttrBgColor {
				t.Fatalf("mode %v: %q at %d is %+v, the bar %+v", mode, c.Rune, x, c, bar)
			}
		}
	}
}

// A tick reads the taps up to drainBytes, the rest waiting for the next
func TestADrainKeepsToItsBudget(t *testing.T) {
	a := mono(pipeline(t, []string{"null"}, []string{"null"}))
	a.live.tap = core.NewTap(100)
	for range 100 {
		a.live.tap.Offer(tapped("p", "null", "", 0, strings.Repeat("x", 64<<10)))
	}
	press(a, terminal.KeyNone)
	size := a.view.rows[0].size
	if n, want := len(a.view.rows), int(math.Ceil(float64(drainBytes)/float64(size))); n != want || len(a.live.tap.Records()) != 100-n {
		t.Fatalf("read %d rows of %d bytes, want %d; %d left", n, size, want, len(a.live.tap.Records()))
	}
}

// While a tap holds records the watch wakes the screen; an empty one does
// not
func TestATapHoldingRecordsWakesTheScreen(t *testing.T) {
	posts := make(chan struct{}, 8)
	r := newRun(&fakeRunner{}, func() { posts <- struct{}{} })
	tap := core.NewTap(1)
	r.fed.Store(tap)
	go r.watch(time.Hour)
	defer r.endAsks()
	select {
	case <-posts:
		t.Fatal("an empty tap woke the screen")
	case <-time.After(3 * drainEvery):
	}
	tap.Offer(tapped("p", "null", "", 0, "x"))
	select {
	case <-posts:
	case <-time.After(time.Second):
		t.Fatal("a tap holding a record did not wake the screen")
	}
}

// A rerun reads the earlier run's tap whole, then a rule marks where the new
// run's rows begin
func TestARerunMarksTheRows(t *testing.T) {
	f := &fakeRunner{}
	a := running(t, pipeline(t, []string{"null"}, []string{"null"}), f)
	a.live.tap = core.NewTap(4)
	a.live.tap.Offer(tapped("p", "null", "", 0, "before"))
	next := core.NewTap(4)
	next.Offer(tapped("p", "null", "", 0, "after"))
	f.start = func(Ask) (*core.Tap, error) { return next, nil }
	a.edit(a.comp.Set(0, compose.Node{Role: "format"}, "type", "txt"))
	press(a, "t")
	await(t, a)
	var got []string
	for _, r := range a.view.rows {
		got = append(got, r.Message+strings.SplitN(r.mark, " ", 2)[0])
	}
	if strings.Join(got, ",") != "before,rerun,after" {
		t.Fatalf("%q", got)
	}
}

// i inspects the filter that dropped the focused row, which the view then
// looks at
func TestIInspectsTheFilterThatDropped(t *testing.T) {
	c := pipeline(t, []string{"null"}, []string{"null"})
	for _, typ := range []string{"include", "exclude"} {
		if _, err := c.Add(0, "filters", typ); err != nil {
			t.Fatal(err)
		}
	}
	a := watching(c, looks[terminal.ColorModeNone])
	a.view.take(tapped("p", "null", "filters", 1, "dropped"))
	press(a, "i")
	if l := a.lines()[a.insp.cursor]; a.viewing || !a.inspect || l.node != (compose.Node{Role: "filters", Index: 1}) || a.point().name != "filter 2" {
		t.Fatalf("viewing %v, inspecting %v on %+v, at %s", a.viewing, a.inspect, l.node, a.point().name)
	}
}

// s picks the point from a list, moving the canvas cursor there, or lw's own
// log while it reaches the screen, until s picks another or a key on the
// diagram moves the cursor
func TestTheChooserPicksThePoint(t *testing.T) {
	a := watching(pipeline(t, []string{"null"}, []string{"null"}), looks[terminal.ColorModeNone])
	press(a, "s", "format", terminal.KeyEnter)
	if n, _ := a.node(); n.Role != "format" || a.point().name != "format" || !a.viewing {
		t.Fatalf("on %+v, at %s, viewing %v", n, a.point().name, a.viewing)
	}
	a.live.state.Log = core.NewTap(1)
	for _, leave := range [][]any{{"s", "format", terminal.KeyEnter}, {"t", "j"}} {
		if press(a, "s", "own log", terminal.KeyEnter); !a.point().own {
			t.Fatalf("at %s", a.point().name)
		}
		if press(a, leave...); a.point().own {
			t.Fatalf("%v left the point on lw's own log", leave)
		}
	}
}
